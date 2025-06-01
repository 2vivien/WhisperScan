#!/usr/bin/env python3
import socket
import random
import ipaddress
import sys
import time
from struct import pack
from threading import Thread, Lock
import logging
from datetime import datetime

# --- CONFIGURATION LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('whisperscan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('WhisperScan')
INTERFACE = "wlp2s0"  # Interface réseau 

# --- CONFIGURATION SCAN (MODIFICATIONS IMPORTANTES) ---
TARGET_IP = "192.168.0.108"
SOURCE_IP_RANGE = "192.168.1.50"  # Une seule source IP (pour port sweep)
BASE_SOURCE_PORT = 49152
TARGET_PORTS = list(range(1, 201)) + [80, 443, 3389, 8080]  # Plus de ports pour port sweep et syn
SCAN_TYPE = "SYN"  # SYN est le plus détectable

# Paramètres de performance (AGRESSIFS pour détection)
TOTAL_PACKETS = 10000  # Beaucoup plus de paquets
THREAD_COUNT = 50      # Plus de threads = plus rapide
PACKETS_PER_THREAD = TOTAL_PACKETS // THREAD_COUNT

# --- FONCTIONS UTILES ---

def ip_range_to_list(ip_range_str):
    """Convertit une plage d'IP en liste avec logging détaillé"""
    logger.info(f"Conversion de la plage IP: {ip_range_str}")
    try:
        if "-" in ip_range_str:
            start_ip_str, end_ip_str = ip_range_str.split("-")
            logger.debug(f"Plage détectée: {start_ip_str} à {end_ip_str}")
            
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())

            if start_ip.version != end_ip.version:
                raise ValueError("Versions IP incompatibles")

            if start_ip > end_ip:
                raise ValueError("L'IP de début doit être <= IP de fin")

            ip_list = [str(ipaddress.ip_address(ip)) 
                      for ip in range(int(start_ip), int(end_ip) + 1)]
            logger.info(f"Génération de {len(ip_list)} IPs dans la plage")
            return ip_list
        else:
            ip = ipaddress.ip_address(ip_range_str.strip())
            logger.info("Adresse IP unique détectée")
            return [str(ip)]
    except Exception as e:
        logger.error(f"Erreur de conversion IP: {e}", exc_info=True)
        return []

def setup_raw_socket():
    """Initialise et configure une socket RAW avec gestion d'erreur"""
    logger.info("Configuration de la socket RAW...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Optimisation des paramètres socket
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024*1024)  # 1MB buffer
        logger.info("Socket RAW configurée avec succès")
        return s
    except PermissionError:
        logger.critical("Erreur: Besoin des privilèges root (sudo)")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Erreur de configuration socket: {e}", exc_info=True)
        sys.exit(1)

def calculate_checksum(data):
    """Calcule le checksum pour les en-têtes avec logging de débogage"""
    logger.debug("Calcul du checksum...")
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s = s + w
    
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return socket.htons(s)

def craft_raw_packet(src_ip, src_port, dst_ip, dst_port, scan_type):
    """Construit un paquet réseau brut avec logging détaillé"""
    logger.debug(f"Construction paquet: {src_ip}:{src_port} > {dst_ip}:{dst_port} [{scan_type}]")
    
    # Construction header IP
    ip_header = pack('!BBHHHBBH4s4s',
                    0x45, 0, 40,  # Version, TOS, Longueur totale
                    random.randint(1, 65535),  # ID
                    0,  # Fragmentation
                    64,  # TTL
                    socket.IPPROTO_TCP,  # Protocol
                    0,  # Checksum (calculé plus tard)
                    socket.inet_aton(src_ip),
                    socket.inet_aton(dst_ip))
    
    # Construction header TCP
    tcp_flags = {
        'SYN': 0x02,
        'FIN': 0x01,
        'XMAS': 0x29,  # FIN|PSH|URG
        'NULL': 0x00,
        'ACK': 0x10
    }.get(scan_type, 0x02)  # Default to SYN
    
    tcp_header_nochk = pack('!HHLLBBH',
                          src_port,
                          dst_port,
                          random.randint(0, 4294967295),  # Seq
                          0,  # Ack
                          (5 << 4),  # Data offset
                          tcp_flags,
                          5840)  # Window
    
    # Calcul checksum TCP
    pseudo_header = pack('!4s4sBBH',
                        socket.inet_aton(src_ip),
                        socket.inet_aton(dst_ip),
                        0,
                        socket.IPPROTO_TCP,
                        len(tcp_header_nochk))
    
    checksum_val = calculate_checksum(pseudo_header + tcp_header_nochk)
    tcp_header = tcp_header_nochk[:16] + pack('H', checksum_val) + pack('!H', 0)  # Urg
    
    # Calcul checksum IP
    ip_header_without_check = ip_header[:10] + b'\x00\x00' + ip_header[12:]
    ip_checksum = calculate_checksum(ip_header_without_check)
    ip_header = ip_header_without_check[:10] + pack('H', ip_checksum) + ip_header[12:]
    
    logger.debug("Paquet construit avec succès")
    return ip_header + tcp_header

# --- THREAD MANAGER ---

class PacketSender(Thread):
    """Thread d'envoi de paquets avec gestion d'erreur et statistiques"""
    def __init__(self, packets, thread_id):
        Thread.__init__(self)
        self.packets = packets
        self.thread_id = thread_id
        self.sent_count = 0
        self.error_count = 0
        self.socket = None
    
    def run(self):
        logger.info(f"Thread {self.thread_id} démarre avec {len(self.packets)} paquets")
        start_time = time.time()
        
        try:
            self.socket = setup_raw_socket()
            
            for i, packet in enumerate(self.packets):
                try:
                    self.socket.sendto(packet, (TARGET_IP, 0))
                    self.sent_count += 1
                    
                    # Log toutes les 100 paquets pour suivi
                    if i % 100 == 0:
                        logger.debug(f"Thread {self.thread_id} a envoyé {i} paquets")
                        
                except Exception as e:
                    self.error_count += 1
                    logger.warning(f"Erreur dans thread {self.thread_id}: {e}")
                    
        except Exception as e:
            logger.error(f"ERREUR CRITIQUE thread {self.thread_id}: {e}")
        finally:
            if self.socket:
                self.socket.close()
                
            duration = time.time() - start_time
            rate = len(self.packets) / duration if duration > 0 else 0
            logger.info(
                f"Thread {self.thread_id} terminé. "
                f"Envoyés: {self.sent_count}, Erreurs: {self.error_count}, "
                f"Taux: {rate:.2f} pkt/s"
            )

# --- MAIN FUNCTION ---

def main():
    """Fonction principale avec gestion complète du scan"""
    logger.info("=== Démarrage de WhisperScan ===")
    logger.info(f"Version: RAW Socket Optimisée - {datetime.now()}")
    
    # Vérification initiale
    if not sys.platform.startswith('linux'):
        logger.warning("Attention: Ce script est optimisé pour Linux")
    
    # Conversion plage IP
    source_ips = ip_range_to_list(SOURCE_IP_RANGE)
    if not source_ips:
        logger.critical("Aucune IP source valide - Arrêt")
        sys.exit(1)
    
    src_ip = source_ips[0]
    logger.info(f"IP source sélectionnée: {src_ip}")
    
    # Préparation des paquets
    logger.info(f"Préparation de {TOTAL_PACKETS} paquets...")
    packets = []
    start_gen = time.time()
    
    for i in range(TOTAL_PACKETS):
        port = TARGET_PORTS[i % len(TARGET_PORTS)]
        src_port = BASE_SOURCE_PORT + (i % (65535 - BASE_SOURCE_PORT))
        packet = craft_raw_packet(src_ip, src_port, TARGET_IP, port, SCAN_TYPE)
        packets.append(packet)
        
        # Log progression
        if i % 500 == 0:
            logger.debug(f"Généré {i} paquets...")
    
    gen_time = time.time() - start_gen
    logger.info(f"Génération terminée en {gen_time:.2f}s ({TOTAL_PACKETS/gen_time:.2f} pkt/s)")
    
    # Répartition des paquets entre threads
    threads = []
    for i in range(THREAD_COUNT):
        start = i * PACKETS_PER_THREAD
        end = None if i == THREAD_COUNT-1 else (i+1)*PACKETS_PER_THREAD
        thread = PacketSender(packets[start:end], i+1)
        threads.append(thread)
    
    # Lancement des threads
    logger.info(f"Lancement de {THREAD_COUNT} threads d'envoi...")
    start_send = time.time()
    
    for t in threads:
        t.start()
    
    # Attente et statistiques
    total_sent = 0
    total_errors = 0
    
    for t in threads:
        t.join()
        total_sent += t.sent_count
        total_errors += t.error_count
    
    send_time = time.time() - start_send
    logger.info(
        "=== RÉCAPITULATIF ==="
        f"\nPaquets envoyés: {total_sent}/{TOTAL_PACKETS}"
        f"\nErreurs: {total_errors}"
        f"\nTemps total: {send_time:.2f}s"
        f"\nDébit moyen: {total_sent/send_time:.2f} paquets/sec"
    )
    
    # Vérification finale
    logger.info(f"Pour vérification, exécutez:")
    logger.info(f"sudo tcpdump -i {INTERFACE} -nn -tttt 'tcp and host {TARGET_IP}'")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Scan interrompu par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Erreur fatale: {e}", exc_info=True)
        sys.exit(1)