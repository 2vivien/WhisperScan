#!/usr/bin/env python3
import socket
import random
import ipaddress
import sys
import time
from struct import pack, unpack
from threading import Thread
import logging
from datetime import datetime
import asyncio
from collections import defaultdict
import urllib.request

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

INTERFACE = "wlp2s0"                  # Mon interface réseau (WiFi ici)
TARGET_IP = "192.168.0.100"           # 🎯 IP de la machine cible (celle à scanner)
SOURCE_IP_RANGE = "192.168.0.108"     # ✅ mon IP (moi, la machine qui scanne)
BASE_SOURCE_PORT = 49152
TARGET_PORTS = list(range(1, 201)) + [80, 443, 3389, 8080]
SCAN_TYPE = "SYN"
TOTAL_PACKETS = 10000
THREAD_COUNT = 50

PACKETS_PER_THREAD = TOTAL_PACKETS // THREAD_COUNT

PORT_STATUS = defaultdict(list)  # {port: ["open", "closed", ...]}

# --- FONCTIONS UTILES ---

def ip_range_to_list(ip_range_str):
    logger.info(f"Conversion de la plage IP: {ip_range_str}")
    try:
        if "-" in ip_range_str:
            start_ip_str, end_ip_str = ip_range_str.split("-")
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())
            if start_ip > end_ip:
                raise ValueError("L'IP de début doit être <= IP de fin")
            return [str(ipaddress.ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]
        else:
            ip = ipaddress.ip_address(ip_range_str.strip())
            return [str(ip)]
    except Exception as e:
        logger.error(f"Erreur de conversion IP: {e}", exc_info=True)
        return []

def setup_raw_socket():
    logger.info("Configuration de la socket RAW...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
        logger.info("Socket RAW configurée avec succès")
        return s
    except PermissionError:
        logger.critical("Erreur: Besoin des privilèges root (sudo)")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Erreur de configuration socket: {e}", exc_info=True)
        sys.exit(1)

def calculate_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return socket.htons(s)

def craft_raw_packet(src_ip, src_port, dst_ip, dst_port, scan_type):
    logger.debug(f"Construction paquet: {src_ip}:{src_port} > {dst_ip}:{dst_port} [{scan_type}]")

    ip_header = pack('!BBHHHBBH4s4s',
                     0x45, 0, 40,
                     random.randint(1, 65535),
                     0,
                     64,
                     socket.IPPROTO_TCP,
                     0,
                     socket.inet_aton(src_ip),
                     socket.inet_aton(dst_ip))

    tcp_flags = {
        'SYN': 0x02,
        'FIN': 0x01,
        'XMAS': 0x29,
        'NULL': 0x00,
        'ACK': 0x10
    }.get(scan_type, 0x02)

    tcp_header_nochk = pack('!HHLLBBH',
                            src_port,
                            dst_port,
                            random.randint(0, 4294967295),
                            0,
                            (5 << 4),
                            tcp_flags,
                            5840)

    pseudo_header = pack('!4s4sBBH',
                         socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip),
                         0,
                         socket.IPPROTO_TCP,
                         len(tcp_header_nochk))

    checksum_val = calculate_checksum(pseudo_header + tcp_header_nochk)
    tcp_header = tcp_header_nochk[:16] + pack('H', checksum_val) + pack('!H', 0)

    ip_header_without_check = ip_header[:10] + b'\x00\x00' + ip_header[12:]
    ip_checksum = calculate_checksum(ip_header_without_check)
    ip_header = ip_header_without_check[:10] + pack('H', ip_checksum) + ip_header[12:]

    return ip_header + tcp_header

def decode_ip_header(data):
    iphdr = unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = iphdr[0]
    ihl = version_ihl & 0xF
    ip_src = socket.inet_ntoa(iphdr[8])
    ip_dst = socket.inet_ntoa(iphdr[9])
    protocol = iphdr[6]
    return ip_src, ip_dst, protocol, ihl * 4

def decode_tcp_header(data):
    tcphdr = unpack('!HHLLBBHHH', data[:20])
    src_port = tcphdr[0]
    dst_port = tcphdr[1]
    flags = tcphdr[5]
    syn_flag = (flags >> 1) & 0x1
    ack_flag = (flags >> 4) & 0x1
    rst_flag = (flags >> 2) & 0x1
    return src_port, dst_port, syn_flag, ack_flag, rst_flag

def get_public_ip():
    try:
        with urllib.request.urlopen('https://api.ipify.org') as response:
            return response.read().decode('utf8')
    except Exception as e:
        logger.error(f"Impossible de récupérer l'IP publique : {e}")
        return None

def get_local_ip(interface):
    # Détecte l'IP locale de l'interface réseau (ex: wlan0, wlp2s0)
    import fcntl, struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[20:24])
    except Exception as e:
        logger.error(f"Impossible de récupérer l'IP locale de {interface} : {e}")
        return None

# --- RÉCEPTION DES RÉPONSES ASYNC ---
async def listen_for_responses(interface, target_ip, target_ports, source_ips):
    logger.info(f"Capture des réponses sur interface {interface}...")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.setblocking(False)
    sock.bind((interface, 0))

    try:
        while True:
            try:
                raw_data = sock.recvfrom(65535)[0]
                

                eth_protocol = unpack('!H', raw_data[12:14])[0]
                if eth_protocol != 0x0800:
                    continue

                ip_data = raw_data[14:]
                ip_src, ip_dst, protocol, iph_len = decode_ip_header(ip_data)

                if ip_dst not in source_ips or ip_src != target_ip:
                    continue

                if protocol == socket.IPPROTO_TCP:
                    tcp_data = ip_data[iph_len:]
                    src_port, dst_port, syn, ack, rst = decode_tcp_header(tcp_data)

                    if dst_port not in target_ports:
                        continue

                    if syn and ack:
                        PORT_STATUS[dst_port].append("open")
                    elif rst:
                        PORT_STATUS[dst_port].append("closed")
                    else:
                        PORT_STATUS[dst_port].append("filtered")

            except BlockingIOError:
                await asyncio.sleep(0.01)
            except Exception as e:
                logger.warning(f"Erreur lors de la capture réseau : {e}")
                break
    finally:
        sock.close()

# --- THREAD MANAGER ---
class PacketSender(Thread):
    def __init__(self, packets, thread_id):
        super().__init__()
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
                    if i % 100 == 0:
                        logger.debug(f"Thread {self.thread_id}: envoyé {i} paquets")
                except Exception as e:
                    self.error_count += 1
                    logger.warning(f"Erreur thread {self.thread_id}: {e}")
        except Exception as e:
            logger.error(f"ERREUR CRITIQUE thread {self.thread_id}: {e}")
        finally:
            if self.socket:
                self.socket.close()
            duration = time.time() - start_time
            rate = len(self.packets) / duration if duration > 0 else 0
            logger.info(f"Thread {self.thread_id} terminé. Envoyés: {self.sent_count}, Erreurs: {self.error_count}, Taux: {rate:.2f} pkt/s")

# --- MAIN FUNCTION ---
async def main():
    logger.info("=== Démarrage de WhisperScan ===")
    logger.info(f"Version: RAW Socket Optimisée - {datetime.now()}")

    if not sys.platform.startswith('linux'):
        logger.warning("Attention: Ce script est optimisé pour Linux")

    source_ips = ip_range_to_list(SOURCE_IP_RANGE)
    if not source_ips:
        logger.critical("Aucune IP source valide - Arrêt")
        sys.exit(1)
    src_ip = source_ips[0]
    logger.info(f"IP source sélectionnée: {src_ip}")

    logger.info(f"Préparation de {TOTAL_PACKETS} paquets...")
    packets = []
    start_gen = time.time()
    for i in range(TOTAL_PACKETS):
        port = TARGET_PORTS[i % len(TARGET_PORTS)]
        src_port = BASE_SOURCE_PORT + (i % (65535 - BASE_SOURCE_PORT))
        packet = craft_raw_packet(src_ip, src_port, TARGET_IP, port, SCAN_TYPE)
        packets.append(packet)
        if i % 500 == 0:
            logger.debug(f"Généré {i} paquets...")

    gen_time = time.time() - start_gen
    logger.info(f"Génération terminée en {gen_time:.2f}s ({TOTAL_PACKETS/gen_time:.2f} pkt/s)")

    threads = []
    for i in range(THREAD_COUNT):
        start = i * PACKETS_PER_THREAD
        end = None if i == THREAD_COUNT - 1 else (i + 1) * PACKETS_PER_THREAD
        thread = PacketSender(packets[start:end], i + 1)
        threads.append(thread)

    logger.info(f"Lancement de {THREAD_COUNT} threads d'envoi...")
    start_send = time.time()
    for t in threads:
        t.start()

    listener_task = asyncio.create_task(
        listen_for_responses(INTERFACE, TARGET_IP, TARGET_PORTS, source_ips)
    )

    for t in threads:
        t.join()
    send_time = time.time() - start_send

    logger.info("=== RAPPORT DES PORTS ===")
    for port in sorted(TARGET_PORTS):
        responses = PORT_STATUS[port]
        open_count = responses.count("open")
        closed_count = responses.count("closed")
        filtered_count = responses.count("filtered")
        status = "no response"
        if open_count > closed_count and open_count > filtered_count:
            status = "open"
        elif closed_count > open_count and closed_count > filtered_count:
            status = "closed"
        elif filtered_count > open_count and filtered_count > closed_count:
            status = "filtered"
        elif open_count == closed_count == filtered_count == 0:
            status = "no response"

        logger.info(f"Port {port}: {status} ({open_count} open, {closed_count} closed, {filtered_count} filtered)")

    # On laisse 2 secondes pour recevoir les réponses
    logger.info("Attente des réponses réseau pendant 2s...")
    await asyncio.sleep(2)

    # Arrêt propre de la capture
    logger.info("Arrêt de la capture...")
    listener_task.cancel()
    try:
        await asyncio.wait_for(listener_task, timeout=1)
    except asyncio.TimeoutError:
        logger.warning("Timeout lors de l'arrêt de la capture")
    except asyncio.CancelledError:
        pass

    logger.info("=== RAPPORT DES PORTS ===")
    for port in sorted(TARGET_PORTS):
        responses = PORT_STATUS[port]
        open_count = responses.count("open")
        closed_count = responses.count("closed")
        filtered_count = responses.count("filtered")
        status = "no response"
        if open_count > closed_count and open_count > filtered_count:
            status = "open"
        elif closed_count > open_count and closed_count > filtered_count:
            status = "closed"
        elif filtered_count > open_count and filtered_count > closed_count:
            status = "filtered"
        elif open_count == closed_count == filtered_count == 0:
            status = "no response"

        logger.info(f"Port {port}: {status} ({open_count} open, {closed_count} closed, {filtered_count} filtered)")

    logger.info(f"Pour vérifier les paquets reçus : sudo tcpdump -i {INTERFACE} -nn 'tcp and host {TARGET_IP}'")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Scan interrompu par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Erreur fatale: {e}", exc_info=True)
        sys.exit(1)