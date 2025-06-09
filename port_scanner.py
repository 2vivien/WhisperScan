import asyncio
from scapy.all import IP, TCP, sr1, RandShort
from collections import defaultdict
import logging

# Configuration
TARGET_IP = "192.168.0.100"
TARGET_PORTS = range(1, 1025)  # Scan des 1024 premiers ports
SCAN_TYPE = "SYN"
MAX_CONCURRENT_SCANS = 500  # Limite de scans simultanés
TIMEOUT = 2  # 2 secondes max par port

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("PortScanner")

PORT_STATUS = defaultdict(str)

async def scan_port(port):
    try:
        # Construction du paquet SYN
        ip_pkt = IP(dst=TARGET_IP)
        tcp_pkt = TCP(sport=RandShort(), dport=port, flags="S")
        packet = ip_pkt / tcp_pkt

        # Envoi et attente de réponse (non-bloquant)
        response = await asyncio.to_thread(sr1, packet, timeout=TIMEOUT, verbose=0)

        if response:
            if response.haslayer(TCP):
                if response[TCP].flags & 0x12:  # SYN-ACK → Port ouvert
                    PORT_STATUS[port] = "open"
                elif response[TCP].flags & 0x14:  # RST → Port fermé
                    PORT_STATUS[port] = "closed"
            else:
                PORT_STATUS[port] = "filtered"
        else:
            PORT_STATUS[port] = "filtered"

    except Exception as e:
        logger.error(f"Erreur sur le port {port}: {e}")
        PORT_STATUS[port] = "error"

async def run_scan():
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    async def limited_scan(port):
        async with semaphore:
            await scan_port(port)

    tasks = [limited_scan(port) for port in TARGET_PORTS]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    logger.info("Démarrage du scan...")
    asyncio.run(run_scan())

    # Affichage des résultats
    for port, status in sorted(PORT_STATUS.items()):
        logger.info(f"Port {port}: {status}")