#!/usr/bin/env python3
from scapy.all import *
import time
import random
import ipaddress
import threading

try:
    import netifaces
except ImportError:
    print("Warning: netifaces is not installed. Please install it (e.g., 'pip install netifaces') or ensure your IDS and tcpdump are configured correctly.")
    netifaces = None  # Continue, but with limited interface detection

def get_default_interface():
    """
    Tries to get the default network interface.
    If netifaces is not available, returns None and prints a warning.
    """
    if netifaces is None:
        return None
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            for iface in netifaces.interfaces():
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                        if link['addr'] == default_gateway[1]:
                            return iface
        return None
    except AttributeError:
        print("Warning: netifaces.gateways() returned an unexpected structure.")
        return None
    except Exception as e:
        print(f"Warning: Error getting default interface: {e}. Ensure your IDS and tcpdump are configured correctly.")
        return None

def get_ip_from_interface(interface):
    """
    Gets the IP address associated with a given interface.
    """
    if netifaces is None:
        return None
    try:
        iface_details = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in iface_details:
            return iface_details[netifaces.AF_INET][0]['addr']
        else:
            return None
    except ValueError:
        print(f"Warning: Interface '{interface}' not found.")
        return None
    except Exception as e:
        print(f"Warning: Error getting IP for interface '{interface}': {e}")
        return None

# Attempt to get the default interface (optional, for informational purposes)
DEFAULT_INTERFACE = get_default_interface()

if DEFAULT_INTERFACE:
    print(f"Default interface detected: {DEFAULT_INTERFACE}")
    SOURCE_IP = get_ip_from_interface(DEFAULT_INTERFACE)
    if SOURCE_IP:
        print(f"Source IP for default interface: {SOURCE_IP}")
    else:
        print("Could not determine source IP for default interface.")
else:
    print("Could not automatically determine the default network interface.")
    print("Ensure your IDS and tcpdump are configured to use the correct interface.")

# Force Scapy to use wlp2s0 even if netifaces didn't find a default
conf.iface = "wlp2s0"

# --- CONFIGURATION ---
TARGET_IP = "192.168.0.108"
SOURCE_IP_RANGE = "192.168.1.50"  # Une seule IP au lieu d'une plage
BASE_SOURCE_PORT = 49152
TARGET_PORTS = list(range(1, 101)) + [80, 443]  # Ports classiques, en ordre
SCAN_TYPE = "SYN"

# Augmente la vitesse d'injection
BASE_PACKETS_PER_SECOND = 1000    # Passé à 1000/s
VARIATION_PERCENTAGE = 10         # Moins de variation
TOTAL_PACKETS = 10000              # Plus de volume
BURST_MODE = True
BURST_SIZE = 500                   # Gros bursts rapides
BURST_INTERVAL = 0.1               # Très court intervalle entre bursts

# --- PARAMÈTRES DE DÉTECTION IDS ---
SYN_SCAN_THRESHOLD_COUNT = 5
SYN_SCAN_WINDOW_SECONDS = 5
HORIZONTAL_SCAN_PORT_THRESHOLD = 15
HORIZONTAL_SCAN_WINDOW_SECONDS = 10
PORT_SWEEP_THRESHOLD = 15
PORT_SWEEP_WINDOW_SECONDS = 10


# --- FONCTIONS UTILES ---
def ip_range_to_list(ip_range_str):
    """
    Convertit une plage d'adresses IP au format "192.168.1.50-192.168.1.99"
    en une liste d'adresses IP valides.
    """
    try:
        start_ip_str, end_ip_str = ip_range_str.split("-")
        start_ip = ipaddress.ip_address(start_ip_str)
        end_ip = ipaddress.ip_address(end_ip_str)

        if start_ip.version != end_ip.version:
            raise ValueError("Mismatched IP versions")

        if start_ip > end_ip:
            raise ValueError("Start IP must be less than or equal to end IP")

        # Conversion correcte avec int(ip) pour éviter les problèmes
        start_int = int(start_ip)
        end_int = int(end_ip)

        return [str(ipaddress.ip_address(ip)) for ip in range(start_int, end_int + 1)]
    except ValueError as e:
        print(f"Invalid IP range format: {e}")
        return [ip_range_str]  # Retourne comme une seule IP si invalide


def craft_packet(src_ip, src_port, dst_ip, dst_port, scan_type):
    """
    Crée un paquet IP/TCP avec les paramètres spécifiés.
    """
    ip_packet = IP(src=src_ip, dst=dst_ip)
    if scan_type == "SYN":
        tcp_flags = "S"
    elif scan_type == "FIN":
        tcp_flags = "F"
    elif scan_type == "XMAS":
        tcp_flags = "FPU"  # FIN, PUSH, URG
    elif scan_type == "NULL":
        tcp_flags = ""
    else:  # ACK scan
        tcp_flags = "A"
    tcp_packet = TCP(sport=src_port, dport=dst_port, flags=tcp_flags)
    return ip_packet / tcp_packet


def inject_traffic(target_ip, source_ips, target_ports, scan_type, base_pps, variation_percentage, total_packets, burst_mode, burst_size, burst_interval):
    packets_sent = 0
    start_time = time.time()
    print("Démarrage de WhisperScan...", flush=True)
    print(f"Ciblant: {target_ip}", flush=True)
    print(f"Type de scan: {scan_type}", flush=True)

    src_ip = random.choice(source_ips)  # Choisis une seule IP source
    target_ports.sort()  # Trie les ports pour simuler un scan linéaire

    try:
        for i in range(total_packets):
            src_port = BASE_SOURCE_PORT + random.randint(0, 65535 - BASE_SOURCE_PORT)
            dst_port = target_ports[i % len(target_ports)]  # Scan cyclique des ports

            packet = craft_packet(src_ip, src_port, target_ip, dst_port, scan_type)
            send(packet, verbose=False)
            packets_sent += 1

            if burst_mode and packets_sent % burst_size == 0:
                time.sleep(burst_interval)
            else:
                pps = base_pps + random.uniform(-base_pps * variation_percentage / 100, base_pps * variation_percentage / 100)
                pps = max(pps, 1)
                time_elapsed = time.time() - start_time
                sleep_time = (packets_sent / pps) - time_elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)

            if packets_sent % 100 == 0:
                print(f"Paquets envoyés: {packets_sent}/{total_packets}", end='\r', flush=True)

        print(f"\nInjection de trafic terminée. {packets_sent} paquets envoyés en {time.time() - start_time:.2f} secondes.", flush=True)

    except KeyboardInterrupt:
        print("\nInjection de trafic interrompue par l'utilisateur.", flush=True)
    except Exception as e:
        print(f"\nUne erreur s'est produite lors de l'injection de trafic : {e}", flush=True)

# --- MAIN ---
if __name__ == "__main__":
    print("--- Initialisation de WhisperScan ---", flush=True)
    source_ips = ip_range_to_list(SOURCE_IP_RANGE)

    print("--- Paramètres de l'injection de trafic ---", flush=True)
    print(f"Cible: {TARGET_IP}", flush=True)
    print(f"IPs sources: {source_ips}", flush=True)
    print(f"Ports cibles: {TARGET_PORTS}", flush=True)
    print(f"Type de scan: {SCAN_TYPE}", flush=True)
    print(f"Vitesse d'injection de base: {BASE_PACKETS_PER_SECOND} paquets/seconde", flush=True)
    print(f"Variation de la vitesse: ±{VARIATION_PERCENTAGE}%", flush=True)
    print(f"Nombre total de paquets: {TOTAL_PACKETS}", flush=True)
    print(f"Mode Burst: {BURST_MODE}", flush=True)
    if BURST_MODE:
        print(f"Taille du Burst: {BURST_SIZE} paquets", flush=True)
        print(f"Intervalle entre les Bursts: {BURST_INTERVAL} secondes", flush=True)

    print("\n--- Paramètres de détection IDS (pour info) ---", flush=True)
    print(f"SYN Scan : seuil={SYN_SCAN_THRESHOLD_COUNT}, fenêtre={SYN_SCAN_WINDOW_SECONDS}s", flush=True)
    print(f"Horizontal Scan : seuil={HORIZONTAL_SCAN_PORT_THRESHOLD}, fenêtre={HORIZONTAL_SCAN_WINDOW_SECONDS}s", flush=True)
    print(f"Port Sweep : seuil={PORT_SWEEP_THRESHOLD}, fenêtre={PORT_SWEEP_WINDOW_SECONDS}s", flush=True)

    print("\n--- Démarrage de l'injection de trafic ---", flush=True)
    inject_traffic(TARGET_IP, source_ips, TARGET_PORTS, SCAN_TYPE, BASE_PACKETS_PER_SECOND, VARIATION_PERCENTAGE, TOTAL_PACKETS, BURST_MODE, BURST_SIZE, BURST_INTERVAL)

    tcpdump_command = f"sudo tcpdump -i wlp2s0 -nn -vv 'tcp and host {TARGET_IP}'"
    print("\n--- Vérification avec tcpdump (Exemple) ---")
    print(f"Exécutez cette commande dans un autre terminal sur la machine cible (ou celle qui capture le trafic):")
    print(f"  {tcpdump_command}")
    print("  (Assurez-vous que l'interface wlp2s0 est correcte pour votre système)")