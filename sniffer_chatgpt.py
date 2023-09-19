from scapy.all import *

# Diccionario para mantener un registro de las direcciones IP y sus conteos
ip_counts = {}

# Función para calcular la información de un símbolo
def calculate_information(probability):
    if probability == 0:
        return 0
    return -math.log2(probability)

# Interfaz de red a capturar (ajusta a tu entorno)
interface = "eth0"

# Filtra paquetes ARP en la interfaz especificada
def arp_packet_handler(packet):
    if ARP in packet:
        arp_layer = packet[ARP]
        if arp_layer.op == 1:  # Paquete ARP de solicitud (who-has)
            ip = arp_layer.pdst
            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1

# Comienza la captura en la interfaz especificada
sniff(iface=interface, filter="arp", prn=arp_packet_handler, store=0, timeout=60)

# Calcula la probabilidad de ocurrencia de cada dirección IP
total_packets = sum(ip_counts.values())
probabilities = {ip: count / total_packets for ip, count in ip_counts.items()}

# Calcula la información de cada símbolo y la entropía de la fuente
entropy = 0
for ip, probability in probabilities.items():
    information = calculate_information(probability)
    entropy += probability * information
    print(f"IP: {ip}, Probabilidad: {probability}, Información: {information}")

print(f"Entropía de la fuente: {entropy}")