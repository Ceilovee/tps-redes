
#porcentaje de protocolos
from scapy.all import *
import datetime
from collections import Counter

# Get the initial datetime
INITIAL_DATETIME = datetime.datetime.now()

# Diccionario para los simbolos
S1 = {}
# Diccionario para los símbolos basados en direcciones IP
S2 = {}
# Contador de UNICAST y BROADCAST
unicast_count = 0
broadcast_count = 0

# Funcion que procesa los paquetes sniffeados
def callback(pkt):
    global unicast_count
    global broadcast_count

    if ARP in pkt:
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

        # Clasifico UNICAST o BROADCAST basado en las direcciones IP
        if dst_ip == "255.255.255.255":
            dire = "BROADCAST"
            broadcast_count += 1
        else:
            dire = "UNICAST"
            unicast_count += 1

        # Armo el símbolo para el diccionario S2
        s_i = (dire, src_ip, dst_ip)

        # Veo si ya existía y con la cantidad de apariciones calculo la probabilidad
        if s_i not in S2:
            S2[s_i] = 0.0
        S2[s_i] += 1.0


def mostrar_fuente_S2(S):
    # Calculo el número de símbolos y los ordeno descending por cantidad
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])

    entropy = 0.0
    output_lines = []
    output_lines.append("\n------------Fuente de Información S2------------")

    for d, k in simbolos:
        # Calculo probabilidad del símbolo (d, k)
        probability = k / N
        output_line = "%s : prob=%.5f" % (d, probability)

        # Calculo la cantidad de información del símbolo (d, k)
        information = -math.log2(probability)
        entropy += information * probability
        output_line += " : info=%.5f" % (information)

        # Printeo la cantidad
        symbol_count = S[d]
        output_line += f" : count={int(symbol_count)}"
        output_lines.append(output_line)

    output_lines.append("\n-------------------------------------------")
    output_lines.append(f"Entropia de S2: {entropy}")
    output_lines.append("-------------------------------------------------")

    # Printeo todo
    outputString = "\n".join(output_lines)
    print(outputString)

# Luego de procesar los paquetes ARP, llamamos a la función mostrar_fuente_S2
paqutesARP = 0
with PcapReader("./Resultados/centro_medico.pcapng") as pcap_reader:
    for pkt in pcap_reader:
        callback(pkt)
        if ARP in pkt: 
            paqutesARP+=1
print("HAY ", paqutesARP, " PAQUETES ARP")
mostrar_fuente_S2(S2)
