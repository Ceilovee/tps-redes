from scapy.all import *

# Recibo la entrada desde consola
import sys
file_dir = "" # Acá vamos a guardar la dire del pcap
if (len(sys.argv) == 1):
    print(">>> usage: python3", sys.argv[0], "./Resultados/<pcap file>") # Mensaje de error, no se recibió dirección de pcap
else:
    file_dir = sys.argv[1]                                               # Esta es la dirección del pcap


# Diccionario de IPs: (IP, # de apariciones)
S2 = {}


def mostrar_fuente(S):
    output_lines = []
    output_lines.append("\n------------Direcciones Encontradas------------")

    simbolos = sorted(S.items(), key=lambda x: -x[1])

    for d, k in simbolos:
        output_line = "IP: %s Count: %i" % (d, k)
        output_lines.append(output_line)

    outputString = "\n".join(output_lines)
    print(outputString)


# Funcion que procesa los paquetes sniffeados
def callback(pkt):

    if pkt.haslayer(Ether):

        proto = pkt[Ether].type

        if (ARP in pkt): # ARP es el protocolo 2054

            # TODO: No estoy segura de cómo tiene que ser esta linea
            dire = pkt[Ether].dst
            #dire = pkt.dst

            # Armo el simbolo para el diccionario
            s_i = (dire, proto)    
        
            # Veo si ya existia, y con la cantidad de apariciones calculo la probabilidad
            if s_i not in S2:
                S2[s_i] = 0.0
            S2[s_i] += 1.0


limiter = 0
if (file_dir != ""): #¿Recibimos dirección de entrada?
    with PcapReader(file_dir) as pcap_reader:
        for pkt in pcap_reader:
            callback(pkt)
            limiter += 1
    
    mostrar_fuente(S2)