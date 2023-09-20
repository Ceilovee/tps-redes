
#porcentaje de protocolos
from scapy.all import *
import datetime
from collections import Counter

# Get the initial datetime
INITIAL_DATETIME = datetime.datetime.now()

# Diccionario para los simbolos
S1 = {}
# Contador de UNICAST y BROADCAST
unicast_count = 0
broadcast_count = 0

# pcap_file =rdpcap("./centro_medico.pcap")

# Funcion que calcula las probabilidades y las muestra dependiendo el parametro
def mostrar_fuente(S):

    # Calculo el numero de simbolos y los ordeno descending por cantidad
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    
    entropy = 0.0
    output_lines = []
    output_lines.append("\n------------Paquetes Capturados------------")

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

    output_lines.append(f"Entropia: {entropy}")

    # Calculo el porcentaje de UNICAST/BROADCAST
    unicast_percentage   = (unicast_count   / N)*100    
    broadcast_percentage = (broadcast_count / N)*100
    
    output_lines.append("\n------------Porcentaje de Direcciones------------")
    output_lines.append(f"UNICAST:   {  unicast_percentage}%")
    output_lines.append(f"BROADCAST: {broadcast_percentage}%")
    output_lines.append("-------------------------------------------------")

    # Calculo porcentaje de protocolos
    output_lines.append("\n------------Porcentaje de Protocolos------------")

    for k, v in S.items():
        pct = v * 100.0 / N
        output_lines.append(f"{k[1]}: {pct}%")
    
    output_lines.append("------------------------------------------------")
           
    # Calculo el runtime
    CURRENT_DATETIME = datetime.datetime.now()
    RUNTIME = CURRENT_DATETIME - INITIAL_DATETIME
    output_lines.append(f"Captura comenzada el {INITIAL_DATETIME} y finalizada el {CURRENT_DATETIME}. Duracion: {RUNTIME}")

    # Printeo todo
    outputString = "\n".join(output_lines)
    print(outputString)



# Funcion que procesa los paquetes sniffeados
def callback(pkt):
    global unicast_count
    global broadcast_count

    if pkt.haslayer(Ether):
        # Clasifico BROADCAST o UNICAST y tomo el protocolo
        if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
            dire = "BROADCAST"
            broadcast_count += 1
        else: 
            dire = "UNICAST"
            unicast_count += 1

        proto = pkt[Ether].type
        
        # Armo el simbolo para el diccionario
        s_i = (dire, proto)
        
        # Veo si ya existia, y con la cantidad de apariciones calculo la probabilidad
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0


# En vez de sniffear paquetes, leemos el archivo de pcap
# sniff(prn=callback, count=10000)
# for p in pcap_file:
#     callback(p)
limiter = 0
with PcapReader("./Captura-18-09-23-HostingMCServer15mins.pcap") as pcap_reader:
    for pkt in pcap_reader:
        callback(pkt)
        limiter += 1

mostrar_fuente(S1)
