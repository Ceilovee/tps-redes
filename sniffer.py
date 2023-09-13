#porcentaje de protocolos
from scapy.all import *
import datetime

# Get the initial datetime
INITIAL_DATETIME = datetime.datetime.now()

# Diccionario para los simbolos
S1 = {}

# Funcion que calcula las probabilidades y las muestra dependiendo el parametro
def mostrar_fuente(S, printOutput=True, printExtraInformation=True, calculateInformation=True):
    # Calculo el numero de simbolos
    N = sum(S.values())
    # Los ordeno descending por la cantidad
    simbolos = sorted(S.items(), key=lambda x: -x[1])  
    
    entropy = 0
    if printOutput:
        output_lines = []
        for d, k in simbolos:
            probability = k / N
            output_line = "%s : prob=%.5f" % (d, probability)
            
            # Veo si calcular la informacion
            if calculateInformation:
                information = -math.log2(probability)
                entropy += information * probability
                output_line += " : info=%.5f" % (information)
            
            # Veo si printear la cantidad
            if printExtraInformation:
                symbol_count = S[d]
                output_line += f" : count={int(symbol_count)}"
            
            output_lines.append(output_line)

        if calculateInformation:
            output_lines.append(f"Entropia: {entropy}")

        # Veo si printear informacion extra
        if printExtraInformation:
            # Calculo el porcentaje de UNICAST/BROADCAST
            num_unicast_packets = S.get('UNICAST', 0)
            num_broadcast_packets = S.get('BROADCAST', 0)
            total_entries = len(S)            
            unicast_percentage = num_unicast_packets / N    
            broadcast_percentage = num_broadcast_packets / N
            
            # Printeo
            output_lines.append(f"Porcentaje de paquetes UNICAST: {unicast_percentage}")
            output_lines.append(f"Porcentaje de paquetes BROADCAST: {broadcast_percentage}")
            output_lines.append(f"Total de entradas: {total_entries}")           

            # Calculo el porcentaje de protocolos


            # Calculo el runtime
            current_datetime = datetime.datetime.now()
            runtime = current_datetime - INITIAL_DATETIME
            output_lines.append(f"Captura comenzada en {INITIAL_DATETIME} y finalizada en {current_datetime}. Duracion: {runtime})")

        outputString = "\n".join(output_lines)
        print(outputString)

# Funcion que procesa los paquetes sniffeados
def callback(pkt):
    if pkt.haslayer(Ether):
        # Clasifico BROADCAST o UNICAST y tomo el protocolo
        dire = "BROADCAST" if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff" else "UNICAST"  
        proto = pkt[Ether].type  
        
        # Armo el simbolo para el diccionario
        s_i = (dire, proto)
        
        # Veo si ya existia, y con la cantidad de apariciones calculo la probabilidad
        if s_i not in S1:
            S1[s_i] = 0.0
        S1[s_i] += 1.0  
    
    # Printeo
    mostrar_fuente(S1, printOutput=False, printExtraInformation=False, calculateInformation=False)  

#Sniffeo 100 paquetes y los proceso con callback()
sniff(prn=callback, count=30)
mostrar_fuente(S1, printOutput=True, printExtraInformation=True, calculateInformation=True)  
