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

# Funcion que calcula las probabilidades y las muestra dependiendo el parametro
def mostrar_fuente(S, printOutput=True, printExtraInformation=True, calculateInformation=True):
    # Calculo el numero de simbolos y los ordeno descending por cantidad
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])  
    
    # Veo si printear 
    if printOutput:
        entropy = 0.0
        output_lines = []
        output_lines.append("------------Paquetes Capturados------------")
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
        output_lines.append("-------------------------------------------")

        if calculateInformation:
            output_lines.append(f"Entropia: {entropy}")
            output_lines.append("")

        # Veo si printear informacion extra
        if printExtraInformation:

            # Calculo el porcentaje de UNICAST/BROADCAST
            total_entries = len(S)            
            unicast_percentage = (unicast_count / N)*100    
            broadcast_percentage = (broadcast_count / N)*100
            
            # Printeo
            output_lines.append("------------Porcentaje de Direcciones------------")
            output_lines.append(f"UNICAST: {unicast_percentage}%")
            output_lines.append(f"BROADCAST: {broadcast_percentage}%")
            output_lines.append("-------------------------------------------------")
            output_lines.append("")

            # Calculo porcentaje de protocolos
            output_lines.append("------------Porcentaje de Protocolos------------")
            s = sum(S1.values())
            for k, v in S1.items():
                pct = v * 100.0 / s
                output_lines.append(f"{k[1]}: {pct}%")
            output_lines.append("------------------------------------------------")
            output_lines.append("")
           
            # Calculo el runtime
            current_datetime = datetime.datetime.now()
            runtime = current_datetime - INITIAL_DATETIME
            output_lines.append(f"Captura comenzada el {INITIAL_DATETIME} y finalizada el {current_datetime}. Duracion: {runtime}")

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
    
    # Printeo
    mostrar_fuente(S1, printOutput=False, printExtraInformation=False, calculateInformation=False)  

#Sniffeo paquetes y los proceso con callback()
sniff(prn=callback, count=300)
mostrar_fuente(S1, printOutput=True, printExtraInformation=True, calculateInformation=True)  
