from scapy.all import *

# Diccionario para los simbolos
S1 = {}

# Funcion que calcula las probabilidades y las muestra dependiendo el parametro
def mostrar_fuente(S, printOutput=True, printCount=False):
    # Calculo el numero de simbolos
    N = sum(S.values())
    # Los ordeno descending por la cantidad
    simbolos = sorted(S.items(), key=lambda x: -x[1])  
    if(printOutput):
        if(printCount):
            print("\n".join(["%s : %d : %.5f" % (d,k, k / N) for d, k in simbolos]))
        else:
            print("\n".join(["%s : %.5f" % (d, k / N) for d, k in simbolos]))
        print()

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
    mostrar_fuente(S1, printOutput = False)  

#Sniffeo 100 paquetes y los proceso con callback()
sniff(prn=callback, count=1000)
mostrar_fuente(S1, printOutput=True, printCount=False)  
