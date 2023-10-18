#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
import numpy as np

# Cantidad de paquetes a enviar para calcular el RTT promedio
burst_size = 5

# Calculamos el RTT promedio para un TTL dado. 
# Si nos pasan una IP, calculamos el RTT promedio para esa IP en lugar de un TTL generico.
# Ademas, devolvemos la IP mas repetida.
def calculate_rtt_info(ttl=25, ip=0):
    # Creo un set para encontrar la IP mas comun
    ip_set = set()
    # Creo un array para guardar los RTTs
    rtt_list = np.empty(burst_size, dtype=float)
    for i in range(burst_size):
        # Si no me pasaron una IP, calculo el RTT promedio para el TTL dado, y viceversa.
        if ip == 0:
            probe = IP(dst=sys.argv[1], ttl=ttl) / ICMP()
        else:    
            probe = IP(dst=ip, ttl=ttl) / ICMP()
        t_i = time()
        ans = sr1(probe, verbose=False, timeout=5)
        t_f = time()
        # Si recibo respuesta, calculo el RTT y lo agrego a la lista de RTTs. Lo mismo para la IP
        if ans is not None:
            rtt = (t_f - t_i) * 1000
            rtt_list[i] = rtt
            ip_set.add(ans.src)
    
    # Si la lista no es vacia, calculo el RTT promedio
    if(rtt_list.any()):
        return np.mean(rtt_list[rtt_list > 0]), max(set(ip_set), key=list(ip_set).count, default=0)
    return 0,0


responses = {}

# Traceroute con TTLs incrementales
for i in range(1):
    print()
    for ttl in range(1, 25):
        probe = IP(dst=sys.argv[1], ttl=ttl) / ICMP()
        t_i = time()
        ans = sr1(probe, verbose=False, timeout=5)
        t_f = time()
        rtt = (t_f - t_i) * 1000

        if ans is not None:
            if ttl not in responses:
                responses[ttl] = []
            responses[ttl].append((ans.src, rtt))

            if ttl in responses:
                # Calculamos el rtt promedio para el ttl actual, y tambien la ip que mas aparece al llamar a este ttl
                mean_rtt_for_ttl, most_frequent_ip = calculate_rtt_info(ttl=ttl)
                # Tambien calculamos el rtt promedio para llegar a la ip en la que estamos ahora
                mean_rtt_for_current_path_ip = calculate_rtt_info(ip=ans.src)
                # Y por ultimo, tambien para la ip mas comun
                mean_rtt_for_most_frequent_ip = calculate_rtt_info(ip=most_frequent_ip)
                print(f"""TTL: {ttl}
                    RTT: {responses[ttl]}
                    RTT Promedio: {mean_rtt_for_ttl}
                    RTT Promedio para la IP actual: {mean_rtt_for_current_path_ip}
                    IP Mas Comun: {most_frequent_ip}
                    RTT Promedio para la IP mas comun: {mean_rtt_for_most_frequent_ip}
                    """)

    
                
