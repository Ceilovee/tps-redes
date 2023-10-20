#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
import numpy as np

# Cantidad de paquetes a enviar para calcular el RTT promedio
burst_size = 30
responses = {}

# Traceroute con TTLs incrementales
for ttl in range(1, 25):

    ip_set = set()
    rtt_list = np.empty(burst_size, dtype=float)

    for i in range(0, burst_size): # Por cada ttl, hago 30 muestreos

        probe = IP(dst=sys.argv[1], ttl=ttl) / ICMP()
        t_i = time()
        ans = sr1(probe, verbose=False, timeout=0.8)
        t_f = time()
        rtt = (t_f - t_i) * 1000

        # Si recibo respuesta, calculo el RTT y lo agrego a la lista de RTTs. Lo mismo para la IP
        if ans is not None:

            rtt = (t_f - t_i) * 1000
            rtt_list[i] = rtt
            ip_set.add(ans.src)

            if ttl not in responses:
                responses[ttl] = []
            responses[ttl].append((ans.src, rtt))

    # Ya corrí 30 veces para el mismo ttl
    
    # RTT: {responses[ttl]}
    if ttl in responses:
        print(f"""TTL: {ttl}
            IP Mas Comun: {max(set(ip_set), key=list(ip_set).count)}
            IPs encontradas: {ip_set}
            RTT Promedio: {np.mean(rtt_list[rtt_list > 0])}
            """)

    if ans is not None and ans.src == sys.argv[1]:
        break