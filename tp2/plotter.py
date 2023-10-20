#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
import numpy as np
import folium
import requests
import json
import pandas as pd
from random import shuffle


# Cantidad de paquetes a enviar para calcular el RTT promedio
responses = {}
burst_size = 1
last_mean_rtt = 0

ip_dst = "138.80.162.69"

# List of IP addresses to trace
ip_addresses = []
# List of labels for connections
connection_labels = []
hop_times = []

# Traceroute con TTLs incrementales
for ttl in range(1, 25):

    ip_set   = set()
    rtt_list = np.empty(burst_size, dtype=float)

    for i in range(0, burst_size): # Por cada ttl, hago 30 muestreos

        probe = IP(dst=ip_dst, ttl=ttl) / ICMP()
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

    # Ya corrimos 30 veces para el mismo ttl



    if ttl in responses:
        
        most_common_ip = max(set(ip_set), key=list(ip_set).count)
        mean_rtt       = np.mean(rtt_list[rtt_list > 0])
        
        print(f"""TTL: {ttl}
            IP Mas Comun:    {most_common_ip}
            IPs encontradas: {ip_set}
            RTT Promedio:    {mean_rtt}
            Tiempo de hop:   {mean_rtt - last_mean_rtt}
            """)
        
        hop_times.append(round(mean_rtt - last_mean_rtt, 2))
        last_mean_rtt = mean_rtt
        ip_addresses.append(most_common_ip)
        connection_labels.append("RTT: " + str(mean_rtt))

    if ans is not None and ans.src == ip_dst:
        break


# Hardcodeamos la dire de Rosen
ip_addresses[0] = "186.139.87.16"

# El primer hop_time es 0
hop_times.pop(0)

####################################################################################
import seaborn as sns
import matplotlib.pyplot as plt

ips = list(ip_addresses)
ips.pop(0)
rtts = hop_times

# Create a bar chart using Seaborn
sns.set(style="whitegrid")  # Optional, for setting the style

# Create a barplot with Seaborn
plt.figure(figsize=(10, 6))  

ax = sns.barplot(x=ips, y=rtts, palette="RdPu") #ESTE O TAB10???

# Add labels and title
ax.set(xlabel='IP Address', ylabel='RTT (ms)')
ax.set_title('RTT for Each IP Address')

# Rotate x-axis labels for better readability (optional)
plt.xticks(rotation=45, ha="right")

# Set the lower limit of the y-axis to 0
ax.set_ylim(bottom=0)

# Display the chart
plt.show()

####################################################################################