#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
import numpy as np
import pandas as pd
from collections import Counter

# Cantidad de paquetes a enviar para calcular el RTT promedio
responses = {}
burst_size = 1
last_mean_rtt = 0

ip_dst = "138.80.162.69"

# Datos para mapear
most_common_ip_addresses = []
most_common_ip_percentages = []
connection_labels = []
hop_times = []

# Traceroute con TTLs incrementales
for ttl in range(1, 25):

    ip_path_list = list()
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
            ip_path_list.append(ans.src)

            if ttl not in responses:
                responses[ttl] = []
            responses[ttl].append((ans.src, rtt))

    # Ya corrimos 30 veces para el mismo ttl
    if ttl in responses:
        
        # Cuento la IP mas comun y cuantas veces aparecio
        most_common_ip, most_common_ip_count = Counter(ip_path_list).most_common(1)[0]
        most_common_ip_percentages.append(most_common_ip_count / len(ip_path_list))
        mean_rtt       = np.mean(rtt_list[rtt_list > 0])
        
        print(f"""TTL: {ttl}
            IP Mas Comun:    {most_common_ip}
            IPs encontradas: {set(ip_path_list)}
            RTT Promedio:    {mean_rtt}
            Tiempo de hop:   {mean_rtt - last_mean_rtt}
            """)
        
        hop_times.append(round(mean_rtt - last_mean_rtt, 2))
        last_mean_rtt = mean_rtt
        most_common_ip_addresses.append(most_common_ip)
        
    if ans is not None and ans.src == ip_dst:
        break


# Hardcodeamos la dire de Rosen
most_common_ip_addresses[0] = "186.139.87.16"

# El primer hop_time es 0
hop_times.pop(0)

############################################MAPPER#############################################

import folium
import requests
import json
import pycountry
import webbrowser

# Create a map centered at a specific location
m = folium.Map(location=[0, 0], zoom_start=2)  # Adjust the coordinates and zoom level as needed

# Create a feature group for the traced IP addresses
fg = folium.FeatureGroup(name="Traced IP Addresses")

# Function to geolocate an IP address using ipinfo.io
def geolocate_ip(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    response = requests.get(url)
    data = response.json()
    return data

# List to store coordinates of traced IP addresses
coordinates = []

# Dictionary to track countries with markers
countries_with_markers = {}

for ip_address in most_common_ip_addresses:
    # Get geolocation information for the IP address
    location_data = geolocate_ip(ip_address)

    # Extract the latitude and longitude from the response
    latitude, longitude = location_data.get("loc").split(",")
    latitude = float(latitude)
    longitude = float(longitude)

    # Reverse geocode to get the country
    country = location_data.get("country")

    # Add the country to the dictionary with blue color
    countries_with_markers[country] = 'Blue'

    # Add a marker for the IP address
    folium.Marker(
        location=[latitude, longitude],
        popup=f"IP: {ip_address}\nLocation: Lat {latitude}, Lon {longitude}",
    ).add_to(fg)

    # Append coordinates to the list
    coordinates.append([latitude, longitude])

# Cambio protocolo de nombre de pais (2 letras a 3 letras)
countries_with_markers = {pycountry.countries.get(alpha_2=key).alpha_3: value for key, value in countries_with_markers.items()}

# Add the feature group to the map
m.add_child(fg)

# Create a line connecting the traced IP addresses with text labels
for i in range(len(coordinates) - 1):
    start_coord = coordinates[i]
    end_coord = coordinates[i + 1]
    line = folium.PolyLine(
        locations=[start_coord, end_coord],
        color="red",
        line_cap="arrow",
        weight=2
    )
    line.add_to(m)

    # Calculate the position for the text label
    label_position = [(start_coord[0] + end_coord[0]) / 2, (start_coord[1] + end_coord[1]) / 2]

    # Create a marker with a text label
    folium.Marker(
        location=label_position,
        icon=folium.DivIcon(html=f'<div style="font-size: 12pt;">RTT: {int(hop_times[i])}</div>'),
    ).add_to(m)

# Fetch the GeoJSON data from the URL
url = "https://raw.githubusercontent.com/python-visualization/folium/master/examples/data/world-countries.json"
response = requests.get(url)
geo_json_data = response.json()

# Create a Choropleth layer to color the countries
folium.Choropleth(
    geo_data=geo_json_data,
    name='choropleth',
    data=None,  # We won't use this data for coloring
    columns=None,
    key_on='feature.id',
    fill_color='gray',  # Default color for all countries
    fill_opacity=0.1,
    line_opacity=0.2,
).add_to(m)

# Add a GeoJSON overlay for the specified countries with custom colors
for feature in geo_json_data['features']:
    country_id = feature['id']
    if country_id in countries_with_markers:
        color = countries_with_markers[country_id]
        folium.GeoJson(feature, style_function=lambda x, color=color: {'fillColor': color}).add_to(m)

# Save the map to an HTML file
name_file = str(ip_dst) + ".html"
m.save(name_file)

# Open the map in a web browser
webbrowser.open(name_file)


############################################PLOTTER#############################################
import seaborn as sns
import matplotlib.pyplot as plt

# Borro la primer entrada de las IPs (siempre es la mia o la de mi router)
ips = list(most_common_ip_addresses)
ips.pop(0)
most_common_ip_percentages.pop(0)

### PLOT RTTs
rtts = list(hop_times)
sns.set(style="whitegrid")
plt.figure(figsize=(10, 6))
ax1 = sns.barplot(x=ips, y=rtts, palette="RdPu")
ax1.set(xlabel='Direcciones IP Recorridas', ylabel='RTT (ms)')
ax1.set_title('RTT Promedio - Plot 1')
plt.xticks(rotation=45, ha="right")
ax1.set_ylim(bottom=0)
plt.show()

### PLOT STABILITY
plt.figure(figsize=(10, 6))
ax2 = sns.barplot(x=ips, y=most_common_ip_percentages, palette="RdPu")  # You can change the palette
ax2.set(xlabel='Direcciones IP Recorridas', ylabel='RTT (ms)')
ax2.set_title('RTT Promedio - Plot 2')
plt.xticks(rotation=45, ha="right")
ax2.set_ylim(bottom=0)
plt.show()
