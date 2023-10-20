#!/usr/bin/env python3
import sys
from scapy.all import *
from time import *
import numpy as np
import folium
import requests

ip_dst = sys.argv[1]

responses = {}
burst_size = 30 # Cantidad de paquetes a enviar para calcular el RTT promedio

# Datos para armar el mapa
ip_addresses      = [] # List of IP addresses to trace
connection_labels = [] # List of labels for connections
hop_times         = []

last_mean_rtt = 0

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

    # Ya corrí 30 veces para el mismo ttl
    if ans is not None:
        
        most_common_ip = max(set(ip_set), key=list(ip_set).count)
        mean_rtt       = np.mean(rtt_list[rtt_list > 0])
        hop_time       = mean_rtt - last_mean_rtt
        
        print(f"""TTL: {ttl}
            IP Mas Comun:    {most_common_ip}
            IPs encontradas: {ip_set}
            RTT Promedio:    {mean_rtt}
            Tiempo de hop:   {hop_time}
            """)

        last_mean_rtt = mean_rtt

        # Actualizo los datos para el mapa
        ip_addresses.append(most_common_ip)
        connection_labels.append("RTT: " + str(mean_rtt))
        hop_times.append(hop_time)

    if ans is not None and ans.src == sys.argv[1]:
        break

# Hardcodeamos la dire de Rosen
ip_addresses[0] = "181.2.54.74"


### Creamos mapa ###

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

for ip_address in ip_addresses:

    # Get geolocation information for the IP address
    location_data = geolocate_ip(ip_address)

    # Extract the latitude and longitude from the response
    latitude, longitude = location_data.get("loc").split(",")
    latitude  = float(latitude)
    longitude = float(longitude)

    # Add a marker for the IP address
    folium.Marker(
        location=[latitude, longitude],
        popup=f"IP: {ip_address}\nLocation: Lat {latitude}, Lon {longitude}",
    ).add_to(fg)

    # Append coordinates to the list
    coordinates.append([latitude, longitude])

# Add the feature group to the map
m.add_child(fg)

# Create an arrowhead line connecting the traced IP addresses with text labels
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
        icon=folium.DivIcon(html=f'<div style="font-size: 12pt;">{connection_labels[i]}</div>'),
    ).add_to(m)

name_file = str(ip_dst) + ".html"

# Save the map to an HTML file
m.save(name_file)

# Open the map in a web browser
import webbrowser
webbrowser.open(name_file)
