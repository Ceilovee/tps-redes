import folium
import requests

# Create a map centered at a specific location
m = folium.Map(location=[0, 0], zoom_start=2)  # Adjust the coordinates and zoom level as needed

# List of IP addresses to trace
ip_addresses = [
    "186.139.87.16",
    "181.88.78.157",
    "195.22.220.56",
    "89.221.35.145",
    "198.32.176.177",
    "202.158.194.176",
    "113.197.15.142",
    "113.197.15.3",
    "113.197.15.9",
    "113.197.15.29",
    "113.197.15.161",
    "113.197.14.148",
    "138.44.208.34",
    "138.80.0.250",
    "138.80.5.105",
    "138.80.162.69",
    # Add more IP addresses
]

# List of labels for connections
connection_labels = [
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    "RTT: 100",
    # Add more labels for connections
]

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

# Save the map to an HTML file
m.save("ip_trace_map.html")

# Open the map in a web browser
import webbrowser
webbrowser.open("ip_trace_map.html")
