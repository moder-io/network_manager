from network_scanner import scan, scan_ports, ping, traceroute

def main():
    print("Iniciando escaneo de red...")
    ip_range = "192.168.1.1/24"  # Cambia según tu red
    devices = scan(ip_range)
    
    print("Dispositivos conectados:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    ip_to_examine = input("Introduce la dirección IP que deseas examinar a fondo: ")

    if any(device['ip'] == ip_to_examine for device in devices):
        print(f"Examinando la IP {ip_to_examine}...")
        
        # Realiza un ping
        if ping(ip_to_examine):
            print(f"{ip_to_examine} responde a ping.")
        else:
            print(f"{ip_to_examine} no responde a ping.")
        
        # Escanea puertos
        open_ports = scan_ports(ip_to_examine)
        if open_ports:
            print(f"Puertos abiertos en {ip_to_examine}: {open_ports}")
        else:
            print(f"No se encontraron puertos abiertos en {ip_to_examine}.")
        
        # Realiza traceroute
        print(f"Traceroute a {ip_to_examine}:")
        for hop in traceroute(ip_to_examine):
            print(hop)

    else:
        print(f"La IP {ip_to_examine} no se encontró en la lista de dispositivos conectados.")

    input("Presiona Enter para salir...")
    

if __name__ == "__main__":
    main()
