from network_scanner import *
from utils import *

def main():
    print("Iniciando escaneo de red avanzado...")
    ip_range = input("Introduce el rango de IP a escanear (por ejemplo, 192.168.1.1/24): ")

    print("Mapeando la red...")
    devices = network_mapping(ip_range)
    
    print("Dispositivos conectados:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Fabricante: {device['vendor']}")
    
    export_to_json(devices, filename="dispositivos_escaneados.json")

    while True:
        ip_to_examine = input("\nIntroduce la dirección IP que deseas examinar a fondo (o 'q' para salir): ")
        if ip_to_examine.lower() == 'q':
            break

        if any(device['ip'] == ip_to_examine for device in devices):
            print(f"\nExaminando la IP {ip_to_examine}...")
            
            if ping(ip_to_examine):
                print(f"{ip_to_examine} responde a ping.")
            else:
                print(f"{ip_to_examine} no responde a ping.")
            
            print("\nEscaneando puertos...")
            open_ports = parallel_port_scan(ip_to_examine, range(1, 1025))
            if open_ports:
                print(f"Puertos abiertos en {ip_to_examine}: {open_ports}")
                for port in open_ports:
                    service = service_version_scan(ip_to_examine, port)
                    print(f"  Puerto {port}: {service}")
                    banner = banner_grab(ip_to_examine, port)
                    print(f"    Banner: {banner}")
                
                port_scan_results = {
                    'ip': ip_to_examine,
                    'open_ports': open_ports
                }
                export_to_json(port_scan_results, filename=f"puertos_abiertos_{ip_to_examine}.json")
            else:
                print(f"No se encontraron puertos abiertos en {ip_to_examine}.")
            
            print("\nRealizando UDP scan en puertos comunes...")
            common_udp_ports = [53, 67, 68, 69, 123, 161, 500]
            for port in common_udp_ports:
                result = udp_scan(ip_to_examine, port)
                print(f"  Puerto UDP {port}: {result}")
            
            print(f"\nTraceroute a {ip_to_examine}:")
            traceroute_result = traceroute(ip_to_examine)
            for hop in traceroute_result:
                print(hop)

            traceroute_data = {
                'ip': ip_to_examine,
                'traceroute': traceroute_result
            }
            export_to_json(traceroute_data, filename=f"traceroute_{ip_to_examine}.json")

            os = os_fingerprint(ip_to_examine)
            print(f"\nSistema operativo detectado: {os}")

            os_data = {
                'ip': ip_to_examine,
                'os': os
            }
            export_to_json(os_data, filename=f"os_detected_{ip_to_examine}.json")
            
            print("\nRealizando escaneo de vulnerabilidades...")
            vulnerabilities = vulnerability_scan(ip_to_examine)
            if vulnerabilities:
                print("Vulnerabilidades detectadas:")
                for vuln in vulnerabilities:
                    print(vuln)

                vulnerability_data = {
                    'ip': ip_to_examine,
                    'vulnerabilities': vulnerabilities
                }
                export_to_json(vulnerability_data, filename=f"vulnerabilidades_{ip_to_examine}.json")
            else:
                print("No se detectaron vulnerabilidades.")
            
            domain = input("\nIntroduce el nombre de dominio asociado (si lo hay) para enumerar DNS: ")
            if domain:
                print("\nEnumeración DNS:")
                dns_records = dns_enumeration(domain)
                for record_type, records in dns_records.items():
                    print(f"  {record_type}: {', '.join(records)}")

                dns_data = {
                    'domain': domain,
                    'dns_records': dns_records
                }
                export_to_json(dns_data, filename=f"dns_records_{domain}.json")
                
                print("\nEscaneando subdominios comunes...")
                common_subdomains = [...]
                found_subdomains = subdomain_scan(domain, common_subdomains)
                if found_subdomains:
                    print("Subdominios encontrados:")
                    for subdomain in found_subdomains:
                        print(f"  {subdomain}")

                    subdomain_data = {
                        'domain': domain,
                        'subdomains': found_subdomains
                    }
                    export_to_json(subdomain_data, filename=f"subdomains_{domain}.json")
                else:
                    print("No se encontraron subdominios comunes.")

        else:
            print(f"La IP {ip_to_examine} no se encontró en la lista de dispositivos conectados.")
    
    initiate_report = input("\n¿Deseas generar un reporte ('y' para aceptar)? ")
    if initiate_report.lower() == 'y':
        report_filename = "network_scan_report.txt"
        generate_report(devices, report_filename)
        print(f"Reporte generado en {report_filename}")
        formatted_results = format_scan_results(devices)
        print(formatted_results)

    print("\n¡Escaneo completo!")
    input("Pulsa enter para cerrar")

if __name__ == "__main__":
    main()
