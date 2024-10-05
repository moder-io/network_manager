from network_scanner import *

def main():
    print("Iniciando escaneo de red avanzado...")
    ip_range = input("Introduce el rango de IP a escanear (por ejemplo, 192.168.1.1/24): ")
    
    print("Mapeando la red...")
    devices = network_mapping(ip_range)
    
    print("Dispositivos conectados:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Fabricante: {device['vendor']}")

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
            else:
                print(f"No se encontraron puertos abiertos en {ip_to_examine}.")
            
            print("\nRealizando UDP scan en puertos comunes...")
            common_udp_ports = [53, 67, 68, 69, 123, 161, 500]
            for port in common_udp_ports:
                result = udp_scan(ip_to_examine, port)
                print(f"  Puerto UDP {port}: {result}")
            
            print(f"\nTraceroute a {ip_to_examine}:")
            for hop in traceroute(ip_to_examine):
                print(hop)
            
            os = os_fingerprint(ip_to_examine)
            print(f"\nSistema operativo detectado: {os}")
            
            print("\nRealizando escaneo de vulnerabilidades...")
            vulnerabilities = vulnerability_scan(ip_to_examine)
            if vulnerabilities:
                print("Vulnerabilidades detectadas:")
                for vuln in vulnerabilities:
                    print(vuln)
            else:
                print("No se detectaron vulnerabilidades.")
            
            domain = input("\nIntroduce el nombre de dominio asociado (si lo hay) para enumerar DNS: ")
            if domain:
                print("\nEnumeración DNS:")
                dns_records = dns_enumeration(domain)
                for record_type, records in dns_records.items():
                    print(f"  {record_type}: {', '.join(records)}")
                
                print("\nEscaneando subdominios comunes...")
                common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4']
                found_subdomains = subdomain_scan(domain, common_subdomains)
                if found_subdomains:
                    print("Subdominios encontrados:")
                    for subdomain in found_subdomains:
                        print(f"  {subdomain}")
                else:
                    print("No se encontraron subdominios comunes.")

        else:
            print(f"La IP {ip_to_examine} no se encontró en la lista de dispositivos conectados.")

    print("\n¡Escaneo completo!")

if __name__ == "__main__":
    main()