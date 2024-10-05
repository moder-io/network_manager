import scapy.all as scapy
import nmap
import subprocess
import socket
from scapy.layers.inet import IP, ICMP, TCP, UDP
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor

def scan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device_info)
    
    return devices

def scan_ports(ip, port_range='1-1024'):
    nm = nmap.PortScanner()
    nm.scan(ip, port_range)
    open_ports = []
    
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            if nm[ip][proto][port]['state'] == 'open':
                open_ports.append(port)
    
    return open_ports

def ping(ip):
    try:
        output = subprocess.check_output(['ping', '-c', '1', ip], stderr=subprocess.STDOUT, universal_newlines=True)
        return "1 received" in output
    except subprocess.CalledProcessError:
        return False
    
def traceroute(ip):
    output = subprocess.check_output(['tracert', ip], stderr=subprocess.STDOUT, universal_newlines=True)
    return output.splitlines()

def os_fingerprint(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-O")
    if 'osmatch' in nm[ip]:
        return nm[ip]['osmatch'][0]['name']
    else:
        return "OS no detectado"

def syn_scan(ip, port):
    src_port = scapy.RandShort()
    resp = scapy.sr1(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=False)
    if resp is None:
        return "Filtrado"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            return "Abierto"
        elif resp.getlayer(TCP).flags == 0x14:
            return "Cerrado"
    return "Desconocido"

def banner_grab(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return "No se pudo obtener el banner"

def vulnerability_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="--script vuln")
    vulnerabilities = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if 'script' in nm[host][proto][port]:
                    vulnerabilities.extend(nm[host][proto][port]['script'])
    return vulnerabilities

def udp_scan(ip, port):
    resp = scapy.sr1(IP(dst=ip)/UDP(dport=port), timeout=2, verbose=False)
    if resp is None:
        return "Abierto|Filtrado"
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3:
            return "Cerrado"
        else:
            return "Filtrado"
    else:
        return "Abierto"

def dns_enumeration(domain):
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    results = {}
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results[record] = [str(rdata) for rdata in answers]
        except:
            results[record] = []
    return results

def subdomain_scan(domain, wordlist):
    found_subdomains = []
    for subdomain in wordlist:
        url = f"http://{subdomain}.{domain}"
        try:
            requests.get(url)
            found_subdomains.append(url)
        except requests.ConnectionError:
            pass
    return found_subdomains

def service_version_scan(ip, port):
    nm = nmap.PortScanner()
    nm.scan(ip, str(port), arguments="-sV")
    if ip in nm.all_hosts() and 'tcp' in nm[ip] and port in nm[ip]['tcp']:
        return nm[ip]['tcp'][port]['product'] + " " + nm[ip]['tcp'][port]['version']
    return "Versión desconocida"

def parallel_port_scan(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: (p, syn_scan(ip, p)), ports)
        for port, status in results:
            if status == "Abierto":
                open_ports.append(port)
    return open_ports

def network_mapping(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments="-sn")
    devices = []
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            devices.append({
                'ip': host,
                'mac': nm[host]['addresses']['mac'],
                'vendor': nm[host]['vendor'].get(nm[host]['addresses']['mac'], "Unknown")
            })
        else:
            devices.append({
                'ip': host,
                'mac': "Unknown",
                'vendor': "Unknown"
            })
    return devices