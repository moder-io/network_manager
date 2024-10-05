import scapy.all as scapy
import nmap
import subprocess

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

def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')
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