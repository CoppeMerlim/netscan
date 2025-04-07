#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import socket
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.devices = {}
        
    def get_network_range(self, ip):
        """Retorna o range de IPs da rede local."""
        ip_parts = ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1/24"
    
    def get_local_ip(self):
        """Obtém o IP local da máquina."""
        try:
            # Cria um socket para obter o IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return None

    def scan_network(self, ip_range):
        """Realiza o scan da rede usando ARP."""
        print(f"[*] Iniciando scan da rede {ip_range}")
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        print("\nDispositivos encontrados:")
        print("IP\t\t\tMAC Address\t\t\tTimestamp")
        print("-" * 75)
        
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            self.devices[ip] = {
                'mac': mac,
                'timestamp': timestamp
            }
            
            print(f"{ip}\t\t{mac}\t\t{timestamp}")

    def run(self):
        """Método principal para executar o scanner."""
        parser = argparse.ArgumentParser(description='Scanner de Rede usando ARP')
        parser.add_argument('-t', '--target', help='IP alvo ou range de IPs (ex: 192.168.1.1/24)')
        args = parser.parse_args()

        if args.target:
            target = args.target
        else:
            local_ip = self.get_local_ip()
            if not local_ip:
                print("[-] Não foi possível determinar o IP local")
                return
            target = self.get_network_range(local_ip)

        try:
            self.scan_network(target)
        except KeyboardInterrupt:
            print("\n[!] Scan interrompido pelo usuário")
        except Exception as e:
            print(f"[-] Erro durante o scan: {str(e)}")

if __name__ == "__main__":
    scanner = NetworkScanner()
    scanner.run() 