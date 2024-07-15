import os
os.system('figlet Sniffer Tool')
print("------------------------------------------------------------")
import time
time.sleep(2)
import argparse
import socket
import struct 
from ctypes import *
class IPHeader(Structure):
    _fields_ = [
        ("ihl",              c_ubyte, 4),
        ("version",          c_ubyte, 4),
        ("tos",              c_ubyte),
        ("len",              c_ushort),
        ("id",               c_ushort),
        ("offset",           c_ushort),
        ("ttl",              c_ubyte),
        ("protocol_num",     c_ubyte),
        ("sum",              c_ushort),
        ("src",              c_uint32),
        ("dst",              c_uint32)
    ]

    def __new__(cls, data=None):
        return cls.from_buffer_copy(data)

    def __init__(self, data=None):
        self.source_ip = socket.inet_ntoa(struct.pack("@I", self.src))
        self.destination_ip = socket.inet_ntoa(struct.pack("@I", self.dst))
        self.protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol = self.protocols.get(self.protocol_num, str(self.protocol_num))

def conn(proto):
    if proto == "TCP":
        print("Sniffer started sniffing TCP packets:")
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        tcp_sock.bind(("0.0.0.0", 0))
        sniffer(tcp_sock, "TCP")
    elif proto == "UDP":
        print("Sniffer started sniffing UDP packets:")
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        udp_sock.bind(("0.0.0.0", 0))
        sniffer(udp_sock, "UDP")
    elif proto == "ICMP":
        print("Sniffer started sniffing ICMP packets:")
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_sock.bind(("0.0.0.0", 0))
        sniffer(icmp_sock, "ICMP")

def sniffer(sock, proto):
    try:
        while True:
            raw_pack = sock.recvfrom(65535)[0]
            ip_header = IPHeader(raw_pack[0:20])
            if ip_header.protocol == proto:
                print(f"Protocol: {ip_header.protocol} Source: {ip_header.source_ip} Destination: {ip_header.destination_ip}")
    except KeyboardInterrupt:
        print(f"Exiting {proto} sniffer....")
        return

def main():

    protocols = ["TCP", "UDP", "ICMP"]
    
    print("Available protocols:")
    for i, proto in enumerate(protocols, 1):
        print(f"{i}. {proto}")
    
    choice = int(input("Select a protocol to sniff (1, 2, or 3): "))
    
    if choice in range(1, len(protocols) + 1):
        selected_proto = protocols[choice - 1]
        conn(selected_proto)
    else:
        print("Invalid choice. Please run the program again and select a valid protocol.")

if __name__ == "__main__":
    main()
