#!/usr/bin/env python3


from scapy.all import *


def read_pkt(packet):
    packet_id = packet[IP].id
   
    if chr(packet_id) == ";":
        print("\n")
    else:
        print(chr(packet_id), end="", flush=True)


def main():
    print("Listening on covert channel...")

    sniff(filter="ip and tcp and host 192.168.1.79 and dst port 8505", prn=read_pkt)


if __name__ == "__main__":
    main()
