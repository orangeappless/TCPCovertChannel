#!/usr/bin/env python3


from scapy.all import *


def create_packet(character):
    pkt = IP(dst="192.168.1.81", id=character)/TCP(flags="S", dport=8505)
    
    return pkt


def main():
    while True:
        data = input("Enter text: ")

        if data == ":q":
            print("Exiting program...")
            break
        
        data += ";"
        ascii_data = [ord(c) for c in data]

        for char in ascii_data:
            covert_pkt = create_packet(char)
            send(covert_pkt)

    sys.exit()


if __name__ == "__main__":
    main()
