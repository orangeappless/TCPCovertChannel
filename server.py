#!/usr/bin/env python3


from scapy.all import *
from cryptography.fernet import Fernet


def read_pkt(packet):
    packet_id = packet[IP].id
   
    with open("encrypted_covert.txt", "a") as file:
        if chr(packet_id) == ";":
            file.write("\n")
            decrypt_data()
        else:
            file.write((chr(packet_id)))


def decrypt_data():
    with open("keyfile.key", "rb") as keyfile:
        key = keyfile.read()
    
    fernet = Fernet(key)

    with open("encrypted_covert.txt", "rb") as file:
        lines = file.read().splitlines()
        last_line = lines[-1]

        last_line_decrypted = fernet.decrypt(last_line)

        print(last_line_decrypted.decode("utf-8"))


def main():
    print("Listening on covert channel...")

    sniff(filter="ip and tcp and host 192.168.1.79 and dst port 8505", prn=read_pkt)


if __name__ == "__main__":
    main()
