#!/usr/bin/env python3


from scapy.all import *
from cryptography.fernet import Fernet
import argparse


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-s",
                        "--server",
                        type=str,
                        help="IP of remote covert channel server",
                        required=True)

    args = parser.parse_args()

    return args


def create_packet(dst_ip, character):
    pkt = IP(dst=dst_ip, id=character)/TCP(flags="S", dport=8505)
    
    return pkt


def encrypt_data(data):
    with open("keyfile.key", "rb") as keyfile:
        key = keyfile.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    return encrypted_data


def main():
    parse_args()
    args = parse_args()

    while True:
        data = input("Enter text: ")

        if data == ":q":
            print("Exiting program...")
            break
        
        data = encrypt_data(data.encode("utf-8"))
        data += b";"
        decoded_data = data.decode("utf-8")

        ascii_data = [ord(c) for c in decoded_data]

        for char in ascii_data:
            covert_pkt = create_packet(args.server, char)
            send(covert_pkt, verbose=False)

    sys.exit()


if __name__ == "__main__":
    main()
