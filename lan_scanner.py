#!/usr/bin/env python3
# Disclaimer: This script is provided for educational purposes only. Do not use this script for malicious or illegal purposes.

from utils import Utils
from argparse import ArgumentParser
from datetime import datetime
from scapy.all import arping

class LanScanner:
    """Class for performing a LAN scan"""
    def __init__(self) -> None:
        pass

    def scan_network(self, ip_network: str) -> None:
        """Send ARP requests to a range of IP addresses and display the result

        Args:
            ip_network (str): The IP network to scan. 
        """
        # Validate the IP address
        is_valid_ip = Utils.is_valid_network_or_ip(ip_network)
        if not is_valid_ip:
            Utils.perror('Invalid IP address or network specified.')
            Utils.perror('Exiting...')
            return

        start_time = datetime.now()
        Utils.poutput(f'Scanning target: {ip_network}')
        Utils.poutput(f'Scan started at: {str(start_time)}\n')

        try:
            # Scan the network for hosts using ARP
            arping(ip_network)

        except KeyboardInterrupt:
            Utils.perror('Got interrupted!')
            Utils.perror('Exiting...')
            return
        except Exception as ex:
            Utils.perror(f'Error: {ex}')
            Utils.perror('Exiting...')
            return

        end_time = datetime.now()
        Utils.poutput(f'Scan ended at: {str(end_time)}\n')
        Utils.poutput(f'Scan duration: {str(end_time - start_time)}')


def main():
    # Parse the command line arguments
    parser = ArgumentParser(description='Scan a network for hosts using ARP')
    parser.add_argument('-i', '--ip-network', required=True, help='IP address or network to scan', required=True)
    args = parser.parse_args()

    # Print the banner
    Utils.print_banner('ip-sweeper')
    # Check if the ip_network argument is valid and print an error if it is not and exit
    if not Utils.is_valid_network_or_ip(args.ip_network):
        Utils.perror('Invalid IP address or network specified.')
        Utils.perror('Exiting...')
        exit(1)

    # Create an instance of the class
    lan_scanner = LanScanner()

    # Scan the network for hosts using ARP
    lan_scanner.scan_network(args.ip)