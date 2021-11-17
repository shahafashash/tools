#!/usr/bin/env python3
# Disclaimer: This script is provided for educational purposes only. Do not use this script for malicious or illegal purposes.

from utils import Utils
from argparse import ArgumentParser
from datetime import datetime
from scapy.all import arping
from time import sleep
from typing import Dict

class LanScanner:
    """Class for performing a LAN scan"""
    def __init__(self) -> None:
        pass

    def scan_network(self, ip_network: str, timeout: int=3) -> Dict[str, Dict[str, str]]:
        """Send ARP requests to a range of IP addresses and display the result

        Args:
            ip_network (str): The IP network to scan. 
            timeout (int): The timeout in seconds for each ARP request. Defaults to 3 seconds.
        
        Returns:
            Dict[str, Dict[str, str]]: A dictionary of IP addresses and their MAC addresses and vendor names.
        """
        # Check if running with root privileges
        if not Utils.is_root():
            Utils.perror('You must run this script with root privileges')
            Utils.perror('Try running \'sudo python3 lan_scanner.py <arguments>\'')
            Utils.perror('Exiting...')
            return
        
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
            # Scan the network for hosts using ARP and display the result
            answered, _ = arping(ip_network, timeout=3, verbose=False)
            
            # Display the results
            headers = ['IP Address', 'Vendor', 'MAC Address', 'Vendor Prefix']
            alignments = {'IP Address': 'l', 'Vendor': 'l', 'MAC Address': 'l', 'Vendor Prefix': 'l'}
            results = []
            num_of_rows = 0
            for answer in answered:
                # Get the IP address
                ip = answer[1].psrc
                # Get the MAC address
                mac = answer[1].hwsrc
                # Get the vendor name and prefix
                vendor = Utils.get_vendor_from_mac(mac)
                vendor_prefix = mac[:8]
                # Add the results to the list
                results.append([ip, vendor, mac, vendor_prefix])
                # Update the table
                num_of_rows += 1
                table = Utils.create_table(results, headers, alignments=alignments, borders=False)
                if num_of_rows != 1:
                    Utils.poutput(f'\33[{num_of_rows}A{table.get_string()}', prefix=False)
                else:
                    Utils.poutput(table.get_string(), prefix=False)
                # Sleep to prevent flooding the network
                sleep(timeout)

        except KeyboardInterrupt:
            Utils.perror('Got interrupted!')
            Utils.perror('Exiting...')
            return
        except Exception as ex:
            Utils.perror(f'Error: {ex}')
            Utils.perror('Exiting...')
            return

        end_time = datetime.now()
        Utils.poutput('', prefix=False)
        Utils.poutput(f'Scan ended at: {str(end_time)}')
        Utils.poutput(f'Scan duration: {str(end_time - start_time)}')
        return {ip: {'vendor': vendor, 'mac': mac, 'vendor_prefix': vendor_prefix} for ip, vendor, mac, vendor_prefix in results}


def main():
    # Parse the command line arguments
    parser = ArgumentParser(description='Scan a network for hosts using ARP')
    parser.add_argument('-i', '--ip-network', required=True, help='IP address or network to scan')
    # Add timeout argument
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Timeout in seconds')
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
    lan_scanner.scan_network(args.ip_network, args.timeout)


if __name__ == '__main__':
    main()