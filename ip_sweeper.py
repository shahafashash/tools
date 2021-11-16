#!/usr/bin/env python3
# Disclaimer: This script is provided for educational purposes only. Do not use this script for malicious or illegal purposes.

from utils import Utils
from nmap import PortScanner
from argparse import ArgumentParser
from datetime import datetime
from typing import Dict

class IpSweeper:
    """Class for performing a port scan on the specified IP network."""
    def __init__(self) -> None:
        pass

    def sweep(self, ip_network: str) -> Dict[str, str]:
        """Performs a port scan on the specified IP network and prints the results in a table.

        Args:
            ip_network (str): The IP network to scan. Can be a single IP or a range of IPs (e.g. 1.1.1.1 or 1.1.1.0/24).
        
        Returns:
            Dict[str, str]: A dictionary containing the IP address and the its state (up or down).
        """
        # Validate the IP network
        is_valid_ip = Utils.is_valid_network_or_ip(ip_network)
        if not is_valid_ip:
            Utils.perror('Invalid IP address or network specified.')
            Utils.perror('Exiting...')
            return {}

        start_time = datetime.now()
        Utils.poutput(f'Scanning target: {ip_network}')
        Utils.poutput(f'Scan started at: {str(start_time)}\n')

        headers = ['IP Address', 'State']
        alignments = {'IP Address': 'l', 'State': 'c'}
        try:
            # Create a PortScanner object
            scanner = PortScanner()
            # Scan the network
            scanner.scan(ip_network, arguments='-n -sP -PE -PA21,23,80,3389')
            # Get the scan results
            results = [[host, scanner[host].state()] for host in scanner.all_hosts()]
            for i, result in enumerate(results):
                host, state = result
                state = Utils.color_text(state, 'green') if state == 'up' else Utils.color_text(state, 'red')
                results[i] = [host, state]
            
            # Sort the results by IP address
            results = sorted(results, key=lambda x: int(x[0].split('.')[-1]))
            # Create a table
            table = Utils.create_table(results, headers, alignments=alignments, borders=False)
            # Print the table
            Utils.poutput(table.get_string(), prefix=False)
        except KeyboardInterrupt:
            Utils.perror('Got interrupted!')
            Utils.perror('Exiting...')
            return {}
        except Exception as ex:
            Utils.perror(f'Error: {ex}')
            Utils.perror('Exiting...')
            return {}
        
        end_time = datetime.now()
        Utils.poutput('', prefix=False)
        Utils.poutput(f'Scan ended at: {str(end_time)}')
        Utils.poutput(f'Scan duration: {str(end_time - start_time)}')
        return {host: 'up' if 'up' in state else 'down' for host, state in results}


def main() -> None:
    """Main function."""
    # Create an argument parser
    parser = ArgumentParser(description='Performs a port scan on the specified IP network and prints the results in a table.')
    parser.add_argument('-i', '--ip-network', required=True, help='The IP network to scan. Can be a single IP or a range of IPs (e.g. 127.0.1.0 or 127.0.1.0/24).')
    args = parser.parse_args()

    # Print the banner
    Utils.print_banner('ip-sweeper')
    # Check if the ip_network argument is valid and print an error if it is not and exit
    if not Utils.is_valid_network_or_ip(args.ip_network):
        Utils.perror('Invalid IP address or network specified.')
        Utils.perror('Exiting...')
        exit(1)

    # Create an IpSweeper object
    ip_sweeper = IpSweeper()
    # Perform a port scan on the specified IP network
    ip_sweeper.sweep(args.ip_network)


if __name__ == '__main__':
    main()