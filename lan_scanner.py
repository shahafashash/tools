#!/usr/bin/env python3
# Disclaimer: This script is for educational purposes only. Do not use it against any network that you dont have authorization to test.

from utils import Utils
from argparse import ArgumentParser
from datetime import datetime
from scapy.all import arping

class LanScanner:
    """Class that represents a lan scanner"""
    def __init__(self) -> None:
        self.__utils = Utils()

    def scan_network(self, ip_network: str) -> None:
        """Sending ARP messages to discover devices on the network.

        Args:
            ip_network (str): Network to scan.
        """
        ip = self.__utils.check_ip_address_or_network(ip_network)
        if ip is None:
            self.__utils.perror(f'Got invalid IP network or invalid IP network format')
            self.__utils.perror('Exiting...')
            exit()

        scan_start = datetime.now()

        self.__utils.poutput(f'canning target: {ip}')
        self.__utils.poutput(f'Scan started at: {str(scan_start)}\n')

        try:
            result = arping(ip)
       
        except KeyboardInterrupt:
            self.__utils.perror('Got interrupted!')
            self.__utils.perror('Exiting...')
            exit()

        except Exception as ex:
            self.__utils.perror(f'Error: {ex}')
            self.__utils.perror('Exiting...')
            exit()

        scan_end = datetime.now()
        self.__utils.poutput('', prefix=False)
        self.__utils.poutput(f'Scan ended at: {str(scan_end)}')
        self.__utils.poutput(f'Total scanning time: {str(scan_end-scan_start)}')


def main():
    utils = Utils()
    scanner = LanScanner()
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip-network', required=True, type=utils.check_ip_address_or_network, 
                    help='Address representing the IP network (ex: 10.0.2.0/24)')
    args = parser.parse_args()
    
    utils.print_banner('lan-scanner')
    target = args.ip_network
    if target is None:
        utils.perror(f'Got invalid IP network or invalid IP networkformat')
        utils.perror('Exiting...')
        exit()
    
    scanner.scan_network(target)

if __name__ == '__main__':
    main()