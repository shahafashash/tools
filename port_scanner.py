#!/usr/bin/env python3
# Disclaimer: This script is for educational purposes only. Do not use it against any network that you dont have authorization to test.

import nmap
from argparse import ArgumentParser
import socket
from datetime import datetime
from utils import Utils


class PortScanner:
    """Class that represents ports scanner"""
    def __init__(self) -> None:
        self.__utils = Utils()

    def scan(self, min_port: int, max_port: int, ip_addr: str=None, host: str=None) -> None:
        """Scans the targets' ports in the given range and prints a table with the results.
        Ports should be in the following range: 1-65535

        Args:
            min_port (int): Port number to start the scan with.
            max_port (int): Port number to end the scan with.
            ip_addr (str, optional): IP address of the target. Defaults to None.
            host (str, optional): Name of the target host. Defaults to None.
        """
        if ip_addr is not None:
            target = ip_addr
        elif host is not None:
            target = socket.gethostbyname(host)
        else:
            target = None

        if target is None:
            invalid_target = ip_addr if ip_addr is not None else host
            self.__utils.perror(f'Got invalid hostname or IP address: {invalid_target}')
            self.__utils.perror('Exiting...')
            exit()

        port_range_str = f'{min_port}-{max_port}'
        port_range = self.__utils.check_port_range(port_range_str)
        if port_range is None:
            self.__utils.perror(f'Error: Got invalid ports range: {min_port}-{max_port}')
            self.__utils.perror('Exiting...')
            exit()

        scan_start = datetime.now()
        self.__utils.poutput(f'Scanning target: {target}')
        self.__utils.poutput(f'Scanning ports range: {min_port}-{max_port}')
        self.__utils.poutput(f'Scan started at: {str(scan_start)}')
        
        scanner = nmap.PortScanner()
        headers = ['Port', 'Service', 'Status']
        alignments = {'Port': 'l', 'Service': 'c', 'Status': 'c'}
        results = []
        table = self.__utils.create_table(results, headers, alignments=alignments, borders=False)
        self.__utils.poutput('', prefix=False)
        num_of_rows = 0
        for port in range(min_port, max_port + 1):
            try:
                result = scanner.scan(target, str(port), arguments='-sS')
                status = result['scan'][target]['tcp'][port]['state']
                status = f'\033[0;31;40m{status}\033[0m' if status == 'closed' else f'\033[0;32;40m{status}\033[0m'
                service = socket.getservbyport(port)
                
                result = [port, service, status]
                results.append(result)    
                num_of_rows += 1

                table = self.__utils.create_table(results, headers, alignments=alignments, borders=False)
                if num_of_rows != 1:
                    self.__utils.poutput(f'\33[{num_of_rows}A{table.get_string()}', prefix=False)
                else:
                    self.__utils.poutput(table.get_string(), prefix=False)

            except KeyboardInterrupt:
                self.__utils.poutput('Got interrupted!')
                self.__utils.poutput('Exiting...')
                exit()
            except Exception:
                pass
           

        scan_end = datetime.now()
        self.__utils.poutput('', prefix=False)
        self.__utils.poutput(f'Scan ended at: {str(scan_end)}')
        self.__utils.poutput(f'Total scanning time: {str(scan_end-scan_start)}')



def main():
    utils = Utils()
    scanner = PortScanner()
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip-address', type=utils.check_ip_address_structure, 
                        help='IPv4 address to scan for open ports')
    group.add_argument('-H', '--host', type=str, 
                        help='Hostname to get its IP address and scan its ports')
    parser.add_argument('-r', '--range', required=False, default='1-65535', type=utils.check_port_range,
                        help='Range of ports to scan for. \
                            The range should be in the following format: <int>-<int>, \
                            Minimum port number: 1, \
                            Maximum port number: 65535')

    args = parser.parse_args()


    utils.print_banner('port-scanner')
    if args.range is None:
        utils.perror('Got invalid ports range')
        utils.perror('Exiting...')
        exit()

    min_port, max_port = args.range

    if args.ip_address is not None:
        target = args.ip_address
    elif args.host is not None:
        target = socket.gethostbyname(args.host)
    else:
        target = None

    if target is None:
        invalid_target = args.ip_address if args.ip_address is not None else args.host
        utils.perror(f'Got invalid hostname or ip address: {invalid_target}')
        utils.perror('Exiting...')
        exit()

    scanner.scan(min_port, max_port, ip_addr=target)

if __name__ == '__main__':
    main()
