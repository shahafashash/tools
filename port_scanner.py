#!/usr/bin/env python3
# Disclaimer: This script is for educational purposes only. Do not use it against any network that you dont have authorization to test.

from argparse import ArgumentParser
import socket
from datetime import datetime
from utils import Utils
from nmap import PortScanner as NmapScanner
from ip_sweeper import IpSweeper


class PortScanner:
    def __init__(self) -> None:
        pass

    def scan_ports(self, hostname: str, port_range: str, method: str='nmap', timing: str='2') -> None:
        """Scan the ports of a host (can be a hostname or ip) and print the results in a table.
        Ports should be in the format 'start-end' and in the range 1-65535.

        Args:
            hostname (str): hostname or ip of the host to scan (e.g. 'www.website.com' or '1.1.1.1')
            port_range (str): range of ports to scan. (e.g. '1-65535')
            method (str, optional): [description]. Defaults to 'nmap'.
        """
        # Get the ip of the host
        ip_address = socket.gethostbyname(hostname)
        # Check if port range is valid
        ports = Utils.is_valid_port_range(port_range)
        if not ports:
            Utils.perror(f'Invalid port range: {port_range}')
            Utils.perror('Exiting...')
            return
        
        # Check if method is valid
        if method not in ['nmap', 'ping']:
            Utils.perror(f'Invalid method: {method}')
            Utils.perror('Exiting...')
            return
        
        # Check if the host is up
        sweeper = IpSweeper()
        hosts = sweeper.sweep(ip_address)
        if hosts[ip_address] == 'down':
            Utils.perror(f'Host \'{hostname}\' is down')
            Utils.perror('Exiting...')
            return

        # Create a table to store the results
        headers = ['Port', 'Service', 'State', 'Reason', 'Version', 'Extra']
        alignments = {'Port': 'l', 'Service': 'c', 'State': 'c', 'Reason': 'c', 'Version': 'c', 'Extra': 'c'}
        results = []
        num_of_rows = 0
        Utils.poutput('', prefix=False)

        # Get start time
        start_time = datetime.now()
        Utils.poutput(f'Scanning ports of \'{hostname}\'')
        Utils.poutput(f'Scanning port range: {port_range}')
        Utils.poutput(f'Scan started at: {str(start_time)}\n')

        # Scan the ports using nmap
        if method == 'nmap':
            # Check if running with root privileges
            if not Utils.is_root():
                Utils.perror('You must run this script with root privileges')
                Utils.perror('Try running \'sudo python3 port_scanner.py <arguments>\'')
                Utils.perror('Exiting...')
                return
                
            # Nmap timing conversion dictionary
            timing_dict = {'0': '-T0', 
                           '1': '-T1', 
                           '2': '-T2', 
                           '3': '-T3', 
                           '4': '-T4', 
                           '5': '-T5', 
                           'paranoid': '-T paranoid', 
                           'sneaky': '-T sneaky', 
                           'normal': '-T normal',
                           'polite': '-T polite', 
                           'aggresive': '-T aggressive', 
                           'insane': '-T insane'}

            # Check if timing is valid
            if timing not in timing_dict.keys():
                Utils.perror(f'Invalid nmap timing: {timing}')
                Utils.perror('Exiting...')
                return

            # Get the nmap timing
            nmap_timing = timing_dict[timing]
            # Nmap arguments
            nmap_args = f'-sS -P0 {nmap_timing}'

            # Create a nmap scanner
            scanner = NmapScanner()
            for port in range(ports[0], ports[1] + 1):
                try:
                    # Scan the port
                    result = scanner.scan(ip_address, str(port), arguments=nmap_args)
                    # Get the state of the port
                    state = result['scan'][ip_address]['tcp'][port]['state']
                    # Color the port state according to the state (open: green, closed: red, filtered: yellow)
                    color = 'green' if state == 'open' else 'red' if state == 'closed' else 'yellow'
                    state = Utils.color_text(state, color)
                    # Get the service name of the port
                    service = result['scan'][ip_address]['tcp'][port]['name']
                    # If service name is not available, skip it
                    if service == '' or service == 'unknown':
                        continue
                    # Get the reason of the port
                    reason = result['scan'][ip_address]['tcp'][port]['reason']
                    # Get the version of the port
                    version = result['scan'][ip_address]['tcp'][port]['version']
                    # Get the extra information of the port
                    extra = result['scan'][ip_address]['tcp'][port]['extrainfo']
                    # Add the port, service, state and reason to the results list
                    results.append([port, service, state, reason, version, extra])
                    num_of_rows += 1
                    # Update the table
                    table = Utils.create_table(results, headers, alignments=alignments, borders=False)
                    if num_of_rows != 1:
                        Utils.poutput(f'\33[{num_of_rows}A{table.get_string()}', prefix=False)
                    else:
                        Utils.poutput(table.get_string(), prefix=False)

                except KeyboardInterrupt:
                    Utils.poutput('Got interrupted')
                    Utils.poutput('Exiting...')
                    return
                except Exception:
                    pass

        # Scan the ports using ping
        else:   # method == 'ping'
            for port in range(ports[0], ports[1] + 1):     
                try:
                    # Create a socket
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        # Try to connect to the port
                        state = s.connect_ex((ip_address, port))

                    # Get the state of the port
                    state = 'open' if state == 0 else 'closed'
                    # Color the port state according to the state (open: green, closed: red)
                    color = 'green' if state == 'open' else 'red'
                    state = Utils.color_text(state, color)
                    # Get the service name of the port
                    service = socket.getservbyport(port)
                    # Add the port, service and open to the results list
                    results.append([port, service, state, ''])
                    num_of_rows += 1
                    # Update the table
                    table = Utils.create_table(results, headers, alignments=alignments, borders=False)
                    if num_of_rows != 1:
                        Utils.poutput(f'\33[{num_of_rows}A{table.get_string()}', prefix=False)
                    else:
                        Utils.poutput(table.get_string(), prefix=False)
                except KeyboardInterrupt:
                    Utils.poutput('Got interrupted')
                    Utils.poutput('Exiting...')
                    return
                except Exception:
                    pass

        # Get end time
        end_time = datetime.now()
        Utils.poutput('', prefix=False)
        Utils.poutput(f'Scan ended at: {str(end_time)}')
        Utils.poutput(f'Scan duration: {str(end_time-start_time)}')


def main() -> None:
    # Create a parser
    parser = ArgumentParser(description='Scan ports of a host')
    # Add arguments
    parser.add_argument('-H', '--hostname', required=True, type=str, help='hostname or ip of the host to scan')
    parser.add_argument('-r', '--range', required=True, type=str, help='range of ports to scan')
    parser.add_argument('-m', '--method', required=False, type=str, default='nmap', help='method to scan the ports (nmap or ping)')
    parser.add_argument('-T', '--timing', required=False, type=str, default='2', help='timing of nmap scan')
    # Parse the arguments
    args = parser.parse_args()

    # Print the banner
    Utils.print_banner('port-scanner')
    # Scan the ports
    scanner = PortScanner()
    scanner.scan_ports(args.hostname, args.range, args.method, args.timing)

if __name__ == '__main__':
    main()