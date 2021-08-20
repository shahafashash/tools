from utils import Utils
import nmap
from argparse import ArgumentParser
from datetime import datetime

class IpSweeper:
    """Class that represents an IP sweeper"""
    def __init__(self) -> None:
        self.__utils = Utils()

    def sweep(self, ip_network: str) -> None:
        """Pings addresses in the given network (or single address if not a network) and returns the status for each address.

        Args:
            ip_network (str): IP network or single IP address (ex: 127.0.1.0 or 127.0.1.0/24)
        """
        ip = self.__utils.check_ip_address_or_network(ip_network)
        if ip is None:
            self.__utils.perror(f'Got invalid IP network or invalid IP network format')
            self.__utils.perror('Exiting...')
            exit()

        scan_start = datetime.now()

        self.__utils.poutput(f'Sweeping target: {ip}')
        self.__utils.poutput(f'Scan started at: {str(scan_start)}\n')

        headers = ['Host', 'Status']
        alignments = {'Host': 'l', 'Status': 'c'}
        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=ip, arguments='-n -sP -PE -PA21,23,80,3389')
            hosts_list = [[x, scanner[x]['status']['state']] for x in scanner.all_hosts()]
            for i, result in enumerate(hosts_list):
                host, status = result
                status = f'\033[0;32;40m{status}\033[0m' if status == 'up' else f'\033[0;31;40m{status}\033[0m'
                hosts_list[i] = [host, status]
            
            hosts_list = sorted(hosts_list, key=lambda x: int(x[0].split('.')[-1]))
            table = self.__utils.create_table(hosts_list, headers, alignments=alignments, borders=False)
            self.__utils.poutput(table.get_string(), prefix=False)

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
    sweeper = IpSweeper()
    parser = ArgumentParser()
    parser.add_argument('-i', '--ip-network', required=True, type=utils.check_ip_address_or_network, 
                    help='Address representing the IP network or IP address (ex: 10.0.2.0/24 or 10.0.2.0)')
    args = parser.parse_args()
    
    utils.print_banner('ip-sweeper')
    target = args.ip_network
    if target is None:
        utils.perror('Got invalid IP network/address or invalid IP network/address format')
        utils.perror('Exiting...')
        exit()
    
    sweeper.sweep(target)

if __name__ == '__main__':
    main()
