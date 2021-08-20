import ipaddress
from pyfiglet import figlet_format
import sys
from prettytable import PrettyTable
from typing import Any, Union, List
import re

class Utils:
    def __init__(self) -> None:
        pass

    def perror(self, text: Any, end: str='\n') -> None:
        """Prints text to stderr. Used to print errors.

        Args:
            text (Any): Text to print.
            end: (str, optional): Text to print after the 'text' argument. Defaults to '\\n'.
        """
        err_msg = f'[!] {text}'
        sys.stderr.write(f'{err_msg}{end}')
        sys.stderr.flush()

    def poutput(self, text: Any, prefix: bool=True, end: str='\n') -> None:
        """Prints text to stderr. Used to print information.

        Args:
            text (Any): Text to print.
            prefix (bool, optional): Print the text with or without the prefix '[*]'. Defaults to True.
            end: (str, optional): Text to print after the 'text' argument. Defaults to '\\n'.
        """
        if prefix is True:
            msg = f'[*] {text}'
        else:
            msg = text

        sys.stderr.write(f'{msg}{end}')
        sys.stderr.flush()

    def create_table(self, data: List[List[Any]], headers: List[str], alignments: dict[str, str]=None, borders: bool=True) -> PrettyTable:
        """Creates a table object

        Args:
            data (List[List[Any]]): List of rows to insert to the table.
            headers (List[str]): Names of the tabls' columns.
            alignments (dict[str, str], optional): Dictionary with columns alignments. Each key represents te column name and the value
                                                   represents the alignment in that column. Defaults to None.
                                                   Valid alignments: l, c, r
            borders (bool, optional): True for table with borders and False for borderless table. Defaults to True.

        Returns:
            PrettyTable: Table object
        """
        table = PrettyTable()
        table.field_names = headers
        table.add_rows(data)

        if alignments is not None:
            for column, alignment in alignments.items():
                table.align[column] = alignment

        table.border = borders

        return table

    def check_ip_address_or_network(self, ip: str) -> Union[str, None]:
        """Check if the IP represents a network or a single adress

        Args:
            ip (str): IP to check

        Returns:
            Union[str, None]: IP address or IP network if represents one of them. None if not.
        """
        network = self.check_ip_network_structure(ip)
        if network is not None:
            return network

        address = self.check_ip_address_structure(ip)
        return address

    def check_ip_network_structure(self, ip_network: str) -> Union[str, None]:
        """Check if IP network is valid

        Args:
            ip_network (str): IP network to check

        Returns:
            Union[str, None]: The IP network if the address is valid. None if not.
        """
        try:
            _, cidr = ip_network.split('/')
            cidr = int(cidr)
            network = ipaddress.ip_network(ip_network)
            return str(network)
        except:
            return None

    def check_ip_address_structure(self, ip_address: str) -> Union[str, None]:
        """Check if the IP address is valid

        Args:
            ip_address (str): IP address to check 

        Returns:
            Union[str, None]: The IP address if the address is valid. None if not.
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return str(ip)
        except:
            return None

    def check_port_range(self, range: str) -> Union[tuple[int, int], None]:
        """Check if the range of ports given is valid and between 1 to 65535

        Args:
            range (str): Range of ports to scan. Arg should be in the following format: <min_port>-<max_port>

        Returns:
            Union[tuple[int, int], None]: Tuple of the minimum and maximum ports. None if the range is not valid.
        """
        try:
            ports = range.split('-')
            min_port, max_port = ports
            min_port = int(min_port)
            max_port = int(max_port)
            if min_port > 0 and min_port <= max_port and max_port <= 65535:
                return (min_port, max_port)
            else:
                return None
        except:
            return None

    def check_mac_address_structure(self, mac_address: str) -> Union[str, None]:
        """Check if the structure of the MAC address is valid

        Args:
            mac_address (str): Mac address to check its' structure.

        Returns:
            Union[str, None]: The MAC address if the structure is valid. None if not.
        """
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$'
        res = re.search(pattern, mac_address)
        if res is not None:
            return mac_address
        return None

    def print_banner(self, header: str) -> None:
        """Prints a banner with the given header

        Args:
            header (str): Header of the banner.
        """
        ascii_banner = figlet_format(header.upper())
        banner = f"""
{ascii_banner}
**********************************************************************
* Created by Shahaf Ashash, 2021                                     *
* Github: https://github.com/shahafashash                            *
* Have Fun!                                                          *
**********************************************************************
"""

        self.poutput(banner, prefix=False)