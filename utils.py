import ipaddress
from pyfiglet import figlet_format
from prettytable import PrettyTable
from typing import List, Dict, Any, Optional, Tuple
import re
import sys
import os
from colorama import Fore
import requests

class Utils:
    """Class for utility functions"""

    @staticmethod
    def perror(text: str, end: str = '\n') -> None:
        """Prints an error message to stderr.

        Args:
            text (str): The text to print.
            end (str, optional): The end of the message. Defaults to '\n'.
        """
        sys.stderr.write(f'[!] {text}' + end)
        sys.stderr.flush()

    @staticmethod
    def poutput(text: str, prefix: bool=True, end: str = '\n') -> None:
        """Prints a message to stdout.

        Args:
            text (str): The text to print.
            prefix (bool, optional): Whether to prefix the message with '[*]'. Defaults to True.
            end (str, optional): The end of the message. Defaults to '\n'.
        """
        if prefix:
            sys.stdout.write(f'[*] {text}' + end)
        else:
            sys.stdout.write(text + end)
        sys.stdout.flush()

    # Funcion to check if program is running with root privileges
    @staticmethod
    def is_root() -> bool:
        """Checks if the program is running with root privileges.

        Returns:
            bool: True if running with root privileges, False otherwise.
        """
        return os.geteuid() == 0

    @staticmethod
    def color_text(text: str, color: str) -> str:
        """Returns a string in a given color.

        Args:
            text (str): The text to color.
            color (str): The color to use.

        Returns:
            str: The colored text.
        """
        return f'{Fore.__dict__[color.upper()]}{text}{Fore.RESET}'
    
    @staticmethod
    def print_banner(header: str) -> None:
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

        Utils.poutput(banner, prefix=False)

    @staticmethod
    def create_table(data: List[List[Any]], headers: List[str], alignments: Dict[str, str]=None, borders: bool=True) -> PrettyTable:
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

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Checks if the given IP address is valid.

        Args:
            ip (str): The IP address to check.

        Returns:
            bool: True if the IP address is valid and False otherwise.
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_network(network: str) -> bool:
        """Checks if the given network is valid.

        Args:
            network (str): The network to check.

        Returns:
            bool: True if the network is valid and False otherwise.
        """
        try:
            ipaddress.ip_network(network)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_network_or_ip(network: str) -> bool:
        """Checks if the given network is valid.

        Args:
            network (str): The network to check.

        Returns:
            bool: True if the network is valid and False otherwise.
        """
        if Utils.is_valid_network(network):
            return True
        elif Utils.is_valid_ip(network):
            return True
        else:
            return False

    @staticmethod
    def is_valid_port_range(port_range: str) -> Optional[Tuple[int, int]]:
        """Checks if the given port range is valid and between 1 and 65535.

        Args:
            port_range (str): The port range to check. The port range is a string in the format 'start-end'.

        Returns:
            Optional[Tuple[int, int]]: Tuple of the start and end ports if the port range is valid and None otherwise.
        """
        if not port_range:
            return None
        try:
            if '-' in port_range:
                start_port, end_port = port_range.split('-')
            else:
                start_port = end_port = port_range
            start_port = int(start_port)
            end_port = int(end_port) if end_port else start_port

            if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535:
                return None

            return start_port, end_port
        except ValueError:
            return None

    @staticmethod
    def is_valid_mac_address(mac: str) -> bool:
        """Checks if the given MAC address is valid.

        Args:
            mac (str): The MAC address to check.

        Returns:
            bool: True if the MAC address is valid and False otherwise.
        """
        if not mac:
            return False
        pattern = re.compile(r'^([0-9a-fA-F]{2}[:]){5}([0-9a-fA-F]{2})$')
        return pattern.match(mac) is not None

    @staticmethod
    def get_vendor_from_mac(mac: str) -> str:
        """Gets the vendor name from the given MAC address.

        Args:
            mac (str): The MAC address to get the vendor name from.

        Returns:
            str: The vendor name.
        """
        if not Utils.is_valid_mac_address(mac):
            return ''
        url = f'https://api.macvendors.com/{mac}'
        try:
            response = requests.get(url)
            return response.text
        except requests.exceptions.RequestException:
            return 'unknown'