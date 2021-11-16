#!/usr/bin/env python3
# Disclaimer: This script is for educational purposes only. Do not use it against any network that you dont have authorization to test.

from utils import Utils
from subprocess import check_output
import re
from typing import Union
from argparse import ArgumentParser


class MacSpoofer:
    """Class for performing MAC spoofing"""
    def __init__(self) -> None:
        pass

    def check_interface(self, interface: str) -> bool:
        """Check if interface is listed in 'ifconfig' command output

        Args:
            interface (str): Interface name

        Returns:
            bool: True if interface is listed in 'ifconfig' command output, False otherwise
        """
        ifconfig_output = check_output("ifconfig -a | sed 's/[ \t].*//;/^$/d'", shell=True, encoding='utf-8')
        interfaces = ifconfig_output.split('\n')
        if interface in interfaces:
            return True
        else:
            Utils.perror(f'Interface \'{interface}\' not found')
            return False

    def get_mac_address(self, interface: str) -> Union[str, None]:
        """Return the current MAC address of the specified interface (eth0, wlan0, etc.) using the ifconfig command

        Args:
            interface (str): Interface name

        Returns:
            Union[str, None]: MAC address of the specified interface if it exists, None otherwise
        """
        if self.check_interface(interface):
            ifconfig_output = check_output("ifconfig " + interface, shell=True, encoding='utf-8')
            mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_output)
            if mac_address is not None:
                return mac_address.group(0)
            else:
                # print error message if interface is not found
                Utils.perror(f'Could not find MAC address for \'{interface}\'')
        return None

    def spoof_mac_address(self, interface: str, new_mac_address: str) -> None:
        """Spoof the MAC address of the specified interface 

        Args:
            interface (str): Interface name
            new_mac_address (str): New MAC address
        """
        # check if the structure of the MAC address is correct
        if not Utils.is_valid_mac_address(new_mac_address):
            Utils.perror(f'Invalid MAC address: \'{new_mac_address}\'')
            return
        # check if the interface exists
        if not self.check_interface(interface):
            return
        # get the current MAC address of the specified interface
        current_mac_address = self.get_mac_address(interface)
        if current_mac_address is None:
            return
        # check if the MAC address is the same as the current MAC address of the specified interface
        if current_mac_address == new_mac_address:
            Utils.perror(f'MAC address of \'{interface}\' is already \'{new_mac_address}\'')
            return
        # change the MAC address of the specified interface
        Utils.poutput(f'Changing MAC address of \'{interface}\' from \'{current_mac_address}\' to \'{new_mac_address}\'')
        check_output(f'ifconfig {interface} down', shell=True, encoding='utf-8')
        check_output(f'ifconfig {interface} hw ether {new_mac_address}', shell=True, encoding='utf-8')
        check_output(f'ifconfig {interface} up', shell=True, encoding='utf-8')
        # check if the MAC address of the specified interface has been changed
        new_mac_address = self.get_mac_address(interface)
        if new_mac_address is None:
            return
        if current_mac_address != new_mac_address:
            Utils.perror(f'Could not change MAC address of \'{interface}\' to \'{new_mac_address}\'')
        else:
            Utils.poutput(f'MAC address of \'{interface}\' has been changed to \'{new_mac_address}\'')


def main() -> None:
    # Create the argument parser
    parser = ArgumentParser(description='Spoof MAC address of an interface')
    parser.add_argument('-i', '--interface', required=True, help='Interface name')
    parser.add_argument('-m', '--mac-address', required=True, help='New MAC address')
    args = parser.parse_args()

    # Print the banner
    Utils.print_banner('mac_spoofer')

    # Create the MAC spoofer object
    mac_spoofer = MacSpoofer()
    # Spoof the MAC address of the specified interface
    mac_spoofer.spoof_mac_address(args.interface, args.mac_address)

if __name__ == '__main__':
    main()