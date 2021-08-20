from utils import Utils
from subprocess import call, check_output
import re
from typing import Union
from argparse import ArgumentParser
import sys

class MacSpoofer:
    """Class that represents an MAC spoofer"""
    def __init__(self) -> None:
        self.__utils = Utils()

    def validate_interface(self, interface: str) -> bool:
        """Validates that the interface is listed in 'ifconfig' output.

        Args:
            interface (str): The interface to check.

        Returns:
            bool: True if the interface was found and False if not.
        """
        interfaces = check_output("ifconfig -a | sed 's/[ \t].*//;/^$/d'", shell=True).decode(sys.stdout.encoding)
        interfaces = interfaces.split(':\n')
        return interface in interfaces

    def current_mac_address(self, interface: str) -> Union[str, None]:
        """Returns the current MAC address of the given interface.

        Args:
            interface (str): The interface to return its' address.

        Returns:
            Union[str, None]: The MAC address of the interface if found, None if not.
        """
        pattern = r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w'
        out = check_output(['ifconfig', interface]).decode(sys.stdout.encoding)
        res = re.search(pattern, out)
        if not res:
            self.__utils.perror(f'Could not find MAC address for {interface}')
            return None

        mac_addr = res.group(0)
        return mac_addr

    def change_mac(self, interface: str, mac_addr: str) -> None:
        """Changes the MAC address of the given interface to the new given MAC address.

        Args:
            interface (str): The interface to change its' MAC address.
            mac_addr (str): The new MAC address.
        """
        mac_address = self.__utils.check_mac_address_structure
        if mac_address is None:
            self.__utils.perror(f'Got invalid MAC address format')
            self.__utils.perror('Exiting...')
            exit()

        is_valid = self.validate_interface(interface)
        if not is_valid:
            self.__utils.perror(f'Got invalid interface: {interface}')
            self.__utils.perror('Exiting...')
            exit()

        current_mac = self.current_mac_address(interface)
        if current_mac is None:
            self.__utils.perror('Exiting...')
            exit()

        if current_mac == mac_addr:
            self.__utils.perror('New MAC address is the same as the current MAC address')
            self.__utils.perror('Exiting...')
            exit()

        self.__utils.poutput(f'Changing MAC address for {interface} from {current_mac} to {mac_addr}...')
        call(['ifconfig', interface, 'down'])
        call(['ifconfig', interface, 'hw', 'ether', mac_addr])
        call(['ifconfig', interface, 'up'])

        current_mac = self.current_mac_address(interface)
        if current_mac == mac_addr:
            self.__utils.poutput(f'New MAC address: {mac_addr}')
        else:
            self.__utils.perror(f'MAC address did not get changed')


def main():
    utils = Utils()
    spoofer = MacSpoofer()
    parser = ArgumentParser()
    parser.add_argument('-i', '--interface', required=True, type=str, 
                    help='Interface to change its\' MAC address')
    parser.add_argument('-m', '--mac-address', required=True, type=utils.check_mac_address_structure, 
                    help='New MAC address')
    
    args = parser.parse_args()
    
    utils.print_banner('mac-spoofer')
    mac_address = args.mac_address
    if mac_address is None:
        utils.perror(f'Got invalid MAC address format')
        self.__utils.perror('Exiting...')
        exit()

    interface = args.interface
    spoofer.change_mac(interface, mac_address)

if __name__ == '__main__':
    main()