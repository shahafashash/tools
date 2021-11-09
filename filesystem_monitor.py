from logging import getLogger, StreamHandler, FileHandler, Formatter, DEBUG
import os
import shutil
import ctypes
from argparse import ArgumentParser
from typing import List, Union
from time import sleep, strftime
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import (
    PatternMatchingEventHandler,
    DirCreatedEvent,
    FileCreatedEvent,
    DirDeletedEvent,
    FileDeletedEvent,
    DirModifiedEvent,
    FileModifiedEvent,
    DirMovedEvent,
    FileMovedEvent
)

class FileSystemMonitor(PatternMatchingEventHandler):
    """Class for monitoring file system events."""
    def __init__(self, patterns: List[str]=None, ignore_patterns: List[str]=[], ignore_directories: bool=False, case_sensitive: bool=False) -> None:
        """Initializes the FileSystemMonitor object.

        Args:
            patterns (List[str], optional): The patterns to be monitored. Defaults to None.
            ignore_patterns (List[str], optional): The patterns to be ignored. Defaults to [].
            ignore_directories (bool, optional): Whether to ignore directories. Defaults to False.
            case_sensitive (bool, optional): Whether to ignore case sensitivity. Defaults to False.
        """
        # Add the logger file pattern to the ignore patterns list.
        ignore_patterns.append('*monitor*.txt')
        # Initialize the super class
        super().__init__(patterns=patterns, ignore_patterns=ignore_patterns, ignore_directories=ignore_directories, case_sensitive=case_sensitive)
        
        # Initialize the logger
        self.logger = self.create_logger()
        # Initialize the backup directory
        self.backup_dir = self.create_backup_dir() if self.is_admin() else None
    
    def is_admin(self) -> bool:
        """Checks if the current user is an administrator.

        Returns:
            bool: Whether the current user is an administrator.
        """
        try:
            # Check if the current user is root (Linux)
            res = os.getuid() == 0
        except AttributeError:
            # Check if the current user is an administrator (Windows)
            res = ctypes.windll.shell32.IsUserAnAdmin() != 0
        return res
    
    def create_logger(self, level: int=DEBUG, print_to_console: bool=True, print_to_file: bool=True, propagate: bool=False) -> None:
        """Creates a logger object.

        Args:
            level (int, default: DEBUG): The level of the logger.
            print_to_console (bool, default: True): Whether to print the log messages to the console.
            print_to_file (bool, default: True): Whether to print the log messages to a log file.
            propagate (bool, default: False): Whether to propagate the log messages to the parent logger.
        """
        logger = getLogger(__name__)
        logger.setLevel(level)
        if print_to_console:
            console_handler = StreamHandler()
            console_handler.setLevel(level)
            # console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        if print_to_file:
            log_file_name = f'monitor_{strftime("%Y-%m-%d_%H-%M-%S")}.txt'
            file_handler = FileHandler(log_file_name)
            file_handler.setLevel(level)
            file_handler.setFormatter(Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)
        logger.propagate = propagate
        return logger   
    
    def create_backup_dir(self) -> str:
        """Creates a backup directory with the name 'backup_<timestamp>'.

        Returns:
            str: The path of the backup directory.
        """
        timestamp = strftime('%Y-%m-%d_%H-%M-%S')
        backup_dir = f'backup_{timestamp}'
        if not os.path.exists(backup_dir):
            os.mkdir(backup_dir)
        return backup_dir
    
    def move_to_backup_dir(self, src_path: str, old_path: str=None) -> None:
        """Copies the created file or directory to the backup directory.

        Args:
            src_path (str): The path of the created file or directory.
            old_path (str, default: None): The path of the original file or directory.
        """
        if old_path:
            os.remove(old_path)
        shutil.copy2(src_path, self.backup_dir)
    
    def on_created(self, event: Union[DirCreatedEvent, FileCreatedEvent]) -> None:
        """Handles the creation of a file or directory.

        Args:
            event (Union[DirCreatedEvent, FileCreatedEvent]): The created file or directory.
        """
        self.logger.info(f"[+] {event.event_type} '{event.src_path}' has been created!")
        if self.backup_dir is not None:
            self.move_to_backup_dir(event.src_path)
        
    def on_deleted(self, event: Union[DirDeletedEvent, FileDeletedEvent]) -> None:
        """Handles the deletion of a file or directory.

        Args:
            event (Union[DirDeletedEvent, FileDeletedEvent]): The deleted file or directory.
        """
        self.logger.info(f"[-] {event.event_type} '{event.src_path}' has been deleted!")
        
    def on_modified(self, event: Union[DirModifiedEvent, FileModifiedEvent]) -> None:
        """Handles the modification of a file or directory.

        Args:
            event (Union[DirModifiedEvent, FileModifiedEvent]): The modified file or directory.
        """
        self.logger.info(f"[!] '{event.src_path}' has been modified!")
        if self.backup_dir is not None:
            self.move_to_backup_dir(event.src_path)
        
    def on_moved(self, event: Union[DirMovedEvent, FileMovedEvent]) -> None:
        """Handles the moving of a file or directory.

        Args:
            event (Union[DirMovedEvent, FileMovedEvent]): The moved file or directory.
        """
        self.logger.info(f"[!] {event.event_type} '{event.src_path}' has been moved! '{event.src_path}' --> '{event.dest_path}'")
        if self.backup_dir is not None:
            self.move_to_backup_dir(event.src_path, event.dest_path)
        
    def monitor(self, path: str='.', recursive: bool=True, sleep_time: int=1) -> None:
        """Monitors the given directory for changes.

        Args:
            path (str, default: '.'): The path of the directory to monitor.
            recursive (bool, default: True): Whether to monitor the subdirectories of the given directory.
            sleep_time (int, default: 1): The time to sleep between each check.
        """
        self.logger.info(f"[*] Monitoring '{path}' for changes...\n")
        start_time = datetime.now()
        # Initialize the observer
        event_handler = self
        observer = Observer()
        observer.schedule(event_handler, path, recursive=recursive)
        # Start monitoring
        observer.start()
        try:
            while True:
                sleep(sleep_time)
        except KeyboardInterrupt:
            observer.stop()
            self.logger.info(f"[!] Monitoring has been stopped.\n")
        # Wait until all threads are finished
        observer.join()
        end_time = datetime.now()
        self.logger.info(f"[*] Finished monitoring '{path}' for changes.")
        self.logger.info(f"[*] Total time taken for the monitoring: {end_time - start_time}")
        

if __name__ == '__main__':
    # Create the arguments parser
    parser = ArgumentParser(description='Monitors a directory for changes and copies the changed files to a backup directory.')
    parser.add_argument('-p', '--path', type=str, default='.', help='The path of the directory to monitor.')
    parser.add_argument('-r', '--recursive', action='store_true', help='Whether to monitor the subdirectories of the given directory.')
    parser.add_argument('-s', '--sleep-time', type=int, default=1, help='The time to sleep between each check.')
    parser.add_argument('-i', '--ignore-directories', action='store_true', help='Whether to ignore directories.')
    parser.add_argument('-c', '--case-sensitive', action='store_true', help='Whether to ignore case when matching files.')
    parser.add_argument('-I', '--ignore-patterns', type=str, nargs='+', default=[], help='The patterns to ignore.')
    parser.add_argument('-P', '--patterns', type=str, nargs='+', help='The patterns to monitor.')
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Create the monitor object.
    monitor = FileSystemMonitor(patterns=args.patterns, ignore_patterns=args.ignore_patterns, case_sensitive=args.case_sensitive)
    # Start the monitoring.
    monitor.monitor(path=args.path, recursive=args.recursive, sleep_time=args.sleep_time)