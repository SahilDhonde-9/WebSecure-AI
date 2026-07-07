import sys

class Logger:
    # ANSI escape codes for terminal coloring
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

    @staticmethod
    def success(message):
        """Logs a successful operation."""
        print(f"{Logger.GREEN}[+] {message}{Logger.RESET}")

    @staticmethod
    def info(message):
        """Logs general information."""
        print(f"{Logger.BLUE}[*] {message}{Logger.RESET}")

    @staticmethod
    def warn(message):
        """Logs a security warning or vulnerability baseline match."""
        print(f"{Logger.YELLOW}[!] {message}{Logger.RESET}")

    @staticmethod
    def error(message):
        """Logs a failure or connection error."""
        print(f"{Logger.RED}[-] {message}{Logger.RESET}")