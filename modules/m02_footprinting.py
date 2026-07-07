import socket

def run():
    print("\n--- [Module 02] Footprinting & Reconnaissance ---")
    domain = input("Enter domain to resolve (e.g., google.com): ") or "localhost"
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Target Domain: {domain}")
        print(f"[+] Resolved IP: {ip}")
    except socket.gaierror:
        print("[-] Could not resolve host.")