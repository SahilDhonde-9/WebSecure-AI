import socket

def run():
    print("\n--- [Module 03] Network Scanning Simulator ---")
    target = input("Enter target IP (Default: 127.0.0.1): ") or "127.0.0.1"
    ports = [21, 22, 80, 443]
    print(f"Auditing common ports on {target}...")
    
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"  [!] Port {port}: OPEN")
        else:
            print(f"  [-] Port {port}: Closed/Filtered")
        s.close()