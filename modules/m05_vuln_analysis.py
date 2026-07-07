def run():
    print("\n--- [Module 05] Vulnerability Analysis Simulator ---")
    software = input("Enter software name (e.g., Apache, OpenSSH): ").lower().strip()
    version = input("Enter version number (e.g., 2.4.1): ").strip()
    
    # Mock vulnerability reference table
    mock_db = {
        "apache": "2.4.49",
        "openssh": "8.4p1"
    }
    
    if software in mock_db:
        if version <= mock_db[software]:
            print(f"[WARNING] {software} v{version} may be outdated. Known vulnerable baseline: <= v{mock_db[software]}")
        else:
            print(f"[+] {software} v{version} appears up to date against local definitions.")
    else:
        print("[-] Software signature not found in local definitions database.")