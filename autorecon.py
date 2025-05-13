import sys
import socket
import subprocess
import requests
import os

report = []  # Collect output here


def banner():
    header = "=" * 50 + "\n" + "        AutoRecon - Reconnaissance Tool\n" + "=" * 50
    print(header)
    report.append(header)


def dns_lookup(target):
    report.append("\n[+] Performing DNS Lookup...")
    print("\n[+] Performing DNS Lookup...")
    try:
        ip = socket.gethostbyname(target)
        line1 = f"    [✔] Hostname: {target}"
        line2 = f"    [✔] Resolved IP: {ip}"
        print(line1)
        print(line2)
        report.extend([line1, line2])
    except socket.gaierror:
        error_msg = "    [✖] DNS resolution failed. Invalid domain or network issue."
        print(error_msg)
        report.append(error_msg)


def whois_lookup(target):
    report.append("\n[+] Performing WHOIS Lookup...")
    print("\n[+] Performing WHOIS Lookup...")
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=10)
        output = result.stdout

        if output:
            for line in output.splitlines():
                if any(keyword in line.lower() for keyword in [
                    "registrar", "org", "domain name", "name server",
                    "creation", "expiry", "updated"
                ]):
                    line_formatted = "    " + line.strip()
                    print(line_formatted)
                    report.append(line_formatted)
        else:
            error_msg = "    [✖] No WHOIS data found."
            print(error_msg)
            report.append(error_msg)

    except FileNotFoundError:
        error_msg = "    [✖] 'whois' tool not found. Install it using: sudo apt install whois"
        print(error_msg)
        report.append(error_msg)
    except subprocess.TimeoutExpired:
        error_msg = "    [✖] WHOIS command timed out."
        print(error_msg)
        report.append(error_msg)
    except Exception as e:
        error_msg = f"    [✖] Error occurred: {e}"
        print(error_msg)
        report.append(error_msg)


def port_scan(target):
    report.append("\n[+] Performing Basic Port Scan...")
    print("\n[+] Performing Basic Port Scan...")
    common_ports = {
        20: 'FTP Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        3306: 'MySQL'
    }

    try:
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                msg = f"    [✔] Port {port} ({service}) is OPEN"
                print(msg)
                report.append(msg)
            sock.close()
    except socket.gaierror:
        error_msg = "    [✖] Hostname could not be resolved."
        print(error_msg)
        report.append(error_msg)
    except socket.error:
        error_msg = "    [✖] Couldn't connect to server."
        print(error_msg)
        report.append(error_msg)


def get_http_headers(target):
    report.append("\n[+] Fetching HTTP Headers...")
    print("\n[+] Fetching HTTP Headers...")
    url = f"http://{target}"
    try:
        response = requests.get(url, timeout=5)
        status_msg = f"    [✔] HTTP Status Code: {response.status_code}"
        print(status_msg)
        report.append(status_msg)
        report.append("    [✔] Headers:")
        print("    [✔] Headers:")
        for key, value in response.headers.items():
            header_line = f"        {key}: {value}"
            print(header_line)
            report.append(header_line)
    except requests.exceptions.RequestException as e:
        error_msg = f"    [✖] Failed to fetch HTTP headers: {e}"
        print(error_msg)
        report.append(error_msg)


def save_report(target):
    os.makedirs("output", exist_ok=True)
    filepath = f"output/{target.replace('.', '_')}_report.txt"
    with open(filepath, "w") as f:
        f.write("\n".join(report))
    print(f"\n[+] Report saved to {filepath}")


def subdomain_bruteforce(target, wordlist_path="subdomains.txt"):
    print("\n[+] Performing Subdomain Brute-Forcing...")

    try:
        with open(wordlist_path, "r") as file:
            subdomains = file.read().splitlines()

        found = False
        for word in subdomains:
            word = word.strip()
            if not word:
                continue  # Skip empty or whitespace-only lines

            subdomain = f"{word}.{target}"
            try:
                ip = socket.gethostbyname(subdomain)
                print(f"    [✔] Found: {subdomain} -> {ip}")
                found = True
            except socket.gaierror:
                continue

        if not found:
            print("    [!] No subdomains found (or all failed to resolve).")

    except FileNotFoundError:
        print(f"    [✖] Wordlist file '{wordlist_path}' not found.")




def main():
    banner()
    if len(sys.argv) != 2:
        print("Usage: python3 autorecon.py <target_domain_or_ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[+] Target set to: {target}")
    report.append(f"\n[+] Target set to: {target}")

    dns_lookup(target)
    whois_lookup(target)
    port_scan(target)
    get_http_headers(target)
    subdomain_bruteforce(target)
    save_report(target)


if __name__ == "__main__":
    main()
