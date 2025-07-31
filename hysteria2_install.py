#!/usr/bin/env python3
# Hysteria2 One-Click Installation Script
# This script automates the installation, configuration, and management of Hysteria2.

import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib import parse
import requests

# Global variables for configuration
HY2_CONFIG_PATH = Path("/etc/hysteria/config.yaml")
HY2_URL_SCHEME_PATH = Path("/etc/hy2config/hy2_url_scheme.txt")
HY2_SHORTCUT_PATH = Path("/usr/local/bin/hy2")
CONFIG_DIR = Path("/etc/hy2config")

def agree_treaty():
    """Prompt user to agree to terms and create shortcut if agreed."""
    def create_hy2_shortcut():
        """Create a shortcut for running the Hysteria2 script."""
        shortcut_content = (
            "#!/bin/bash\n"
            "wget -O hy2.py https://raw.githubusercontent.com/Humran13/hysteria2-installer/main/hysteria2_install.py && "
            "chmod +x hy2.py && python3 hy2.py\n"
        )
        HY2_SHORTCUT_PATH.write_text(shortcut_content)
        HY2_SHORTCUT_PATH.chmod(0o755)

    agree_file = CONFIG_DIR / "agree.txt"
    if agree_file.exists():
        print("You have already agreed to the terms, thank you!")
        create_hy2_shortcut()
        return

    while True:
        print(
            "I agree to use this program in compliance with the laws of the server location, "
            "the country where the server is hosted, and my own country. The program author is not "
            "responsible for any improper actions by the user. This program is for learning and "
            "exchange purposes only and must not be used for any commercial purposes."
        )
        choice = input("Do you agree and have read the Hysteria2 installation terms above [y/n]: ").lower()
        if choice == "y":
            CONFIG_DIR.mkdir(exist_ok=True)
            agree_file.touch()
            (CONFIG_DIR / "hy2_url_scheme.txt").touch()
            create_hy2_shortcut()
            break
        elif choice == "n":
            print("You must agree to the terms to proceed with installation.")
            sys.exit()
        else:
            print("\033[91mPlease enter a valid option!\033[m")

def run_subprocess(command, shell=True, executable="/bin/bash"):
    """Run a subprocess command and return the result."""
    try:
        result = subprocess.run(command, shell=shell, executable=executable, check=True)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command execution failed: {e}")
        return None

def validate_port(port_input):
    """Validate port number input."""
    try:
        port = int(port_input)
        if 1 <= port <= 65535:
            return port
        print("Port number must be between 1 and 65535. Please try again.")
        return None
    except ValueError:
        print("Port number must be a valid integer without decimal points. Please try again.")
        return None

def hysteria2_install():
    """Install or update Hysteria2."""
    while True:
        choice = input("Do you want to install/update Hysteria2 [y/n]: ").lower()
        if choice == "y":
            print("1. Install the latest version\n2. Install a specific version")
            version_choice = input("Enter your choice: ")
            if version_choice == "1":
                print("Installing the latest version...")
                result = run_subprocess("bash <(curl -fsSL https://get.hy2.sh/)")
                if result:
                    print("Hysteria2 installation completed. Proceed to configuration.")
                    hysteria2_config()
                break
            elif version_choice == "2":
                version = input("Enter the version number (e.g., 2.6.0, without 'v'): ")
                print(f"Installing Hysteria2 v{version}...")
                result = run_subprocess(f"bash <(curl -fsSL https://get.hy2.sh/) --version v{version}")
                if result:
                    print(f"Hysteria2 v{version} installation completed. Proceed to configuration.")
                    hysteria2_config()
                break
            else:
                print("\033[91mInvalid input. Please try again.\033[m")
        elif choice == "n":
            print("Hysteria2 installation canceled.")
            break
        else:
            print("\033[91mInvalid input. Please try again.\033[m")

def hysteria2_uninstall():
    """Uninstall Hysteria2."""
    while True:
        choice = input("Do you want to uninstall Hysteria2 [y/n]: ").lower()
        if choice == "y":
            print("Uninstalling Hysteria2...")
            run_subprocess("bash <(curl -fsSL https://get.hy2.sh/) --remove")
            run_subprocess(
                "rm -rf /etc/hysteria; "
                "rm -rf /etc/systemd/system/multi-user.target.wants/hysteria-server.service; "
                "rm -rf /etc/systemd/system/multi-user.target.wants/hysteria-server@*.service; "
                "systemctl daemon-reload; "
                "/etc/hy2config/jump_port_back.sh; "
                "rm -rf /etc/ssl/private; "
                "rm -rf /etc/hy2config; "
                "rm -rf /usr/local/bin/hy2"
            )
            print("Hysteria2 uninstallation completed.")
            sys.exit()
        elif choice == "n":
            print("Hysteria2 uninstallation canceled.")
            break
        else:
            print("\033[91mInvalid input. Please try again.\033[m")

def server_manage():
    """Manage Hysteria2 service."""
    while True:
        print(
            "1. Start service (enable auto-start on boot)\n"
            "2. Stop service\n"
            "3. Restart service\n"
            "4. View service status\n"
            "5. View logs\n"
            "6. View Hysteria2 version details\n"
            "0. Return"
        )
        choice = input("Enter your choice: ")
        commands = {
            "1": "systemctl enable --now hysteria-server.service",
            "2": "systemctl stop hysteria-server.service",
            "3": "systemctl restart hysteria-server.service",
            "4": "systemctl status hysteria-server.service",
            "5": "journalctl --no-pager -e -u hysteria-server.service",
        }
        if choice in commands:
            if choice == "4":
                print("\033[91mPress 'q' to exit status view.\033[m")
            run_subprocess(commands[choice])
        elif choice == "6":
            os.system("/usr/local/bin/hysteria version")
        elif choice == "0":
            break
        else:
            print("\033[91mInvalid input. Please try again.\033[m")

def get_ip_info(ip_version="ipv4"):
    """Fetch public IP address (IPv4 or IPv6)."""
    global hy2_domain
    headers = {"User-Agent": "Mozilla"}
    url = "http://ip-api.com/json/" if ip_version == "ipv4" else "https://api.ip.sb/geoip"
    try:
        response = requests.get(url, headers=headers, timeout=3)
        response.raise_for_status()
        ip_data = response.json()
        isp = ip_data.get("isp", "").lower()
        ip_key = "query" if ip_version == "ipv4" else "ip"
        ip = ip_data.get(ip_key, "")
        if "cloudflare" in isp:
            ip = input("Warp detected. Please enter the correct server IP: ")
        hy2_domain = ip if ip_version == "ipv4" else f"[{ip}]"
        print(f"{ip_version.upper()} WAN IP: {hy2_domain}")
    except requests.RequestException as e:
        print(f"Failed to fetch IP: {e}")
        hy2_domain = ""

def generate_self_signed_cert():
    """Generate a self-signed certificate."""
    global domain_name
    domain_name = input("Enter the domain for the self-signed certificate (default: bing.com): ").strip() or "bing.com"
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain_name):
        print("Invalid domain format. Please enter a valid domain!")
        return generate_self_signed_cert()

    target_dir = Path("/etc/ssl/private")
    target_dir.mkdir(parents=True, exist_ok=True)
    ec_param_file = target_dir / "ec_param.pem"
    cert_file = target_dir / f"{domain_name}.crt"
    key_file = target_dir / f"{domain_name}.key"

    run_subprocess(["openssl", "ecparam", "-name", "prime256v1", "-out", str(ec_param_file)])
    run_subprocess([
        "openssl", "req", "-x509", "-nodes", "-newkey", f"ec:{ec_param_file}",
        "-keyout", str(key_file), "-out", str(cert_file), "-subj", f"/CN={domain_name}", "-days", "36500"
    ])
    run_subprocess(f"chmod 666 {key_file} {cert_file} && chmod 777 {target_dir}")
    print(f"Self-signed certificate generated! Certificate: {cert_file}, Private key: {key_file}")

def configure_acme_dns():
    """Configure ACME DNS settings."""
    dns_providers = {
        "1": ("cloudflare", "cloudflare_api_token"),
        "2": ("duckdns", "duckdns_api_token", "duckdns_override_domain"),
        "3": ("gandi", "gandi_api_token"),
        "4": ("godaddy", "godaddy_api_token"),
        "5": ("name.com", "namedotcom_token", "namedotcom_user", "namedotcom_server"),
        "6": ("vultr", "vultr_api_key"),
    }
    while True:
        dns_choice = input(
            "DNS Provider:\n1. Cloudflare\n2. Duck DNS\n3. Gandi.net\n4. Godaddy\n5. Name.com\n6. Vultr\nEnter your choice: "
        )
        if dns_choice in dns_providers:
            provider, *fields = dns_providers[dns_choice]
            config = []
            for field in fields:
                value = input(f"Enter {field}: ")
                config.append(f"      {field}: {value}")
            config_str = "\n".join(config)
            return f"type: dns\n  dns:\n    name: {provider}\n    config:\n{config_str}"
        print("\033[91mInvalid input. Please try again.\033[m")

def configure_port_hopping(hy2_port):
    """Configure port hopping for Hysteria2."""
    global jump_ports_hy2
    while True:
        choice = input("Enable port hopping [y/n]: ").lower()
        if choice == "y":
            print("Select your IPv4 network interface (default: eth0, typically not 'lo')")
            os.system("ip -o addr | awk '{print $2}' | sort -u")
            interface = input("Enter your network interface name: ")
            first_port = validate_port(input("Enter the starting port number: "))
            last_port = validate_port(input("Enter the ending port number: "))
            if not (first_port and last_port) or first_port > last_port:
                print("Invalid port range. Please try again.")
                continue

            jump_port_back_v6 = ""
            if input("Enable IPv6 port hopping [y/n]: ").lower() == "y":
                print("Select your IPv6 network interface:")
                os.system("ip -o addr | awk '{print $2}' | sort -u")
                interface6 = input("Enter your IPv6 network interface name: ")
                ip6_cmd = f"ip6tables -t nat -A PREROUTING -i {interface6} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}"
                run_subprocess(ip6_cmd)
                jump_port_back_v6 = f"&& ip6tables -t nat -D PREROUTING -i {interface6} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}\n"

            jump_port_back_path = CONFIG_DIR / "jump_port_back.sh"
            if jump_port_back_path.exists():
                run_subprocess(str(jump_port_back_path))
                jump_port_back_path.unlink()

            run_subprocess(f"iptables -t nat -A PREROUTING -i {interface} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}")
            jump_port_back_path.write_text(
                f"#!/bin/sh\niptables -t nat -D PREROUTING -i {interface} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port} {jump_port_back_v6}"
            )
            run_subprocess(f"chmod 777 {jump_port_back_path}")
            jump_ports_hy2 = f"&mport={first_port}-{last_port}"
            break
        elif choice == "n":
            jump_ports_hy2 = ""
            break
        else:
            print("\033[91mInvalid input. Please try again.\033[m")

def hysteria2_config():
    """Configure Hysteria2 settings."""
    global hy2_domain, domain_name, insecure, jump_ports_hy2
    jump_ports_hy2 = ""
    while True:
        print(
            "1. View Hysteria2 configuration\n"
            "2. Modify Hysteria2 configuration automatically\n"
            "3. Modify Hysteria2 configuration manually\n"
            "4. Optimize performance (recommended: install xanmod kernel)\n"
            "0. Return"
        )
        choice = input("Enter your choice: ")
        if choice == "1":
            try:
                os.system("clear")
                print("Hysteria2 configuration file contents:\n")
                print(HY2_CONFIG_PATH.read_text())
                print(HY2_URL_SCHEME_PATH.read_text())
                print("Clash, Surge, and Sing-box templates are in /etc/hy2config/. Please check them manually.\n")
            except FileNotFoundError:
                print("\033[91mConfiguration file not found.\033[m")
        elif choice == "2":
            try:
                hy2_port = None
                while not hy2_port:
                    hy2_port = validate_port(input("Enter port number: "))
                hy2_username = urllib.parse.quote(input("Enter username: "))
                hy2_passwd = input("Enter a strong password: ")
                hy2_url = input("Enter the masquerade domain (must include https://): ")

                brutal_mode = "true" if input("Enable Brutal mode (not recommended by default) [y/n]: ").lower() == "n" else "false"
                
                obfs_mode, obfs_scheme = "", ""
                if input("Enable obfuscation mode (not recommended by default, disables masquerade) [y/n]: ").lower() == "y":
                    obfs_passwd = urllib.parse.quote(input("Enter obfuscation password: "))
                    obfs_mode = f"obfs:\n  type: salamander\n  salamander:\n    password: {obfs_passwd}"
                    obfs_scheme = f"&obfs=salamander&obfs-password={obfs_passwd}"

                sniff_mode = ""
                if input("Enable protocol sniffing (Sniff) [y/n]: ").lower() == "y":
                    sniff_mode = "sniff:\n  enable: true\n  timeout: 2s\n  rewriteDomain: false\n  tcpPorts: 80,443,8000-9000\n  udpPorts: all"

                configure_port_hopping(hy2_port)

                print("1. Automatically apply for a domain certificate\n2. Use a self-signed certificate (no domain required)\n3. Manually specify certificate paths")
                cert_choice = input("Enter your choice: ")
                if cert_choice == "1":
                    hy2_domain = input("Enter your domain: ")
                    domain_name = hy2_domain
                    hy2_email = input("Enter your email: ")
                    acme_dns = configure_acme_dns() if input("Configure ACME DNS settings (skip if unsure) [y/n]: ").lower() == "y" else ""
                    insecure = "&insecure=0"
                    HY2_CONFIG_PATH.write_text(
                        f"listen: :{hy2_port}\n\nacme:\n  domains:\n    - {hy2_domain}\n  email: {hy2_email}\n  {acme_dns}\n\n"
                        f"auth:\n  type: password\n  password: {hy2_passwd}\n\nmasquerade:\n  type: proxy\n  proxy:\n    url: {hy2_url}\n    rewriteHost: true\n\n"
                        f"ignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n"
                    )
                elif cert_choice == "2":
                    generate_self_signed_cert()
                    ip_mode = input("1. IPv4 mode\n2. IPv6 mode\nEnter your choice: ")
                    get_ip_info("ipv4" if ip_mode == "1" else "ipv6")
                    insecure = "&insecure=1"
                    HY2_CONFIG_PATH.write_text(
                        f"listen: :{hy2_port}\n\ntls:\n  cert: /etc/ssl/private/{domain_name}.crt\n  key: /etc/ssl/private/{domain_name}.key\n\n"
                        f"auth:\n  type: password\n  password: {hy2_passwd}\n\nmasquerade:\n  type: proxy\n  proxy:\n    url: {hy2_url}\n    rewriteHost: true\n\n"
                        f"ignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n"
                    )
                elif cert_choice == "3":
                    hy2_cert = input("Enter the certificate path: ")
                    hy2_key = input("Enter the key path: ")
                    hy2_domain = input("Enter your domain: ")
                    domain_name = hy2_domain
                    insecure = "&insecure=0"
                    HY2_CONFIG_PATH.write_text(
                        f"listen: :{hy2_port}\n\ntls:\n  cert: {hy2_cert}\n  key: {hy2_key}\n\n"
                        f"auth:\n  type: password\n  password: {hy2_passwd}\n\nmasquerade:\n  type: proxy\n  proxy:\n    url: {hy2_url}\n    rewriteHost: true\n\n"
                        f"ignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n"
                    )
                else:
                    print("\033[91mInvalid input. Please try again.\033[m")
                    continue

                os.system("clear")
                hy2_passwd = urllib.parse.quote(hy2_passwd)
                hy2_v2ray = f"hysteria2://{hy2_passwd}@{hy2_domain}:{hy2_port}?sni={domain_name}{obfs_scheme}{insecure}{jump_ports_hy2}#{hy2_username}"
                print("Your V2Ray QR code:\n")
                time.sleep(1)
                os.system(f'echo "{hy2_v2ray}" | qrencode -s 1 -m 1 -t ANSI256 -o -')
                print(f"\n\n\033[91mYour Hysteria2 link: {hy2_v2ray}\nImport it using v2ray/nekobox/v2rayNG/nekoray software.\033[m\n\n")
                HY2_URL_SCHEME_PATH.write_text(f"Your V2Ray Hysteria2 configuration link: {hy2_v2ray}\n")

                print("Downloading Clash, Sing-box, and Surge configuration files to /etc/hy2config/")
                hy2_v2ray_url = urllib.parse.quote(hy2_v2ray)
                url_rule = "%0A&ua=&selectedRules=%5B%22Ad%20Block%22%2C%22AI%20Services%22%2C%22Youtube%22%2C%22Google%22%2C%22Private%22%2C%22Location%3ACN%22%2C%22Telegram%22%2C%22Apple%22%2C%22Non-China%22%5D&customRules=%5B%5D"
                for config_type in ["clash", "sing-box", "surge"]:
                    run_subprocess(f"curl -o /etc/hy2config/{config_type}.yaml 'https://sub.crazyact.com/{config_type}?config={hy2_v2ray_url}{url_rule}'")
                print("\033[91mClash, Sing-box, and Surge configuration files saved to /etc/hy2config/!\033[m")

                run_subprocess("systemctl enable --now hysteria-server.service")
                run_subprocess("systemctl restart hysteria-server.service")

            except FileNotFoundError:
                print("\033[91mConfiguration file not found. Please install Hysteria2 first.\033[m")
        elif choice == "3":
            print("\033[91mUsing nano editor for manual configuration. Save with Ctrl+X to exit.\033[m")
            run_subprocess("nano /etc/hysteria/config.yaml")
            run_subprocess("systemctl enable --now hysteria-server.service")
            run_subprocess("systemctl restart hysteria-server.service")
            print("Hysteria2 service started.")
        elif choice == "4":
            run_subprocess(
                "wget -O tcpx.sh 'https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh' && "
                "chmod +x tcpx.sh && ./tcpx.sh"
            )
        elif choice == "0":
            break
        else:
            print("\033[91mInvalid input. Please try again.\033[m")

def check_hysteria2_version():
    """Check the installed Hysteria2 version."""
    try:
        output = subprocess.check_output(
            "/usr/local/bin/hysteria version | grep '^Version' | grep -o 'v[.0-9]*'",
            shell=True,
            stderr=subprocess.STDOUT
        )
        version = output.decode("utf-8").strip()
        print(f"Current Hysteria2 version: {version}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to check version: {e.output.decode('utf-8')}")

def main():
    """Main program loop."""
    agree_treaty()
    while True:
        os.system("clear")
        print("\033[91mHELLO HYSTERIA2!\033[m (Run 'hy2' for quick start)")
        print(
            "1. Install/Update Hysteria2\n"
            "2. Uninstall Hysteria2\n"
            "3. Configure Hysteria2\n"
            "4. Manage Hysteria2 Service\n"
            "0. Exit"
        )
        choice = input("Enter your choice: ")
        os.system("clear")
        if choice == "1":
            hysteria2_install()
        elif choice == "2":
            hysteria2_uninstall()
        elif choice == "3":
            hysteria2_config()
        elif choice == "4":
            check_hysteria2_version()
            server_manage()
        elif choice == "0":
            print("Exiting...")
            sys.exit()
        else:
            print("\033[91mInvalid input. Please try again.\033[m")
            time.sleep(1)

if __name__ == "__main__":
    main()