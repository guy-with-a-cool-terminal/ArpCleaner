#!/usr/bin/env python3
import subprocess
import re
import time
import sys
from datetime import datetime
from collections import defaultdict

class ARPProtector:
    def __init__(self, trusted_macs_file='trustedmacs.txt'):
        self.trusted_macs = self.load_trusted_macs(trusted_macs_file)
        self.attack_count = defaultdict(int)
        self.last_clean_time = time.time()
        self.sudo_authenticated = False
        
    def log(self, message):
        """Fast logging"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def load_trusted_macs(self, filename):
        """Load trusted MACs"""
        trusted = set()
        try:
            with open(filename, "r") as f:
                for line in f:
                    mac = line.strip().lower()
                    if re.match(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', mac):
                        trusted.add(mac)
            
            if not trusted:
                self.log("ERROR: No valid trusted MACs found")
                sys.exit(1)
                
            self.log(f"Protecting with {len(trusted)} trusted MAC(s): {', '.join(trusted)}")
            return trusted
            
        except FileNotFoundError:
            self.log(f"ERROR: File '{filename}' not found")
            sys.exit(1)

    def get_arp_table(self):
        """Get ARP table quickly"""
        try:
            result = subprocess.run(['arp', '-a'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=3,
                                  check=True)
            return result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.log(f"ARP read failed: {e}")
            return None

    def parse_arp(self, arp_output):
        """Parse ARP output fast"""
        entries = {}
        for line in arp_output.splitlines():
            match = re.search(r'\?\s+\(([0-9.]+)\)\s+at\s+([0-9a-f:]+)\s+\[ether\]', line)
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                entries[ip] = mac
        return entries

    def authenticate_sudo_once(self):
        """Authenticate sudo once at start to avoid repeated prompts"""
        if self.sudo_authenticated:
            return True
            
        self.log("Authenticating sudo access for ARP protection...")
        try:
            # Test sudo with a harmless command
            result = subprocess.run(['sudo', 'echo', 'sudo authenticated'], 
                                  timeout=30, 
                                  check=True,
                                  capture_output=True)
            self.sudo_authenticated = True
            self.log("Sudo authenticated successfully")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            self.log("ERROR: Sudo authentication failed")
            return False

    def clear_malicious_arp(self, suspicious_ips):
        """Clear multiple ARP entries efficiently"""
        if not suspicious_ips:
            return
            
        cleared_count = 0
        failed_count = 0
        
        for ip in suspicious_ips:
            try:
                # Quick ARP deletion with minimal timeout
                result = subprocess.run(['sudo', 'arp', '-d', ip],
                                      timeout=5,
                                      capture_output=True,
                                      text=True)
                if result.returncode == 0:
                    cleared_count += 1
                    self.attack_count[ip] += 1
                else:
                    failed_count += 1
                    
            except subprocess.TimeoutExpired:
                self.log(f"Timeout clearing {ip}")
                failed_count += 1
            except Exception as e:
                self.log(f"Error clearing {ip}: {e}")
                failed_count += 1

        if cleared_count > 0:
            self.log(f"BLOCKED: Cleared {cleared_count} malicious ARP entries")
        if failed_count > 0:
            self.log(f"WARNING: Failed to clear {failed_count} entries")

    def scan_and_protect(self):
        """Main protection logic - fast scan and immediate action"""
        arp_data = self.get_arp_table()
        if not arp_data:
            return

        current_entries = self.parse_arp(arp_data)
        suspicious_ips = []
        trusted_count = 0

        # Quick analysis
        for ip, mac in current_entries.items():
            if mac in self.trusted_macs:
                trusted_count += 1
            else:
                suspicious_ips.append(ip)
                if self.attack_count[ip] == 0:  # First time seeing this
                    self.log(f"THREAT DETECTED: {ip} -> {mac} (not in trusted list)")

        # Immediate action on threats
        if suspicious_ips:
            self.clear_malicious_arp(suspicious_ips)
        
        # Status update
        if len(current_entries) > 0:
            threat_ratio = len(suspicious_ips) / len(current_entries)
            if threat_ratio > 0.5:
                self.log(f"HIGH ALERT: {len(suspicious_ips)}/{len(current_entries)} entries are suspicious!")
            elif suspicious_ips:
                self.log(f"Active protection: {len(suspicious_ips)} threats blocked, {trusted_count} trusted")
            else:
                # Only log clean status occasionally to reduce noise
                current_time = time.time()
                if current_time - self.last_clean_time > 120:  # Every 2 minutes
                    self.log(f"Network clean: {trusted_count} trusted devices")
                    self.last_clean_time = current_time

    def run_protection(self, scan_interval=15):
        """Main protection loop"""
        self.log("Starting ARP spoofing protection...")
        
        # Authenticate sudo once at startup
        if not self.authenticate_sudo_once():
            sys.exit(1)

        scan_count = 0
        try:
            while True:
                scan_count += 1
                self.scan_and_protect()
                
                # Adaptive sleep - scan faster if under attack
                total_attacks = sum(self.attack_count.values())
                if total_attacks > 10:
                    sleep_time = max(5, scan_interval // 2)  # Scan faster under attack
                    if scan_count % 10 == 0:
                        self.log(f"Under attack mode: {total_attacks} total blocks")
                else:
                    sleep_time = scan_interval
                
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            self.log("Protection stopped by user")
            if sum(self.attack_count.values()) > 0:
                self.log(f"Session summary: Blocked {sum(self.attack_count.values())} attack attempts")

def main():
    if len(sys.argv) > 1:
        trusted_file = sys.argv[1]
    else:
        trusted_file = 'trustedmacs.txt'
    
    protector = ARPProtector(trusted_file)
    
    # Allow custom scan interval
    scan_interval = 15  # Default 15 seconds
    if len(sys.argv) > 2:
        try:
            scan_interval = int(sys.argv[2])
            if scan_interval < 5:
                print("Minimum scan interval is 5 seconds")
                scan_interval = 5
        except ValueError:
            print("Invalid scan interval, using default 15 seconds")
    
    protector.run_protection(scan_interval)

if __name__ == "__main__":
    main()