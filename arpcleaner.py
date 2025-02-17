import subprocess
import re
import time

def get_arp_table():
    try:
        result = subprocess.run(['arp','-a'],capture_output=True,text=True,check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"error getting ARP table: {e}")
        return None

def get_trusted_macs(filename='trustedmacs.txt'):
    try:
        with open(filename,"r") as f:
            macs = [line.strip() for line in f]
        return macs
    except FileNotFoundError:
        print(f"Trusted MAC address file '{filename}' not found.")
        return []
    
def clear_arp_entry(ip_address):
    try:
        subprocess.run(['sudo','arp','-d',ip_address],check=True)
        print(f"deleted arp entry for {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error deleting ARP entry for {ip_address}: {e}")
        
def main():
    trusted_macs = get_trusted_macs()
    if not trusted_macs:
        return
    while True:  # i will use cron jobs but for now lets use famous while loop
        arp_table = get_arp_table()
        if arp_table:
            for line in arp_table.splitlines():
                match = re.search(r"\((.*?)\) at (.*?) \[ether\]", line)
                if match:
                    ip_address = match.group(1)
                    mac_address = match.group(2)
                    if mac_address not in trusted_macs:
                        clear_arp_entry(ip_address)
        time.sleep(60)

if __name__ == "__main__":
    main()
                
