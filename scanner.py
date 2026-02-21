import socket
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import time

"""
Parses user input and iterates over IP addresses to scan.
Accepts a single IP, a CIDR network block, or a start/end IP range.
"""
def scanner(iplist):
    dic = {}
    if  len(iplist) == 2:
        startip = ipaddress.ip_address(iplist[0])
        endip = ipaddress.ip_address(iplist[1])
        current_ip = startip
        while current_ip <= endip:
            op = port_Reader(current_ip)
            dic[str(current_ip)] = op
            current_ip += 1
    elif len(iplist) == 1:
        try:
            startip = ipaddress.ip_network(iplist[0])
            endip = startip
            for current_ip in startip:
                op = port_Reader(current_ip)
                dic[str(current_ip)]  = op
        except ValueError:
            startip = ipaddress.ip_address(iplist[0])
            endip = startip
            current_ip = startip
            while current_ip <= endip:
                op = port_Reader(current_ip)
                dic[str(current_ip)] = op
                current_ip += 1
    else:
        raise SystemError ("falta ou excesso de atributos")
    return dic

"""
Uses a ThreadPoolExecutor to concurrently scan all 65535 ports on a given IP.
"""
def port_Reader(ip):
    open_ports = []
    list_ports = range(1, 65536)
    port_Conector_static_ip = partial(port_Conector, ip)
    with ThreadPoolExecutor(max_workers=1000) as executor:
        results = list(executor.map(port_Conector_static_ip,list_ports))
    for res in results:
        if res is not None:
            open_ports.append(res)
    return open_ports
"""
Attempts a TCP connection to a specific port. 
Returns the port number if open, otherwise returns None.
"""
def port_Conector(ip,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.05)
    result = s.connect_ex((str(ip),port))
    s.close()
    if result == 0:
        return port
    return None
    
if __name__ == "__main__":
    args = sys.argv[1:]
    start = time.time()
    
    if len(args) == 0:
        print("Usage: python scanner.py <ip_start> [ip_end]")
        print("   or: python scanner.py <network_cidr>")
        sys.exit(1)
        
    try:    
        final_res = scanner(args)
        
        print("\n--- Scan Results ---")
        for ip, ports in final_res.items():
            if ports:
                print(f"[+] IP {ip} has open ports: {ports}")
            else:
                print(f"[-] IP {ip}: 0 open ports found")
                
    except ValueError:
        print("[!] Error: Invalid IP address or network format provided.")
        
    end = time.time()
    print(f"\nExecution Time: {end - start:.2f}s")