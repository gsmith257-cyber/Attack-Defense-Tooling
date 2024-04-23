# Attack-Defense-Tooling
Attack &amp; Defense CTF Tooling created for NSA Cyber Exercise (NCX)

## Below here is README I created for NCX

# NCX CCE 2024 Tooling

## Table of Contents

- [NCX CCE 2024 Tooling](#ncx-cce-2024-tooling)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
  - [Usage](#usage)
    - [1.1. Talon](#Talon)
    - [1.2. Talon Handler](#Talon-Handler)
    - [1.3. Playbook](#Playbook)
    - [1.4. Pwn4All](#Pwn4All)
    - [1.5. Alert Scripts](#Alert-Scripts)
  - [Contributing](#contributing)
  - [License](#license)

## Introduction

This repository contains the tooling for the NCX 2024 Cyber Combat exercise competition. The tools are designed to be used in a controlled environment and should not be used in any other setting.
These tools have been tested on the TestEnvironment provided in the `2024/TestEnvironment` directory.

## Installation

To install the tools, clone the repository and navigate to the `2024` directory.

For during NCX simply copy and paste the code into the terminal while editing in vim or nano and save to a file. (You may need to chunk the code into smaller pieces)

## Usage

### Talon

Talon is a multithreaded reverse shell handler that listens for incoming connections from compromised machines. It is designed to be run on the attack machines.

**If machine resets are allowed make sure to edit the script to also allow root login on machines through the ssh config persistance or they will just reset**

Once Talon receives a connection it will follow these steps:
1. Check if the connection is from an IP on the blacklist.
2. Attempt to verify that it is a reverse shell by executing `which <insert binary>` and checking the output to see if it is the expected binary path. If not it will close the connection and after failed attempts from same IP it will add the IP to the blacklist.
3. If the connection is verified as a reverse shell, it will attempt to stabalize the shell using python.
4. Once stabalized, it will establish OPSEC by:
    - Unsetting the HISTFILE
    - Clearing the history
    - Linking the history to /dev/null
    - Clearing auth.log
    - Linking auth.log to /dev/null
    - Clearing syslog, kern.log, and lastlog
5. It will then use pythons ssl library to encrypt the connection and send so commands can be executed securely.
6. From there it will run any exploit and/or privesc that the user has defined in the code. (It is blank by default)
7. Now it will start persistance:
    - Adds cronjobs in /etc/crontab and session crontab to run rev shells to talon handler every 2 minutes.
    - Adds backdoors to only allow games and news users to ssh in.
    - Adds passwords and auth keys to games and news users and sets login to /bin/bash.
    - Backdoors the cat binary to call a reverse shell back to talon handler each time its executed.
    - Adds backdoor to ~/.bashrc to call a reverse shell back to talon handler each time a new shell is opened.
    - Attempts to add custom chattr (likely will fail)
    - Backdoors the `cat` command to call a reverse shell back to talon handler each time it is executed, along with executing cat like normal.
    - **If** a webserver is detected it will attempt to add a php "webshell" that when called will write IOC to IOC location and also display flags. This will be located at `/index.bak.php`
8. Now it will plant the IOC on the system and save all flags set in the code to the designated flag location. (default: `/var/tmp/info/<hostname>`)

### Talon Handler

Talon Handler is a multithreaded listener that listens for incoming connections from compromised machines. It is designed to be run on the attack machines.

Once Talon Handler receives a connection it will follow these steps:
1. Check if the connection is from an IP on the blacklist.
2. Attempt to verify that it is a reverse shell by executing `which <insert binary>` and checking the output to see if it is the expected binary path. If not it will close the connection and after failed attempts from same IP it will add the IP to the blacklist.
3. If the connection is verified as a reverse shell, it will attempt to stabalize the shell using python.
4. Once stabalized, it will establish OPSEC by:
    - write IOC to IOC location
    - Save flags using the harded coded flag location to `/tmp/flags.txt`

### Playbook

The playbook is a markdown file that contains the steps that the team should follow to prepare for the attack phase. It is designed to be used as a checklist to ensure that all necessary steps are completed before the attack phase begins.

### Pwn4All

Pwn4All is a script that is designed to be run on the attack machines. It is used to automate the process of launching exploits against the target machines. The script is meant to be customized as needed.

### Alert Scripts

The alert scripts are designed to be used in to replace the whoami, id, and echo binaries on our machines. The scripts will log the user and timestamp to a file when the command is executed along with placing them in a fake shell that seems like it doesnt work and logs their commands.

To see the alerts run `cat /tmp/.alert.txt`

## Contributing

**Reach out to Grant before contributing**



**Chattr taken from [here](https://github.com/fasc8/Chattr-for-KOTH)**
