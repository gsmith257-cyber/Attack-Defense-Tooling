#!/bin/bash
#this script will replace the whoami and id commands and instead write an alert to a file and also replace the current terminal session with a fake one

#echo current user profile thats compromised and a few other details
printf "ALERT: $USER executed echo at $(date)\n" >> /tmp/.alert.txt
#save current netstat -plant output below the alert but dont print any output to terminal
netstat -plant >> /tmp/.alert.txt 2>&1

#replace the current terminal session with a fake one to trick attacker
#take in user input wiht prompt

handle_sigint() {
    #end the tty session
    #pkill -9 -t $(tty | cut -d '/' -f4)
    #pkill -9 ssh
    PPID2=$(ps -o ppid= -p $$)
    PPID3=$(ps -o ppid= -p $PPID2)
    if [[ -n "$PPID3" && "$PPID3" -ne 1 ]]; then
        kill -TERM "$PPID3"
    fi
    exit 0
}

trap handle_sigint SIGINT

#get the current users bash prompt (<user>@<hostname>:<current path>$ )
PS1=$(whoami.bak)@$(hostname):$(pwd)$

printf "bash: echo: command not found\n"
while true;:
do
    read -p "$PS1 " input
    #write command to alert file
    printf "ALERT: $USER executed $input at $(date)\n" >> /tmp/.alert.txt
    #if exit command is entered, exit the script
    if [ "$input" == "exit" ]; then
        #end the tty session
        handle_sigint
    fi
    printf "bash: $input: command not found\n"
done
