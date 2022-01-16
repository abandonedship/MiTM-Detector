#!/bin/bash

# THIS IS POC

###### IMPORTANT NOTE ######################################################################
#                                                                                          #
#   IF AN ATTACKER IS POISONNING GATEWAY WITH ETTERCAP SNIFFING ALL HOST CONNECTIONS       #
#   ONLY ROUTER'S GATEWAY ARP TABLES WILL BE POISSONED. IN THAT CASE THE ATTACKER IS       #
#   CHANGING ONLY GATEWAY'S ARP TABLES VALUES, YOUR COMPUTER ARP TABLES WILL NOT BE        #
#   AFFECTED. SO THATS THE MAIN PROBLEM, * THIS SCRIPT IS BASED TO BLOCK THE GATEWAY'S     #
#   SPOOFED CONNECTIONS, RESULTANT IN THIS CASE THAT YOU LOSE THE CONNECTION IF THE        #
#   SCRIPT DETECTS GATEWAY'S ADDRESS SPOOFED. IF YOU ARE SURE IS NOT RECOMMENDED CONNECT   #
#   TO THAT NETWORK...POSSIBLE THAT ATTACKER IS POISSONING JUST ROUTER'S ARP TABLES        #
#                                                                                          #
#   tip: maybe you can use wireshark tool (GREAT ONE) with some duplicated address filter  #
#                                                                                          #
############################################################################################




printf "This program only works if you know gateway REAL mac address\n"
sleep 1
read -p "ENTER ORIGINAL GATEWAY MAC ADDRESS: " original_gateway_mac
printf "Flushin...\n"
########### flushin /proc/net/arp entries
ip -s -s neigh flush all
#########################################
arptables --flush
printf "BLOCKING ALL ARP PACKETS...\n"
arptables -P INPUT DROP
sleep 1
printf "SETTING ORIGINAL GATEWAY MAC AND ACEPTING ONLY HIS ARP PACKETS...\n"
arptables -I INPUT --source-mac "$original_gateway_mac" -j ACCEPT
printf "Done, ARP request that not comming from $original_gateway_mac will be blocked\nIf an attacker was POISONING your ARP table this should stop him\n"
sleep 1
