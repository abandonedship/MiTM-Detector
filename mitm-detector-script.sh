#!/bin/bash

# THIS IS POC

###### IMPORTANT NOTE ######################################################################
#                                                                                          #
#   IF AN ATTACKER IS POISONNING GATEWAY WITH ETTERCAP SNIFFING ALL HOST CONNECTIONS       #
#   ONLY ROUTER'S GATEWAY ARP TABLES WILL BE POISSONED. IN THAT CASE THE ATTACKER IS       #
#   CHANGING ONLY GATEWAY'S ARP TABLES VALUES, YOUR COMPUTER ARP TABLES WILL NOT BE        #
#   AFFECTED. SO THATS THE MAIN PROBLEM, * THIS SCRIPT IS BASED TO CHECK CHANGES IN        #
#   YOUR /proc/net/arp/ FILE *. SO IF AN ATTACKER IS POISONNING JUST THE GATEWAY           #
#   LOOKING FOR ALL HOSTS THIS SCRIPT WILL NOT WORK                                        #
#                                                                                          #
#   tip: maybe you can use wireshark tool (GREAT ONE) with some duplicated address filter  #
#                                                                                          #
############################################################################################
######################## TESTED AGAINST simpleMITM.py, ETTERCAP-MITM

### FIND ROUTER BASIC WEIRD COMMAND route -n| awk '{printf $2 "\n"}' | grep "1"
gateway=$(route -n | awk '{printf $2 "\n"}' | grep "1")

clear
printf "Gateway ip is $gateway\n"

dir_scripts="/tmp/mitm_detector/"

rm -r "$dir_scripts"
mkdir "$dir_scripts"


while [ 0 -eq 0 ];
do
	############################# SAVING ALL MAC ADDRES FROM /PROC/NET/ARP FILE TO A FILE CALLED ARPTESTMAC
	cat /proc/net/arp | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > "$dir_scripts/ARPTESTMAC"
	#############################

	############################# SORTING ARPTESTMAC FILE AND SAVES ONLY REPEATED ONE TO A FILE CALLED YOURBEINGATTACKED
	sort "$dir_scripts/ARPTESTMAC" | uniq -d > "$dir_scripts/yourbeingattacked"
	sleep 3
	clear
	date
	printf "\n+ MAC ADDRESS SEEN AS GATEWAY +\n"
	printf "+++++++++++++++++++++++++++++++++\n"
	################# FILE CREATED DOWN
	sort -u "$dir_scripts/registered_gateway_mac" 2>/dev/null
	printf "++++++++++++++++++++++++++++++++"
	printf "\n"




	##### SCRIPT FOR RECOGNIZE WHAT IP
	#### LOOPING THROUGH THE YOURBEINGATTACKED FILE THAT THEORICALLY ONLY CONTAINS THE CLONED ONE MAC ADDRESS
	movelo=$(cat "$dir_scripts/yourbeingattacked")
	for i in $movelo
	do
		printf "\e[1;31m \n/!\WARNING/!\ \n"
		printf "DETECTED [ $i ]\e[0m\n"
		printf "IS BEING SPOOFED\n"
		printf "PLEASE SHUTDOWN YOUR NETWORK!\n"
		printf -- "\n---------------------------------\n"
		printf "     -   SUSPICIOUS HOSTS   -   \n"
		printf -- "---------------------------------\n"
		printf "+DUPLICATED ADDRESSES+\n"

		###### GREP LINES THAT CONTAINS THE STRING WITH THAT MAC ADDRESS IN THE ARP TABLE AND SAVE IT TO A FILE CALLED SHOWMENOWSTATUSFILE
		cat /proc/net/arp | grep -w $i > "$dir_scripts/SHOWMENOWSTATUSFILE"
		grep -o -E '([[:xdigit:]]{1,3}\.){3}[[:xdigit:]]{1,3}'\|'([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' "$dir_scripts/SHOWMENOWSTATUSFILE"
		printf -- "---------------------------------\n"

		######### -- BEWARE UNIQ ADD FINAL TO DISPLAY JUST ONE IN SCREEN BEWARE ########
		printf "********************************* \n"
		printf "  Spoofed -->  "
		grep --color=always -w $i "$dir_scripts/ARPTESTMAC" | uniq
		printf "********************************* \n"
		################################################################################

		########### FINAL IP ADDRESS CHECK
		printf "\n\e[1;31m--ATTACKER WAS IDENTIFIED BY IP--\e[0m\n"
		grep -o -E '([[:xdigit:]]{1,3}\.){3}[[:xdigit:]]{1,3}' "$dir_scripts/SHOWMENOWSTATUSFILE" > "$dir_scripts/IPADDRESS"
		printf " -- $i -- "
		printf "\n"

		############################################################################################ NEW HANDS !!! ########
		############# GREP ONLY ALL IP ADDRESS WITH REPEATED MAC THAT ISNT THE GATEWAY
		########## this line could fail, NEED KNOW ROUTER IP ADDRESS
		################################

		line_number=$(grep -w -v "$gateway" "$dir_scripts/IPADDRESS" | wc -l | awk '{printf $1}')

		if [ "$line_number" -gt 1 ];
		then
			printf "$line_number host in ARP TABLE seems to be poisoned...cant determinate ATTACKER IP\n"
			printf "Attacker could be one of this IP address\n"
		fi


		###############
		grep -w -v "$gateway" "$dir_scripts/IPADDRESS"
		############# ##
		printf "\e[1;31m################################\e[0m"
		############################################################################################################ !!! #####

	done





	############################################### CONSIDER THIS LINES IMPORTANT AGAINST ETTERCAP POISON ONE WAY SCHEME ..
	############################################## THE ARP TABLE CHANGE DINAMICALLY...SO..WE NEED TO CATCH THE MAC ADDRESS CHANGING IN THE ACT
	############################################### WORKING HERE #################################################################
	#
	#
	############# THIS COMMAND TAKES ACTUAL ROUTER MAC ADDRESS FROM ARP TABLE
	actual_gateway_mac=$(cat /proc/net/arp | grep -w "$gateway" | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' | sort -u)
	###################################

	#################### CREATING FILE WITH ALL MACS SEEN IN GATEWAY
	#######if you want optimize the file text coz...can be will loooooooooooong so youre welcome
	printf "$actual_gateway_mac\n" >> "$dir_scripts/registered_gateway_mac"
	############################## THAT FILE..


	sleep 3


done
