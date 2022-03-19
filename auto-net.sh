#!/bin/bash -x
#
# This code uses the VMWare parameters for retrieving host information and configuring the machines thereafter, grabbing an IP and enabling 
# central authentication in the process.  What is checked, or done:
#
#	- Check DNS servers to verify if an IP is taken. 
#	- Check if IP is pingable.
#	- Check if IP exists in the specified DNS server list.
#
# If IP checks pass, the IP is assigned to this VM.
#
#
# Contributors / Authors:
# 
# 	Tom Kacperski
#
#

# LAB DNS List
LDNS=( 192.168.0.224 192.168.0.44 192.168.0.45 192.168.0.154 192.168.0.155 );

INTNAME="ens192";

NDOMAIN="nix.mds.xyz";
IPA01="idmipa01";
IPA02="idmipa02";
UNDOMAIN=${NDOMAIN^^};					# Uppercase the domain.
NCPATH="/etc/sysconfig/network-scripts";


# Network Interface Config Template
IFCFG_T="$NCPATH/ifcfg-$INTNAME-template";
IFCFG_C="$NCPATH/ifcfg-$INTNAME";
IFCFG_TB=$(basename $IFCFG_T);

# KRB5 Configuration Files
KRB5_T="/etc/krb5.conf-template";
KRB5_C="/etc/krb5.conf";

IPSUBNET=192.168.0.0/24;
IPRANGE="192.168.0.100-192.168.0.255";

# DHCP Client specific configuration parameter.
PATH_DHCLIENT_CONF=/etc/dhcp/dhclient.conf;

RETRIES=20;				# Number of times to try to get a unique IP.

TMPIP="/tmp/.eDrsldDI.tmp";
CONFIGFILE="./auto-net.conf";
USERCONFIGFILE="";

# SSSD Config files
SSSDP_C=/etc/sssd/sssd.conf;
SSSDP_T="$SSSDP_C-template";

# SSHD Config files
SSHD_C="/etc/ssh/sshd_config";
SSHD_T="/etc/ssh/sshd_config-template";

IPACLIENTCREDFILE="/tmp/ipa-client-credentials";

# Systemd config.
SYSDAUTONET="/etc/systemd/system/auto-net.service";


usage() {
	echo "Usage: $0 [-n <"NS LIST"> ] [-d "<DOMAIN>" ]" 1>&2;
	exit 1;
}

# Setup flag:
ISSETUP=false;

# If parameters are specified, they'll overwrite the above defaults.
while getopts ":n:d:p:b:r:c:s" ARG; do
    case "${ARG}" in
        n)
            LDNS=( ${OPTARG} );
            ;;
        d)
            NDOMAIN=${OPTARG}
	    UNDOMAIN=${NDOMAIN^^};                                  # Uppercase the domain.
            ;;
        p)
            IPA01=${OPTARG}
            ;;
        b)
            IPA02=${OPTARG}
            ;;
        r)
            IPSUBNET=${OPTARG}
            ;;
        c)
            USERCONFIGFILE=${OPTARG}
            ;;
        s)
            ISSETUP=true
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))


# ------------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------------
function compare-config ( ) {
        cc-msg=$1;
	cc-template=$2;
	cc-target=$3;

	echo "$cc-msg, $cc-template, $cc-target";
}


# Source the config file only if a user provided config file was not provided on the command line.
if [[ -r $CONFIGFILE && $USERCONFIGFILE != "" && ! -r $USERCONFIGFILE ]]; then
    echo "Using default config file: $CONFIGFILE";
    . $CONFIGFILE;
elif [[ -r $USERCONFIGFILE ]]; then
    . $USERCONFIGFILE; 
else
    echo "No proper config file specified.  Using script defined defaults.";
fi

# ------------------------------------------------------------------------------------
# Configure the templates if missing.
# ------------------------------------------------------------------------------------

compare-config ( "NIC Card Template missing", $IFCFG_TB, $IFCFG_T );

# NIC card.
if [[ ! -r $IFCFG_T ]]; then
	echo "NIC Card Template missing. Copying $IFCFG_TB to $IFCFG_T.";
	/bin/cp $IFCFG_TB $IFCFG_T;
else
	if [[ -r $IFCFG_TB ]]; then
		echo "File $IFCFG_T existed. Comparing to the templates.  If different, $IFCFG_T will be updated.";

		# Comparing template NIC card.
		if diff $IFCFG_T $IFCFG_TB; then
			/bin/cp $IFCFG_TB $IFCFG_T;
		else
			echo "Files $IFCFG_TB and $IFCFG_T were the same.  Skipping copy.";
		fi
		
	else
		
		echo "ERROR: No network configuration files found in the ./templates/$(basename $IFCFG_T) folder. Exiting.";
		exit 1;
	fi
fi
exit 0;


# SSSD Config File: File will be auto copied if missing.

# KRB5 Configuration Files
if [[ ! -r $KRB5_T ]]; then
	echo "KRB5 Config Template missing. Copying $KRB5_T config file to the /etc/ folder.";
	/bin/cp ./templates/$(basename $KRB5_T) $KRB5_T;
else
	echo "ERROR: No KRB5 config file found in the templates folder.  Please create one before running the script once more."
	exit 1;
fi


# SSHD Config Files
if [[ ! -r $SSHD_T ]]; then
	echo "SSHD Config Template missing. Copying $SSHD_T config file to the /etc/ folder.";
	/bin/cp ./templates/$(basename $SSHD_T) $SSHD_T;
else
	echo "ERROR: No SSHD config file found in the templates folder.  Please create one before running the script once more.";
	exit 1;
fi


# Systemd Auto Net startup script.
if [[ ! -r $SYSDAUTONET ]]; then
	echo "Systemd Auto Net startup file was missing.  Copying $(basename $SYSDAUTONET) to $SYSDAUTONET .";
	/bin/cp ./templates/$(basename $SYSDAUTONET);
	systemctl enable @SYSDAUTONET;
	systemctl daemon-reload;

else
	echo "ERROR: No Systemd template found.  Please create one before running the script once more.";
	exit 1;
fi


# Exit if only a setup is required.
if [[ $ISSETUP == "true" ]]; then
	echo "NOTE: Setup specified.  Exiting since ony setup required.  Not configuring system.";
	echo "IMPORTANT: Don't forget to set a password in $IPACLIENTCREDFILE file. Otherwise SSSD won't bind with Free IPA.";
	exit 0;
else
	echo "Setup (ISSETUP) was set to false, meaning configuration of this system will commence.";
fi

# ------------------------------------------------------------------------------------



# Variables you've used are going to be printed below.
echo "Variables you've used are: $NDOMAIN $UNDOMAIN $IPA01 $IPA02";

for ITM in "${LDNS[@]}"; do
	echo $ITM;
done


# Exit if we don't see $INTNAME.  
[[ $( ip a | grep -Ei "$INTNAME" ) == "" ]] && {
	echo "ERROR: This client doesn't have an $INTNAME NIC.  Script limited to clients with $INTNAME interface only.";
        exit 0;
}


# Setting dhclient.conf file for fast IP expiration in an attempt to induce assignment of unique IP's from the DHCP server.
cat > $PATH_DHCLIENT_CONF << DHCLIENT-END
supersede dhcp-lease-time 5;
supersede dhcp-rebinding-time 5;
supersede dhcp-renewal-time 5;
DHCLIENT-END



# We will only care about the first IP we retrieve from dhclient, since it can assign more then one.
# If it's able to assign more then one, then we are not dealing with a new build.  In this case,
# the script will exit indicating we've already built this host.
# New builds will get a new MAC address and when they do, a single new IP is generated.
# NOTE: This depends on the network NIC having NO IP on the template only.


# Plan B:  This is the NMAP method of getting and assigning IP's if DHCPD fails.  The function also checks the defined DNS list to ensure
# none of the returned IP's have a DNS value.
function nmap-subnet () {
	# If you're here, DHCPD has failed to get a unique IP that isn't listed in one of the DNS servers.  So we'll sniff for one.

	# We need to be on the network before NMAP can get a list of available IP's.  This IP will only be temporarilly assigned.
	dhclient -r; dhclient -x; dhclient -v;

	NMAPTMP="/tmp/.dkdiISKDJwjsdw.tmp";
	nmap -v -sn -n $IPSUBNET -oG -|awk '/Down/ { print $0; }' > $NMAPTMP;


	# Exit if not on the network.
	if grep -Ei "failed to determine route to" $NMAPTMP; then
		echo "ERROR: Found \"failed to determine route to\" in $NMAPTMP.  This typically means we're not on the network.";
		echo "ERROR: We need to be on the network via a temporary IP to run nmap.  Exiting as a result.";
	fi


	# Convert the IP Range to intigers for comparison.
	MINIP=$( echo "$IPRANGE" | awk -F"-" '{ print $1 }' |  awk '{ gsub(/\./,"", $0); print $0;}' );
	MAXIP=$( echo "$IPRANGE" | awk -F"-" '{ print $2 }' |  awk '{ gsub(/\./,"", $0); print $0;}' );


	# Cycle through nmap listed IP's.  Ensure it's not assigned in the DNS.  Return with a valid IP.
	for IPENTRY in $( cat $NMAPTMP | awk '{ print $2 }' ); do

		# Convert the new IP to an integer.  Compare to the MIN and MAX.
		NMAPIP=$( echo "$IPENTRY" | awk '{ gsub(/\./,"", $0); print $0;}' );

		# If no IP is up, exit and print a message indicating as such.
		if [[ -z $NMAPIP ]]; then
			echo "ERROR: Couldn't find a single IP on the IP Range $IPRANGE.";
			exit 0;
		fi


		# If IP is not in range, go back to the top of the loop to get another IP.
		if [[ $NMAPIP -lt $MINIP || $NMAPIP -gt $MAXIP ]]; then 
			continue;
		fi


		# Check the defined list of DNS servers.  Maybe IP is assigned to a server in the DNS.
		DNSLOOK="";
		for _ITM in "${LDNS[@]}"; do

			DNSLOOK=$( dig -x $IPENTRY @$_ITM | grep -EA1 "ANSWER SECTION"|awk /PTR/'{ print $NF; }' | grep -v PTR );

			# Break loop if IP is assigned in the DNS.  No need to check further.
			[[ $DNSLOOK != "" ]] && break;
	
		done


		# Exit if we found a unique IP. Otherwise continue with the loop to find another IP.  Getting here ensures this.
		[[ -z "$DNSLOOK" ]] && {
			break;
		}

	done


	# If DNSLOOK is not empty, it means we did not find a valid IP.  Print a message indicating so.
	if [[ ! -z "$DNSLOOK" ]]; then
		echo "ERROR: We could not find any IP that was not already assigned.  Verify using nmap and your local DNS if any IP's are left on this subnet. ";
		exit 0;
	fi


	echo "RETV: $NMAPIP";
}



# TEST ONLY
# RETV=$( nmap-subnet | awk '/RETV: /{ print $2; }' );
# echo $RETV;
# exit 0;

IPCNT=0;
while [[ true ]]; do

	# Exit or end any dhclients already running in memory.
	dhclient -r; dhclient -x;

	# Remove the leases file to guarantee we will get a unique IP address on another attempt.
	rm -f /var/lib/dhclient/*leases;

	# Determine if we have a 1) temporary IP assigned, 2) our hostname contains 'template' in the name.
	EIPADDR=$(ip a|awk -v intname=$INTNAME '{
	        if ( $0 ~ /"'"$INTNAME"'"/ )
	                ETH=1;
	        if ( $0 ~ /inet [0-9]/ && ETH == 1 ) {
	                gsub (/\/.*/, "", $0 );
	                print $2;
	                ETH=0;
	        }}'|head -n 1);

	# Retrieve the temporary IP address set on the template.
	TIPADDR=$( grep -Ei 999 $IFCFG_T | grep IPADDR );


	#
	# If a) our temporary address is assigned or 
	#    b) temporary NIC config (IFCFG_T) is not empty (meaning host config was not completed) or
	#    c) there is no IP assigned and and the hostname contains 'template'
	# then attempt to get another IP. 
	#
	[[ ( ! -z $TIPADDR || -r $IFCFG_T )  || ( -z $EIPADDR && $(hostname|grep -Ei "template") != "" ) ]] && {

		# Logic below impeded unique IP assignment.  Removing for now.
	        # ifdown $INTNAME;
		# rm -f /var/lib/dhclient/*leases;
		# ifup $INTNAME;

		echo "PATH_DHCLIENT_CONF = $PATH_DHCLIENT_CONF";
		dhclient -v;				# <-------------------<  HERE HERE <-------------------<
	} || { 
		echo "WARNING: Looks like host already had an IP address so must be on the network.  Not running dhclient again."; 
	};

	# Get the IP address assigned to $INTNAME by dhclient above. 
	IPADDR=$(ip a|awk '{
	        if ( $0 ~ /"'"$INTNAME"'"/ )
	                ETH=1;
	        if ( $0 ~ /inet [0-9]/ && ETH == 1 ) {
	                gsub (/\/.*/, "", $0 );
	                print $2;
	                ETH=0;
	        }}'|head -n 1);

	# If IPADDR is empty, exit.  We should have gotten an IP by now or something else went wrong and we should exit.
	echo "IPADDR = |$IPADDR|";
	[[ -z $IPADDR ]] && {
		echo "ERROR: No IP can be derived after running dhclient.  DHCPD is down?  Increase DHCPD timeouts? Exiting.";
		exit 0;
	}


	# Check if the IP is already taken on one of the DNS servers.  If it is, attempt to get a new one.
	FNDONE="";
	for ITM in "${LDNS[@]}"; do

		FNDONE=$( dig -x $IPADDR @$ITM | grep -EA1 "ANSWER SECTION"|awk /PTR/'{ print $NF; }' | grep -v PTR );

		[[ $FNDONE != "" ]] && break;

	done


	# Don't proceed further (continue) if IP is taken. Attempt to get another IP by running above logic again up to $IPCNT times.
	if [[ $FNDONE != "" ]]; then

		# Count number of failed attempts to get a valid IP.
		IPCNT=$(( $IPCNT + 1 ));

		# Give up after $RETRIES tries.
		if [[ $IPCNT -ge $RETRIES ]]; then
			echo "FATAL: Exiting.  Tried to get a unique IP $IPCNT times but failed each time.  Maybe you're out of IP's?";
			IPADDR="";
			# break;
		else

			# Sleep a bit if we still can't get an IP after 5 tries.
			if [[ $IPCNT -ge 3 ]]; then
				dhclient -r; 
				dhclient -x;

				# Logic below actually impeded unique IP assignment.  Removing for now.
				# rm -f /var/lib/dhclient/dhclient.leases;

				# Sleep longer if we're cycling through the same set of IP(s) .
				if [[ -r $TMPIP && $( grep -Ei "${IPADDR}" $TMPIP ) != "" ]]; then
					sleep 10;
				else
					sleep 5;
				fi
			fi

			# Save invalid IP in a text file for future lookup.
			echo $IPADDR >> $TMPIP;

			continue;
		fi

	fi


	# If we got here and have no IP address, try the NMAP method.
	if [[ -z "$IPADDR" ]]; then
                if [[ $(which nmap) == "" ]]; then
                        echo "WARNING: nmap not found.  Installing nmap and netcat for required network tools.";
			yum install nmap netcat nmap-netcat -y
                fi
		RETV=$( nmap-subnet | awk '/RETV: /{ print $2; }' );
		IPADDR = $RETV;
	fi


	# If we still have no IP, exit.
	if [[ -z "$IPADDR" ]]; then
		exit 0;
	fi


	echo "Unique IP: $IPADDR";

	# Get the new hostname defined in the VM properties.
	NHOSTNAME=$(vmtoolsd --cmd 'info-get guestinfo.ovfEnv'|awk '{
	        if ( $0 ~ /GuestHostname/ ) {
	                gsub(/.*oe:value="/, "", $0 );
	                gsub (/"\/>/, "", $0 );
	                print;
	        }}');

	# Check that we actually got a hostname from the VM.  Exit if we didn't.
	[[ $NHOSTNAME == "" || $( echo "$NHOSTNAME" | grep -Ei "template" ) != "" ]]  && { 
		echo "ERROR: Hostname is still set to something with word template in it or it is blank.  In other words, could not get hostname using vmtoolsd from the Options - Properties - GuestHostname variable of the VM.  Exiting.";
		exit 0;
	} || {
		echo "Hostname: $NHOSTNAME , IP Address: $IPADDR";
	}

	# Exit if no hostname was defined on the VM.
	[[ -z "$NHOSTNAME" ]] && { 
		echo "ERROR: Hostname returned from vmtoolsd was empty.";
		exit 0;
	}

	# Create the static configuration file ifcfg-$INTNAME using the 1) IP and 2) hostname derived above.
	awk 'BEGIN {
	                IPADDR="'"$IPADDR"'";
	                NHOSTNAME="'"$NHOSTNAME"'";
	                NDOMAIN="'"$NDOMAIN"'";
	        } {
	                if ( $0 ~ /IPADDR/ ) {
	                        $0="IPADDR="IPADDR;
	                }

	                if ( $0 ~ /HOSTNAME/ ) {
	                        $0="HOSTNAME="NHOSTNAME"."NDOMAIN;
	                }
	                print $0;
	        }' < $NCPATH/ifcfg-$INTNAME > $NCPATH/ifcfg-n-$INTNAME;

	# -------------------------
	# In the ifcfg-$INTNAME a few things are done.
	# 1) PEERDNS=no  -  This causes many extra nameservers to be added to /etc/resolv.conf.  Need to disable this or it will
	#                   affect if we can ssh between hosts using the short names after we are added to FreeIPA / KDC.
	# 

	IPAEXISTS=$(dig -x $IPADDR | grep -Ei "PTR"|grep -Evi "^;"|awk '{ print $NF }'|sed -e "s/[.]$//g")
	HOSTEXISTS=$( hostnamectl | grep -Ei "$NHOSTNAME[.]$NDOMAIN" );
	if [[ $IPAEXISTS != "" || $HOSTEXISTS != "" ]]; then
		echo "ERROR: This hosts hostname matches it's intended future name, therefore no change is needed.";
		rm -f $NCPATH/ifcfg-n-$INTNAME;

		if echo "$HOSTEXISTS" | grep -Ei template 2>&1 >/dev/null; then
			echo "ERROR: This hosts hostname contains the word 'template' which matches it's intended name.  Exiting as a result since we consider this host as complete in this scenario.";
			exit 0;
		fi
	else
		break;
	fi

done


# ------------------------------------------------------------------------
#
# Ok, let's do it!
#
# ------------------------------------------------------------------------
echo "Ok, we're going to do a bunch of changes to the system.  You have 5 seconds to backout by pressing CTRL + C to get out.";


if [[ $APPLYCONFIG == "true" || $APPLYCONFIG == "yes" ]]; then
	echo "NOACT: Not applying config as per the config file setting parameter APPLYCONFIG ($APPLYCONFIG).";
	exit 0;
else
	sleep 5;
fi


cp -p $NCPATH/ifcfg-$INTNAME $NCPATH/_ifcfg-$INTNAME-backup-$(date +%s);
mv $NCPATH/ifcfg-n-$INTNAME $NCPATH/ifcfg-$INTNAME;

dhclient -r; dhclient -x;
hostnamectl set-hostname $NHOSTNAME.$NDOMAIN;
systemctl restart network;

[[ $(rpm -aq|grep -Ei ipa-client) == "" ]] && yum install ipa-client -y;
[[ $(rpm -aq|grep -Ei authconfig) == "" ]] && yum install authconfig -y;

yum update ipa-client -y;
yum update authconfig -y;
yum update sssd -y;


# Check if temporary password file exists with our credentials.  Exit if not.
[[ ! -r $IPACLIENTCREDFILE ]] && {
	echo "ERROR: Temporary pass file is missing.  Recreate it and place the IPA password in it.  Check the script for the file name."
	exit 0;
}


# Get temp pa$$.
TMPP=$(cat $IPACLIENTCREDFILE);

ipa-client-install --uninstall;
ipa-client-install --force-join -p autojoin -w "$TMPP" --fixed-primary --server=$IPA01.$NDOMAIN --server=$IPA02.$NDOMAIN --domain=$NDOMAIN --realm=$UNDOMAIN -U

authconfig --enablesssd --enablesssdauth --enablemkhomedir --updateall --update;

echo "Checking for the krb5.conf template file.  If one exists, I'm going to reconfigure the host one to use the template.";
[[ -r $KRB5_T ]] && {
        cp -p $KRB5_C ${KRB5_C}-backup-$(date +%s);
        cat $KRB5_T | sed -e "s/TEMPLATE-HOSTNAME.*=/$(hostname) =/g" > $KRB5_C;
}

# Modify SSHD accordingly.
[[ -r $SSHD_T ]] && {
	# Need two settings here.  See this page: http://microdevsys.com/wp/getting-asked-for-when-using-host-shortname-with-kerberos-delegation/
	cp -p $SSHD_T $SSHD_C;
}

# Sync up the time.  If we don't, ssh to other servers won't work well.
ping -c 1 $IPA01 >/dev/null 2>&1 && { ntpdate -u $IPA01; } || { ntpdate -u $IPA02; };
hwclock --adjust;

# Add auto mount for NFS home directories.
ipa-client-automount --location=UserHomeDir01 -U

# Copy the template over the sssd.conf file in the event the package installer nukes the files.
[[ ! -r $SSSDP_C ]] && /usr/bin/cp $SSSDP_T $SSSDP_C;

# Adjust SSSD home directories and some DNS and LDAP values.
cat > sssd-updates.txt <<SSSD-END
dyndns_update = True
dyndns_update_ptr = True
ldap_schema = ad
ldap_id_mapping = True

override_homedir = /n/%d/%u
# fallback_homedir = /n/%d/%u
# ldap_user_home_directory = unixHomeDirectory
SSSD-END

[[ $(grep -Ei "dyndns_update = True|dyndns_update_ptr = True|ldap_schema = ad|ldap_id_mapping = True|override_homedir = /n/%d/%u" $SSSDP ) == "" ]] && {
        awk 'BEGIN {
                STAG="";
        }
        {
                if ( $0 ~ /\[sssd\]/ ) {
                        DZERO=$0;
                        while(getline<"sssd-updates.txt") {
                                print;
                        };
                        print "";
                        print DZERO;
                } else {
                        print;
                }
        }' < $SSSDP_C > $SSSDP_C-new;
        /usr/bin/mv $SSSDP_C-new $SSSDP_C;
	chmod 600 $SSSDP_C;
        systemctl restart sssd;
} || {
        echo "DONE: Nothing to update. Values dyndns_update = True|dyndns_update_ptr = True|ldap_schema = ad|ldap_id_mapping = True|override_homedir = /n/%d/%u already in file.";
}

# Remove the password file once we are done connecting this host to FreeIPA / IDM.
echo "$HOSTNAME" | grep -Eiv "template" >/dev/null 2>&1 && id tom@mds.xyz >/dev/null 2>&1 && rm -f /tmp/.resolv.conf.swp;

# Give some indication that this script was executed and completed.
echo "$(date +%s): COMPLETE: auto-net.sh was fully executed.  About to reboot the machine." >> /tmp/auto-net.sh.log

rm -f $IFCFG_T;

# Clean up this boot script.
rm -f /etc/dhcp/dhclient.conf
rm -f /etc/sysconfig/network-scripts/auto-net.sh

# Reboot the server to take all changes into effect and start up cleanly after all changes.
reboot;


