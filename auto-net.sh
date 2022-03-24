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

# Template Folder
TEMPLATEF="./templates";

# LAB DNS List
LDNS=( 192.168.0.224 192.168.0.46 192.168.0.51 );
STRDNS="192.168.0.224 192.168.0.46 192.168.0.51";


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
KRB5_TB=$(basename $KRB5_T);


IPSUBNET=192.168.0.0/24;
IPRANGE="192.168.0.100-192.168.0.255";

NETGATEWAY="192.168.0.1";
IPNETMASK="24"
NETSEARCH="mds.xyz nix.mds.xyz mws.mds.xyz";
NETDOMAIN="mds.xyz nix.mds.xyz mws.mds.xyz";

# DHCP Client specific configuration parameter.
PATH_DHCLIENT_CONF=/etc/dhcp/dhclient.conf;

RETRIES=5;				# Number of times to try to get a unique IP.

TMPIP="/tmp/.eDrsldDI.tmp";
CONFIGFILE="./auto-net.conf";
USERCONFIGFILE="";

# SSSD Config files
SSSDP_C=/etc/sssd/sssd.conf;
SSSDP_T="$SSSDP_C-template";

# SSHD Config files
SSHD_C="/etc/ssh/sshd_config";
SSHD_T="/etc/ssh/sshd_config-template";
SSHD_TB=$(basename $SSHD_T);

IPACLIENTCREDFILE="/tmp/ipa-client-credentials";

# Systemd config.
SYSDAUTONET="/etc/systemd/system/auto-net.service";

#
OSVERSION=""

function osversion() { 
	grep -Ei "Rocky Linux.*8\." /etc/os-release 2>&1 >/dev/null && { OSVERSION="ROL8"; }
	grep -Ei "CentOS Linux.*7" /etc/os-release 2>&1 >/dev/null && { OSVERSION="COL7"; }
}

osversion;

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


# Change to the executing directory.
CWD=$(pwd);
MOI=$(basename $0);
MOID=$(dirname $0);

cd $MOID || { 
	echo "FAILED to change to $MOID"; 
	exit 0; 
};
NWD=$(pwd);




# ------------------------------------------------------------------------------------
# FUNCTIONS
# ------------------------------------------------------------------------------------
function compare-config () {
        cc_msg="$1";
	cc_template="$2";
	cc_target="$3";

	cc_tfolder="./templates";

	echo "compare-config: $cc_msg, $cc_template, $cc_target";

	# NIC card.
	if [[ ! -r $cc_target ]]; then
		echo "compare-config: $cc_msg. Copying $cc_template to $cc_target.";
		/bin/cp $cc_tfolder/$cc_template $cc_target;
	else
		if [[ -r $cc_tfolder/$cc_template ]]; then
			echo "compare-config: File $cc_target existed. Comparing to the templates.  If different, $cc_target will be updated.";

			# Comparing template NIC card.
			if diff $cc_target $cc_tfolder/$cc_template; then
				/bin/cp $cc_tfolder/$cc_template $cc_target;
			else
				echo "compare-config: Files $cc_template and $cc_target were the same.  Skipping copy.";
			fi
		
		else
		
			echo "compare-config: ERROR: No network configuration files found in the $cc_tfolder folder. Expected to find $cc_template.  Exiting.";
			exit 1;
		fi
	fi
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

compare-config 'NIC Card Template missing' "$IFCFG_TB" "$IFCFG_T";
compare-config 'KRB5 Config Template missing' "$KRB5_TB" "$KRB5_T";
compare-config 'KRB5 Config Template missing' "$SSHD_TB" "$SSHD_T";

# SSSD Config File: File will be auto copied if missing.

# Systemd Auto Net startup script.
if [[ ! -r $SYSDAUTONET ]]; then
	if [[ -r ./templates/$(basename $SYSDAUTONET) ]]; then
		echo "Systemd Auto Net startup file was missing.  Copying $(basename $SYSDAUTONET) to $SYSDAUTONET .";
		/bin/cp ./templates/$(basename $SYSDAUTONET) $SYSDAUTONET;
		systemctl enable $SYSDAUTONET;
		systemctl daemon-reload;
	else
		echo "File ./templates/$(basename $SYSDAUTONET) was not readable.  Exiting";
		exit 1;
	fi

else
	echo "Systemd $SYSDAUTONET startup file existed!";
fi


# Last but not least, let's copy this script to a folder that has execute permissions, instead of /root/auto-net/ .
# /tmp is used since executing from /root/auto-net/ doesn't work and yields a permission denied.
if [[ ! -d /tmp/auto-net ]]; then
	echo "Copying contents of current /root/auto-net folder to /tmp for execution.";
	cp -iRp /root/auto-net /tmp/;
	restorecon -irv /tmp/auto-net/;
	chcon -t bin_t /tmp/auto-net/$(basename $0);
fi


# Exit if only a setup is required.
if [[ $ISSETUP == "true" ]]; then
	echo "NOTE: Setup specified.  Exiting since only setup required.  Not configuring system.";
	echo "IMPORTANT: Don't forget to set a password in $IPACLIENTCREDFILE file. Otherwise SSSD won't bind with Free IPA.";
	exit 0;
else
	echo "Setup (ISSETUP) was set to false, meaning configuration of this system will commence.";
fi

# ------------------------------------------------------------------------------------


# Set SELinux permissions.
yum install policycoreutils-python-utils -y

# Set SELinux permissions for common utilities, including DHCPD and dhclient.  Without these, SELinux will prevent execution.
# This will take a while to execute so executing on the image is best.
for SEPERM in $( echo NetworkManager_var_lib_t cluster_conf_t cluster_var_lib_t cluster_var_run_t dhcpc_state_t dhcpc_tmp_t dhcpc_var_run_t initrc_var_run_t net_conf_t root_t systemd_passwd_var_run_t virt_lxc_var_run_t virt_var_run_t ); do semanage permissive -a $SEPERM; done


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


	echo "RETV: $IPENTRY";
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
	        if ( $0 ~ /'$INTNAME'/ )
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
		echo "ERROR: Output of 'ip a' below:"
		ip a
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
		IPADDR="$RETV";
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
	if [[ $OSVERSION == "ROL7" || $OSVERSION == "COL7" || $OSVERSION == "RHL7" ]]; then 
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
	elif [[ $OSVERSION == "ROL8" || $OSVERSION == "COL8" || $OSVERSION == "RHL8" ]]; then
		nmcli con add \
			con-name $INTNAME \
			ifname $INTNAME \
			type ethernet \
			ip4 $IPADDR/$IPNETMASK \
			gw4 $NETGATEWAY \
			ipv4.method manual \
			ipv4.dns "$STRDNS" \
			connection.autoconnect yes \
			ipv4.dns-search "$NETSEARCH"
	
	else
		echo "ERROR: Unknown OS. Exiting.";
		exit 1;
		
	fi

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


# Set resolv.conf first
if [[ $TEMPLATEF != "" && -r $TEMPLATEF/resolv.conf-template ]]; then
	echo "Backing up /etc/resolv.conf to /etc/resolv.conf-backup-01 and copying in $TEMPLATEF/resolv.conf-template to /etc/resolv.conf .";
	/bin/cp -p /etc/resolv.conf /etc/resolv.conf-backup-01;
	/bin/cp $TEMPLATEF/resolv.conf-template /etc/resolv.conf;
else
	echo "WARN: Skipping adjusting /etc/resolv.conf. By doing so, I'm assuming your existing config will work.";
fi


hostnamectl set-hostname $NHOSTNAME.$NDOMAIN;

# Release the IP temporarily as we start up Networking with the permanently updated files.
dhclient -r; dhclient -x;

# Check version and initiate the network config.
if [[ $OSVERSION == "ROL7" || $OSVERSION == "COL7" || $OSVERSION == "RHL7" ]]; then

	cp -p $NCPATH/ifcfg-$INTNAME $NCPATH/_ifcfg-$INTNAME-backup-$(date +%s);
	mv $NCPATH/ifcfg-n-$INTNAME $NCPATH/ifcfg-$INTNAME;

	systemctl restart network;

elif [[ $OSVERSION == "ROL8" || $OSVERSION == "COL8" || $OSVERSION == "RHL8" ]]; then
	nmcli con down $INTNAME;
	nmcli con up $INTNAME;
	nmcli con show $INTNAME;
else
	echo "WEIRD: This should have exited earlier if the OS version isn't one we support. ";
	exit 1;
fi


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


# Return to the former directory.
cd $CWD;

# Reboot the server to take all changes into effect and start up cleanly after all changes.
reboot;


