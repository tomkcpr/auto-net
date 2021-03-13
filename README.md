# auto-net

Backend script to automatically register VMWare VM's against Free IPA .  This is a very basic implementation of the tool.



INSTALLATION (ONE TIME)
------------------------------------------------------------------------------------------------------------------------------------------------------------

Create or clone a machine to one with that includes 'template' in the name. 

List of DNS Servers to use.  Set 

	LDNS=( 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 );


The domain you wish to use for registration.

	NDOMAIN="my.domain.com";


The user ID to verify against once registration completes.

	USERID="user@my.domain.com";


The Free IPA servers to register against.

	IPA01="freeipa01";
	IPA02="freeipa02";


The NET interface to use as a template.

	UNDOMAIN=${NDOMAIN^^};                                  # Uppercase the domain.
	NCPATH="/etc/sysconfig/network-scripts";
	IFCFG_T="$NCPATH/template-ifcfg-eth0";


IP Subnet to discover free IP's on.

	IPSUBNET=10.0.0.0/24;
	IPRANGE="10.0.0.100-10.0.0.255";


In the VMWare vApp Options section of the template, define the following:

	GuestHostname	: <SHORT NAME>
	OSType		: <OS Type>                        (Optional)


Crate a FreeIPA user such as 'autojoin' that has the following role defined (RBAC) and roles set:

	RBAC: Host Auto Join
	User Login: autojoin

	Roles:
		Host Administrators
		Host Enrollment


Interface template.  This file can be anything of your choosing but should contain an ADDR line.  This line will be replaced.  Ideally the interface IP specified should contain N.N.N.999 .   This ensures a duplicate IP is not present when the system is preconfigured.

	/etc/sysconfig/network-scripts/template-ifcfg-eth0


Kerberos conf template.  This, again, can be anything you like however it should contain the following TEMPLATE-HOSTNAME entry.

	# cat /etc/krb5.conf-template

	[libdefaults]
	.
	.

	[realms]
	.
	.


	[domain_realm]
	  TEMPLATE-HOSTNAME.my.domain.com = MY.DOMAIN.COM


The SSSD template again can be anything.  A sample is given below.  No special prameters are required for this one.

	# cat /etc/sssd/sssd.conf-template
	[domain/my.domain.com]
	cache_credentials = True
	krb5_store_password_if_offline = True
	ipa_domain = my.domain.com
	id_provider = ipa
	auth_provider = ipa
	access_provider = ipa
	ipa_hostname = template-rhel7.my.domain.com
	chpass_provider = ipa
	ipa_server = freeipa01.my.domain.com, freeipa02.my.domain.com
	ldap_tls_cacert = /etc/ipa/ca.crt
	autofs_provider = ipa
	ipa_automount_location = UserHomeDir01


	[sssd]
	services = nss, sudo, pam, autofs, ssh
	domains = my.domain.com


	[nss]
	homedir_substring = /home


	[pam]

	[sudo]

	[autofs]

	[ssh]

	[pac]

	[ifp]

	[secrets]

	[session_recording]



Define a systemd startup script such as this:

	# cat /etc/systemd/system/auto-net.service
	[Unit]
	After=network.target

	[Service]
	ExecStart=/etc/sysconfig/network-scripts/auto-net.sh

	[Install]
	WantedBy=default.target


Save and shutdown the template.


EXECUTION
-------------------------------------------------------------------------------------------------------------------------

Clone a VM from the template and boot up ensuring to set the GuestHostname above to the hostname you would like to use. 

Boot up and SSH in using your central ID managed by FreeIPA or AD (If your FreeIPA is paired up with AD.)



