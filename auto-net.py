#!/usr/bin/python3
import random

# ---------------------------------------------------------------------------------------------------------------------------
#
# IMPORTS Section
#
# ---------------------------------------------------------------------------------------------------------------------------
import sys				# pip3 install sys
import logging
import nmap				# pip3 install nmap
import os
import yaml				# pip3 install pyyaml

# ---------------------------------------------------------------------------------------------------------------------------
#
# Class Auto Net
#
#	Purpose: 	On a non-network enabled machine, attempt to obtain an IP address and configure
#			the client with a DNS entry (FreeIPA), IP, SSSD AD Authentication, AutoFS (NFS)
#
#
#
#
# ---------------------------------------------------------------------------------------------------------------------------
class AutoNet:
	logFile="/var/log/auto-net/auto-net-default.log"					# DEFAULT
	confFile="/etc/sysconfig/auto-net/auto-net.yaml"					# DEFAULT
	ipAddress=""

	# Declaring private because I feel like it.
	__yamlConfig=None

	def __init__(self):
		self.ipAddress = ""

	def __init__(self, log):
		self.ipAddress = ""
		self.log = log
		log.setLevel(logging.DEBUG)

		self.loadConf(self.confFile)

		dirLogPath=os.path.dirname(self.logFile)

		print("Checking if path %s exists: " % (dirLogPath))

		# Test if path exists.  Create it if it doesn't exist.
		exists = os.path.exists(dirLogPath)
		if not exists:
			os.mkdir(dirLogPath, 0o750)
			print("The new directory, %s,  is created!" % (dirLogPath))

		fh = logging.FileHandler(self.logFile)

		formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		fh.setFormatter(formatter)
		log.addHandler(fh)

	# ----------------------------------------------------------------------------------------------------------
	#
	# Load json file of configuration settings, checking if default also defined in VMware vSphere Server
	#
	#
	# ----------------------------------------------------------------------------------------------------------
	def loadConf(self,config):

		try:
			# Read YAML config file
			with open(config, 'r') as stream:
			    self.__yamlConfig = yaml.safe_load(stream)
		except:
			print("ERROR: Config file %s, did not exist or could not be loaded.  Exiting." % (config))
			sys.exit(1)

		print(yaml.dump(self.__yamlConfig))

		print(self.__yamlConfig.get('autonet.ipa',0))


	# ----------------------------------------------------------------------------------------------------------
	#
	# Setup the message logger for the rest of the logic.
	#
	#
	# ----------------------------------------------------------------------------------------------------------
	def logmsg(self, msg):
		if self.log:
			with open(self.logFile, "a") as f:
				f.write (str(msg) + "\n")


	# ----------------------------------------------------------------------------------------------------------
	#
	# Convert a class-based netmask to a classless cidr
	#
	#
	# ----------------------------------------------------------------------------------------------------------
	def tocidr(self, netmask):
		'''
		:param netmask: netmask ip addr (eg: 255.255.255.0)
		:return: equivalent cidr number to given netmask ip (eg: 24)
		'''
		return sum([bin(int(x)).count('1') for x in netmask.split('.')])


	# ----------------------------------------------------------------------------------------------------------
	#
	# Scan the VLAN / Subnet for available IP's once a temporary IP is retrieved.
	#
	#
	# ----------------------------------------------------------------------------------------------------------
	def nmapScan(self, vlan, netmask):

        	# NMAP VLAN to determine IP availability.
		self.logmsg("nmapScan(self, vlan, netmask)")
		self.logmsg("vlan: " + vlan)
		self.logmsg("netmask: " + netmask)

		nm = nmap.PortScanner ()

		cidr=ipaddress.IPv4Network('0.0.0.0/' + netmask).prefixlen
		# print ("cidr: ", cidr);

		try:
			self.logmsg("Running nm.scan ... vlan(%s), netmask(%s) \n" % ( vlan, netmask) )
			raw = nm.scan(hosts=vlan+'/'+str(cidr), arguments=' -v -sn -n ')
		except Exception as e:
			logging.exception(e)

		for a, b in raw.get('scan').items():
			if str(b['status']['state']) == 'down' and str(b['status']['reason']) == 'no-response':
				try:
					self.logmsg("ipv4: %s" % (str(b['addresses']['ipv4'] )))
					self.logmsg("state:  %s" % (str(b['status']['state']  )))

					self.finlst.append([str(b['addresses']['ipv4']), str(b['status']['state'])])
					self.logmsg("a, b: %s %s" % (str(a), str(b)))
				except Exception as listexc:
					self.logmsg("Error inserting element: %s %s" % (a, b))
					self.logmsg("Exception Encountered: ", listexc)
					continue

		self.logmsg("self.finlst: %s" % (self.finlst))

		self.logmsg("Finished scanning " + str(dt.now()) + "\n")
		return self.finlst                       # returns a list



	# ----------------------------------------------------------------------------------------------------------
	#
	# Lookup if a set of IP's retrieved earlier are already allocated to hostnames which may be offline.
	# This ensures no IP conflict is possible when those machines come up.
	#
	#
	# ----------------------------------------------------------------------------------------------------------
	def dnsLookup(self):
		self.logmsg("dnsLookup(self): ")
    
		dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
		dns.resolver.default_resolver.nameservers = self.dnslst

		# Check that self.finlst is not empty.  Quit otherwise.
		self.logmsg("self.finlst: " + str(self.finlst))
		if not self.finlst:
			self.logmsg("ERROR: self.finlst was empty.  This indicates that the nmap scanned failed or returned no results.  Sometimes this is due to missing parameters, such as NETWORK_ADDRESS or NETWORK_MASK not being set.  This is needed by nmap.  Please check the Advanced Section and Custom Attribute Key/Value pairs for the Virtual Network.\n")

		for x in range(len(self.finlst)):
			# print("DNS.  PTR of: ", self.finlst[x][0])

			try:
				answers = dns.resolver.query(self.finlst[x][0], 'PTR')
			except Exception as dnsexc:
				# print ("DNS Exception Encountered: ", dnsexc)
				self.dnschklst.append(self.finlst[x])
			continue

		#    print("IP List:")
		#    for rdata in answers:
		#        print(rdata)

		#   for x in range(len(finlst)):
		#        print("", finlst[x][0] )

		return self.dnschklst



	# ----------------------------------------------------------------------------------------------------------
	#
	# Lookup if a set of IP's retrieved earlier are already allocated to hostnames which may be offline.
	# This ensures no IP conflict is possible when those machines come up.
	#
	#
	# ----------------------------------------------------------------------------------------------------------
	def configInitialNmcliNetworking(self):
		pass




# ------------------------------------------------------------------------ 
#
# MAIN
# 
# 
# ------------------------------------------------------------------------ 
def main():
	# Set logger properties
	logger = logging.getLogger(__name__)

	an = AutoNet(logger)

	# Print parameters provided to this tool
	an.logmsg("main(): Python Script name: " + sys.argv[0])
	an.logmsg("main(): Number of arguments: " + str(len(sys.argv)))
	an.logmsg("main(): The arguments are: " + str(sys.argv))

	an.loadConf(an.confFile)


if __name__ == "__main__":
    retcode=main()
    sys.exit(retcode)
