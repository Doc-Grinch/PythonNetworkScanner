import ipaddress
from queue import Queue
from subprocess import run, PIPE
import threading
from sys import stderr


QUEUE = Queue()
OPEN_IP = []
IPS = []


def ips_of_network():
    print("Please choose the network to scan (192.168.1.0/24): ")
    network = input()
    try:
        network = ipaddress.IPv4Network(network, strict=True)
        for host in network.hosts():
            IPS.append(host.exploded)
    except ValueError as e:
        print("The network selected is wrong", e, file=stderr)
        exit(-1)


def ping_scan(ip):
    response = run(f"ping -n 1 -w 500 {ip}", stdout=PIPE)
    if response.returncode == 0:
        return True

    return False


def get_ip():
    for ip in IPS:
        QUEUE.put(ip)


def worker_ip():
    while not QUEUE.empty():
        ip = QUEUE.get()
        if ping_scan(ip):
            print("IP {} is open!".format(ip))
            OPEN_IP.append(ip)


def run_scanner_ip(threads):
    ips_of_network()
    get_ip()
    thread_list = []

    for t in range(threads):
        thread = threading.Thread(target=worker_ip)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    print("Open IP are:", OPEN_IP)


run_scanner_ip(254)
