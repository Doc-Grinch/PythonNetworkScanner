#!/usr/bin/env python3

# -*- coding:utf-8 -*-
# Network vulnerability scanner with threads
# Written by Arthur D, Simon D and Kevin D

from sys import stderr
from queue import Queue
import socket
import threading
import ipaddress
from subprocess import run, getoutput, PIPE
import json
import nmap
import nvdlib as nvdlib

QUEUE = Queue()
OPEN_PORTS = []


# Main function
def handle():
    writefile(ipconfig_infos(), "configs.txt")
    host = choose_network()
    network = ipaddress.ip_network(host, False)
    get_ip(network)
    choose_ip()
    run_scanner_port(800, 3)


# Function that displays the ip addresses found and ask for the selection
def choose_network():
    ips = readfile()
    print(ips)
    choose = int(input("Please choose the ip from 0 to " + str((len(ips)) - 1) + " of the network : \n"))
    return ips[choose]


# Function that display IPs from the network and ask for the selection
def choose_ip():
    ip = read_ips()
    print(ip)
    choose = int(input("Please choose the ip to scan from 0 to " + str((len(ip)) - 1) + "\n"))
    global TARGET_IP
    TARGET_IP = ip[choose]


# Get ipconfig information
def ipconfig_infos():
    interfaces = getoutput("ip r")
    interfaces.encode("utf-8")
    return interfaces


# Function to write in a file
def writefile(texttowrite, file):
    try:
        with open(file, "w") as fw:
            fw.writelines(texttowrite)
    except PermissionError as e:
        print("Cannot write to the file", e, file=stderr)
        exit(1)


# Read the IPs of the file
def readfile():
    try:
        with open("configs.txt", "r") as fr:
            lines = fr.readlines()
            for i, line in enumerate(lines):
                string = line.split(" ")
                if i == 0:
                    print(f"Mode: {string[6]}")
                try:
                    print(f"Interface:  {string[2]}\n\
                        Reseau/Masque:  {string[0]}\n\
                        Adresse IP:  {string[8]}\n")
                except IndexError:
                    continue
    except PermissionError as e:
        print("Cannot read the result IP file", e, file=stderr)
        exit(1)


def read_ips():
    try:
        text_file = open('result_ip.txt', 'r')
        lines = text_file.read().splitlines()
        text_file.close()
        return lines
    except PermissionError as e:
        print("Cannot read result IPs file.", e, file=stderr)
        exit(1)


def port_scan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_IP, port))
        return True
    except:
        return False


def get_ports(mode):
    if mode == 1:
        for port in range(1, 1024):
            QUEUE.put(port)
    elif mode == 2:
        for port in range(1, 49152):
            QUEUE.put(port)
    elif mode == 3:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 389, 443, 3389]
        for port in ports:
            QUEUE.put(port)


# Ping with Windows parameters
def get_ip(network):
    try:
        result_file = open("result_ip.txt", "w")
    except PermissionError as e:
        print("Cannot open result IPs file.", e, file=stderr)
        exit(1)
    for host in network.hosts():
        response = run(f"ping -c 1 -W 1 {host.exploded}", stdout=PIPE)
        if response.returncode == 0:
            print("IP {} is reachable!".format(host))
            result_file.write(host.exploded + "\n")
    result_file.close()


def worker():
    while not QUEUE.empty():
        port = QUEUE.get()
        if port_scan(port):
            serviceName = socket.getservbyport(port, "tcp")
            print("Port {} is open!".format(port))
            print("Name of the service running at port number %d : %s" % (port, serviceName))
            OPEN_PORTS.append(port)


def run_scanner_port(threads, mode):
    get_ports(mode)
    thread_list = []
    for t in range(threads):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    print("Open ports are:", OPEN_PORTS)
    writefile(str(OPEN_PORTS), "result_ports.txt")

def nvd_search(search):
    r = nvdlib.searchCVE(keyword=search, cvssV3Severity="CRITICAL", limit=10)
    
    for eachCVE in r:
        print(eachCVE.v3severity + ' - ' + str(eachCVE.v3score))
        print(eachCVE.cve.description.description_data[0].value)
        

def banner(ip, port):
    ns = nmap.PortScanner()
    for ports in port:
        dic = ns.scan(str(ip), str(ports))
        res = json.dumps(dic)
        jres = json.loads(res)

        product = jres["scan"][str(ip)]["tcp"][str(ports)]["product"]
        version = jres["scan"][str(ip)]["tcp"][str(ports)]["version"]

        print(product + " " + version)
        nvd_search(product)

choose_ip()
run_scanner_port(800, 3)
banner(TARGET_IP, OPEN_PORTS)

