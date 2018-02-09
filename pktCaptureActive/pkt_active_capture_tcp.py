import socket
import threading
import time
import struct
import Queue
import os
from scapy.all import *

count_all = 0
reply_count = 0
iFace = "eno16777736"
g_timeout = 2
g_send_str = "\x00\x0e8\x9bK\xadv\xa6\xa6\xff\x85\x00\x00\x00\x00\x00"  #openvpn str

def tcp_sender(ip, port):
    try:
        ADDR = (ip, port)
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.settimeout(g_timeout)
        sock_tcp.connect((ip, port))
        sock_tcp.send(g_send_str)
        global count_all
        global reply_count
        count_all += 1
        data = sock_tcp.recv(1024)
        print "rcv success:" + str(data)
        reply_count += 1
        print "replayed:all    " + str(reply_count) + ":" + str(count_all)
    # sock_tcp.close()
    except:
        print ip + ":" + str(port)
        pass


def set_sniffer(pkts, pkt_filter, ifa, num, filename):
    try:
        pkts = sniff(iface=ifa, filter=pkt_filter, count=num, timeout=g_timeout + 1)
        wrpcap(filename, pkts)
    except:
        print "stop the sniff abnormally!"
        pass


def detected_thread(lines, outputpath, start, end):
    for i in range(start, end):
        line = lines[i]
        line = line.strip()
        ip, port_list = line.split("\t")
        ports = port_list.split(";")
        for port in ports:
            pkt_filter = "host " + ip + " and port " + str(port)
            pkts = scapy.plist.PacketList()
            num = 100
            filename = outputpath + "/" + ip + "_" + str(port) + ".pcap"
            t = threading.Thread(target=set_sniffer, args=(pkts, pkt_filter, iFace, num, filename))
            t.start()
            time.sleep(0.1)
            tcp_sender(ip, int(port))
            t.join()
            print pkts


def scan(inputfile, outputpath, thread_num):
    fd = open(inputfile)
    lines = fd.readlines()
    lineNum = len(lines)
    threads = []
    for i in range(0, thread_num):
        start = i * (int(lineNum / thread_num))
        end = (i + 1) * (int(lineNum / thread_num))
        if i == thread_num - 1:
            end = lineNum
        t = threading.Thread(target=detected_thread, args=(lines, outputpath, start, end))
        threads.append(t)

    for i in range(0, thread_num):
        threads[i].start()
    for i in range(0, thread_num):
        threads[i].join()


if __name__ == '__main__':
    import sys

    inputfile = sys.argv[1]
    thread_num = int(sys.argv[2])
    outputfile = sys.argv[3]
    scan(inputfile, outputfile, thread_num)
# test("216.58.208.106",443,"./")
