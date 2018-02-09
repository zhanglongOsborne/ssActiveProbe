#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyleft Osborne_ZL
2017-10-20
'''

import threading
from scapy.all import *
import ctypes
import inspect

iv_buffer_max_size = 256  # from ss-libev setting
scan_max_try = 128
max_thread_num = 16
g_time_out = 5
inet_face = "eth0"

'''
def _async_raise(tid, exctype):
    """raises the exception, performs cleanup if needed"""
    tid = ctypes.c_long(tid)
    if not inspect.isclass(exctype):
        exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


def stop_thread(thread):
    _async_raise(thread.ident, SystemExit)

'''

def test_port_isopen(ipaddr, port):
    result = False
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(1)
    try:
        sk.connect((ipaddr, port))
        result = True
    except Exception:
        result = False
    return result


def compat_ord(s):
    if type(s) == int:
        return s
    return _ord(s)


def compat_chr(d):
    if bytes == str:
        return _chr(d)
    return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord
chr = compat_chr


def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s


def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s


def random_string(length):
    return os.urandom(length)


def test_single(iv, ip, port, addrtype, attack_data, timeout=g_time_out):
    try:
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
        af, socktype, proto, canonname, sa = addrs[0]
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(sa)
        s.send(iv + to_bytes(chr(addrtype)) + attack_data)
        # print("the send data: %s"%(iv + to_bytes(chr(addrtype)) + attack_data))
        ok = False
        try:
            ret = s.recv(1024)
        # print ("the recv data_len: %d"%(len(ret)))
        except socket.timeout:
            ok = True
        except:
            pass
        return ok
    except:
        pass


class TestThread(threading.Thread):
    def __init__(self, lock, semaphore, index, attack_ok_list, params):
        threading.Thread.__init__(self)
        self.lock = lock
        self.semaphore = semaphore
        self.index = index
        self.params = params
        self.attack_ok_list = attack_ok_list
        semaphore.acquire()

    def run(self):
        for retry in range(3):
            ok = test_single(*self.params)
            if ok is None:
                continue
            if ok:
                self.lock.acquire()
                self.attack_ok_list.append([self.params[0], self.params[3], self.index])
                self.lock.release()
            break
        self.semaphore.release()


def scan(iv_len, addr, port):
    # print('scan iv size is %d' % iv_len)
    iv_data = random_string(iv_len - 2)
    attack_ok_list = []
    addrtype = 0
    att_data_len = 6
    attack_data = random_string(att_data_len)
    lock = threading.Lock()
    semaphore = threading.Semaphore(max_thread_num)
    for index in range(scan_max_try + iv_buffer_max_size):
        if index % 50 == 10:
            # print("%d%%" % (index * 100 / (scan_max_try + iv_buffer_max_size)))
            pass
        iv = iv_data + struct.pack('>H', index)
        # print iv
        testThread = TestThread(lock, semaphore, index, attack_ok_list, (iv, addr, port, addrtype, attack_data))
        testThread.start()

    # print("Waiting response")
    for thread_num in range(max_thread_num):
        semaphore.acquire()

    print("%s\t%d\t%d\t%d\t%d\t%f" % (addr, port, iv_len, index + 1, len(attack_ok_list), len(attack_ok_list) / float(index + 1)))
    return False


def detect(iv_len, addr, port):
    scan(iv_len, addr, port)


def pkt_capture(filter_rule, iFace, pkts):
    pkts = sniff(filter=filter_rule, iface=iFace, count=3)
    print pkts


def detectThread(start, end, mutex, sum):
    for i in range(start, end):
        addr_port = lines[i].replace("\n", "").split('\t')
        # print addr_port
        addr = addr_port[0]
        ports = addr_port[1]
        port_arr = ports.split(";")
        for port_str in port_arr:
            port = int(port_str)
            if test_port_isopen(addr, port):
                for i in [16, 12, 8]:
                    # pkts=[]
                    # filter_rule = "ip host "+addr+" and tcp port "+port_str
                    iFace = inet_face
                    # pkt_thread = threading.Thread(target=pkt_capture,args=(filter_rule,iFace,pkts))
                    # pkt_thread.start()
                    # detect(i,addr, port)
                    # stop_thread(pkt_thread);
                    # print pkts
                    # wrpcap("./result/"+addr+"_"+port_str+"_"+str(i)+".pcap",pkts);
                    command = "tcpdump -i " + iFace + " host " + addr + " and port " + port_str + " -s0 -w " + "./ss_own_result/" + addr + "_" + port_str + "_" + str(
                        i) + ".pcap &"
                    # print command
                    os.system(command)
                    detect(i, addr, port)
                    grep_str = "tcpdump -i " + iFace + " host " + addr + " and port " + port_str + " -s0 -w " + "./ss_own_result/" + addr + "_" + port_str + "_" + str(
                        i) + ".pcap"
                    command = "ps aux|grep \"" + grep_str + "\"|grep -v \"grep\"|awk '{print $2}'|xargs kill -9"
                    # print command
                    os.system(command)
            else:
                print("%s:%d port is not arrival" % (addr, port))
                pass


def main(filePath, threadNum):
    global sum
    sum = 0
    global mutex
    mutex = threading.Lock()
    file = open(filePath, "r")
    global lines
    lines = file.readlines()
    lineNum = len(lines)
    threads = []

    sum = 0

    for i in range(0, threadNum):
        start = i * (int(lineNum / threadNum))
        end = (i + 1) * (int(lineNum / threadNum))
        if i == threadNum - 1:
            end = lineNum
        t = threading.Thread(target=detectThread, args=(start, end, mutex, sum))
        threads.append(t)

    for i in range(0, threadNum):
        threads[i].start()
    for i in range(0, threadNum):
        threads[i].join()
        # print sum
        # outfile.writelines(str(sum)+"\n")


if __name__ == '__main__':
    # print sys.argv[1]
    ipFilePath = sys.argv[1]
    # ipOutPath=sys.argv[2]
    threadNum = int(sys.argv[2])
    main(ipFilePath, threadNum)
