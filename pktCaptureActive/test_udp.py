import socket
import threading
import time
import struct
import Queue

queue = Queue.Queue()


def udp_sender(ip, port):
    try:
        ADDR = (ip, port)
        sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_udp.sendto("\r\x0e\xa5\r\xbc\n\xea\xe3\xebQ039\x01\xea'\xcf\xd95r\x074xO\xeb\xde\xa0\x01\x05\x14CHLO\x13\x00\x00\x00PAD\x00\xd2\x03\x00\x00SNI\x00\xe6\x03\x00\x00VER\x00\xea\x03\x00\x00CCS\x00\xfa\x03\x00\x00MSPC\xfe\x03\x00\x00UAID(\x04\x00\x00TCID,\x04\x00\x00PDMD0\x04\x00\x00SMHL4\x04\x00\x00ICSL8\x04\x00\x00CTIM@\x04\x00\x00NONP`\x04\x00\x00MIDSd\x04\x00\x00SCLSh\x04\x00\x00CSCTh\x04\x00\x00COPTh\x04\x00\x00IRTTl\x04\x00\x00CFCWp\x04\x00\x00SFCWt\x04\x00\x00------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------fonts.googleapis.comQ039\x01\xe8\x81`\x92\x92\x1a\xe8~\xed\x80\x86\xa2\x15\x82\x91d\x00\x00\x00Chrome/61.0.3163.100 Windows NT 6.1; WOW64\x00\x00\x00\x00X509\x01\x00\x00\x00\x1e\x00\x00\x00\xba\x7f\xe9Y\x00\x00\x00\x00\x01\x03\xe5\x08\x10\xf4@\xcc\xbeuD\x0e(\xa4\xbbH<\xe1Z\xfbq\xae\x95e\x8b\xd4\x84>\x8e\xc4\x14Nd\x00\x00\x00\x01\x00\x00\x00\xfc\xa7\x00\x00\x00\x00\xf0\x00\x00\x00`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", ADDR)
        sock_udp.settimeout(2)
        print sock_udp.recv(1024)
        sock_udp.close()
    except:
        pass

def scan(inputfile):
    fd = open(inputfile)
    lines = fd.readlines()
    for line in lines:
        ip , port = line.split("\t")
        udp_sender(ip,int(port))


if __name__ == '__main__':
    import sys
    inputfile = "C:\\Users\\macworld\\Desktop\\ss_attack\\server_ip_port.result"
    scan(inputfile)