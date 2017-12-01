#!/usr/bin/env python
# -*- coding = UTF-8 -*-
# authored by Osborne 2017-10-24
from scapy.all import *
import os
import sys
import chardet

# TCP flags
TCP_FLAG_C = 0x80
TCP_FLAG_E = 0x40
TCP_FLAG_U = 0x20
TCP_FLAG_A = 0x10
TCP_FLAG_P = 0x08
TCP_FLAG_R = 0x04
TCP_FLAG_S = 0x02
TCP_FLAG_F = 0x01

# server replay type
RE_OTHER = 0x00
RE_SSL_ALERT = 0x01
RE_400_BAD_REQ = 0x02
RE_220_FTP_READY = 0x04
RE_421_TOO_MANY_CONN = 0x08
RE_530_LOGIN = 0x10
RE_SSH_VER = 0x20
RE_QUIC = 0x40
RE_PPTP = 0x80
RE_TEAMVIEW = 0x0100

# reply str type
_400_bad_req_str = "400 Bad request"
_421_too_many_conn = "421"
_220_ftp_ready = "220"
_530_ftp_login = "530"
_ssl_alert = '\x15\x03\x01\x00\x02\x02\x46'
_ssh_ver = 'ssh'
_quic = r"(Handshake timeout expired)|(REJ)|(STK)|(SNO)|(PROF)|(SCFG)|(AEAD)|(SCID)|(PDMD)|(TBKP)|(PUBS)|(KEXS)|(OBIT)|(EXPY)|(RREJ)|(STTL)|(CSCT)|(CRT)"
_pptp = r"\x1a\+<M"
_teamview = r"(\x17\$\x11)|(\x11\x30\x36)"

def get_pkt_time(pkt):
    return pkt.time


def analyse_reply_data(replystr):
    ret = RE_OTHER
    replaystr = replystr.lower()
    #print chardet.detect(replaystr)
    if "400 Bad request" in replystr:
        ret = ret ^ RE_400_BAD_REQ
    if "421" in replystr:
        ret = ret ^ RE_421_TOO_MANY_CONN
    if "220" in replystr:
        ret = ret ^ RE_220_FTP_READY
    if "530" in replystr:
        ret = ret ^ RE_530_LOGIN

    if '\x15\x03\x01\x00\x02\x02\x46' in replystr:
        #print chardet.detect(replaystr)
        ret = ret ^ RE_SSL_ALERT
    if "ssh" in replystr:
        ret = ret ^ RE_SSH_VER

    return ret


def trans_tuple4_to_str(tuple_4):
    return tuple_4[0] + ";" + tuple_4[1] + ";" + str(tuple_4[2]) + ";" + str(tuple_4[3]) ,\
            tuple_4[1] + ";" + tuple_4[0] + ";" + str(tuple_4[3]) + ";" + str(tuple_4[2])


def get_4_tuple(pkt):
    tuple_4 = []
    if pkt is not None and IP in pkt:
        tuple_4.append(pkt[IP].src)
        tuple_4.append(pkt[IP].dst)
        if TCP in pkt:
            tuple_4.append(pkt[TCP].sport)
            tuple_4.append(pkt[TCP].dport)
        elif UDP in pkt:
            tuple_4.append(pkt[UDP].sport)
            tuple_4.append(pkt[UDP].dport)
        else :
            return
        return tuple_4

