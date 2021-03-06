#!/usr/bin/env python
# -*- coding = UTF-8 -*-
# authored by Osborne 2017-10-24

from scapy.all import *
from util import *

invalid_time_stamp = -1.0
time_out_threshold = 5


def read_pcap(pcap_dir):
    if pcap_dir is None:
        return None
    try:
        pkts = rdpcap(pcap_dir)
        return pkts
    except:
        pass


class StreamAttribute(object):
    def __init__(self, tuple_4):
        self.dns = ""
        # tuple_4 format:srcIP,dstIP,srcPort,dstPort
        self.tuple_4 = tuple_4

        #these attribute is for tcp
        self.client_syn_time = invalid_time_stamp
        self.server_syn_ack_time = invalid_time_stamp
        self.is_fin = 0
        # fin_dir: c->s:0    s->c:1
        self.fin_dir = -1
        self.fin_time = 0.0
        self.client_fin_server_rst = 0
        self.server_fin_client_rst = 0
        self.is_rst = 0
        # rst_dir: c->s:0x01    s->c:0x10
        self.rst_dir = 0x00
        self.rst_option = 0
        self.rst_option_len = 0
        self.rst_option_size = 0
        self.rst_flag = 0  # this is used to distinguish reset(reset and ack)

        # these attribute is for tcp and udp
        self.first_pkt_time = invalid_time_stamp
        self.client_data_send_time = invalid_time_stamp
        self.client_send_data_len = -1
        self.client_send_data = ""
        self.is_server_reply = 0
        self.server_reply_data_len = 0
        self.server_reply_time = invalid_time_stamp
        self.server_reply_type = RE_OTHER
        self.server_reply_data = ""
        self.is_timeout = 0
        self.pkt_cnt = 0
        self.max_pkt_len = 0
        self.min_pkt_len = 0xffff
        self.ave_pkt_len = 0.0
        self.total_pkt_len = 0
        self.last_pkt_time = invalid_time_stamp



    # return type: 0:c->s   1:s->c
    def get_pkt_dir(self, pkt):
        pkt_tuple4 = get_4_tuple(pkt)
        if pkt_tuple4[0] == self.tuple_4[0]:
            return 0
        else:
            return 1

    def extract_attr_from_pkt(self, pkt):
        if TCP in pkt:
            tcp = pkt[TCP]
            self.pkt_cnt = self.pkt_cnt + 1
            pkt_len = len(tcp)
            pkt_time = get_pkt_time(pkt)
            self.total_pkt_len = pkt_len + self.total_pkt_len
            self.ave_pkt_len = self.total_pkt_len/self.pkt_cnt
            if self.max_pkt_len < pkt_len:
                self.max_pkt_len = pkt_len
            if self.min_pkt_len > pkt_len:
                self.min_pkt_len = pkt_len
            if pkt_time > self.last_pkt_time:
                self.last_pkt_time = pkt_time
            if self.first_pkt_time == invalid_time_stamp or pkt_time < self.first_pkt_time:
                self.first_pkt_time = pkt_time


            #print tcp.flags
            if tcp.flags == TCP_FLAG_S and self.client_syn_time == invalid_time_stamp:
                self.client_syn_time = pkt_time
            if tcp.flags == TCP_FLAG_S ^ TCP_FLAG_A and self.server_syn_ack_time == invalid_time_stamp:
                self.server_syn_ack_time = pkt_time
            #if tcp.flags & TCP_FLAG_P:
            if hasattr(tcp,'load'):
                if self.get_pkt_dir(pkt) == 0:
                    if self.client_data_send_time == invalid_time_stamp:
                        self.client_data_send_time = pkt_time
                        self.client_send_data_len = len(tcp.load)
                        self.client_send_data = tcp.load
                else:
                    self.is_server_reply = 1
                    self.server_reply_data_len = len(tcp.load)
                    self.server_reply_time = pkt_time
                    self.server_reply_data = tcp.load
                    self.server_reply_type = analyse_reply_data(tcp.load)
            #anlyse reset
            if tcp.flags & TCP_FLAG_R :
                self.is_rst = 1
                self.rst_flag = tcp.flags
                # c->s
                if self.get_pkt_dir(pkt) == 0:
                    self.rst_dir = self.rst_dir & 0x10 ^ 0x01
                    if self.is_fin == 1 and self.fin_dir == 1 :
                        self.server_fin_client_rst = 1
                # s->c
                else :
                    self.rst_dir = self.rst_dir & 0x01 ^ 0x10
                    if self.is_fin==1 and self.fin_dir == 0 :
                        self.client_fin_server_rst = 1
                if hasattr(tcp,'option'):
                    self.rst_option = 1
                    self.rst_option_len,self.rst_option_size = analyse_tcp_option(tcp)
            # tcp fin
            if tcp.flags & TCP_FLAG_F:
                if self.is_fin == 0 :
                    self.is_fin = 1
                    self.fin_dir = self.get_pkt_dir(pkt)
                    self.fin_time = pkt_time

        elif UDP in pkt:
            udp = pkt[UDP]
            self.pkt_cnt = self.pkt_cnt + 1
            pkt_len = len(udp)
            pkt_time = get_pkt_time(pkt)
            self.total_pkt_len = pkt_len + self.total_pkt_len
            self.ave_pkt_len = self.total_pkt_len / self.pkt_cnt
            if self.max_pkt_len < pkt_len:
                self.max_pkt_len = pkt_len
            if self.min_pkt_len > pkt_len:
                self.min_pkt_len = pkt_len
            if pkt_time > self.last_pkt_time:
                self.last_pkt_time = pkt_time
            if self.first_pkt_time == invalid_time_stamp or pkt_time < self.first_pkt_time:
                self.first_pkt_time = pkt_time

            if hasattr(udp,'load'):
                if self.client_data_send_time == invalid_time_stamp:
                    self.client_data_send_time = pkt_time
                    self.client_send_data_len = len(udp.load)

                    self.client_send_data = udp.load

                else:
                    self.is_server_reply = 1
                    self.server_reply_data_len = len(udp.load)
                    self.server_reply_time = pkt_time
                    self.server_reply_data = udp.load
                    self.server_reply_type = analyse_reply_data(udp.load)

            return

    def formate_write_file(self, fd):
        record = self.tuple_4[0] + "\t" + self.tuple_4[1] + "\t" + str(self.tuple_4[2]) + "\t" + str(self.tuple_4[3]) \
                 + "\t" + str(self.client_data_send_time - self.first_pkt_time) + "\t" + str(self.client_send_data_len) \
                 +  "\t" + str(self.is_server_reply) + "\t" + str(self.server_reply_data_len) \
                 + "\t" + str(self.server_reply_time - self.first_pkt_time) + "\t" + str(self.server_reply_type) + "\t" \
                 + "\t" + z(self.is_timeout) + "\t" + str(self.pkt_cnt) + "\t" + str(self.max_pkt_len) + "\t" + str(self.min_pkt_len) \
                 + "\t" + str(self.ave_pkt_len) + "\t" + str(self.last_pkt_time - self.first_pkt_time) \
                 + "\t" + str(self.server_syn_ack_time - self.client_syn_time)  \
                 + "\t" + str(self.is_fin) + "\t" + str(self.fin_dir) + "\t" + str(self.fin_time - self.client_syn_time) \
                 + "\t" + str(self.is_rst) + "\t" + str(self.rst_dir) + "\t" + str(self.rst_option) \
                 + "\t" + str(self.rst_option_size) + "\t" + str(self.rst_option_len) + "\t" + str(self.rst_flag) + "\n"

        fd.write(record)


def extract_attr_from_pcap(pcap_dir,out_dir,dns_str):
    pkts = read_pcap(pcap_dir)
    if pkts is None:
        return
    streams = {}
    left_pkts = scapy.plist.PacketList()
    for pkt in pkts:
        tuple4 = get_4_tuple(pkt)
        if tuple4 is None:
            continue
        key1, key2 = trans_tuple4_to_str(tuple4)
        if streams.has_key(key1):
            streams[key1].extract_attr_from_pkt(pkt)
        elif streams.has_key(key2):
            streams[key2].extract_attr_from_pkt(pkt)
        else:
            if TCP in pkt:
                tcp = pkt[TCP]
                if tcp.flags == TCP_FLAG_S:
                    new_stream_attr = StreamAttribute(tuple4)
                    streams[key1] = new_stream_attr
                    new_stream_attr.dns = dns_str
                    new_stream_attr.extract_attr_from_pkt(pkt)
                else:
                    left_pkts.append(pkt)
            elif UDP in pkt:
                print dns_str
                if pkt[IP].dst == dns_str :
                    udp = pkt[UDP]
                    new_stream_attr = StreamAttribute(tuple4)
                    streams[key1] = new_stream_attr
                    new_stream_attr.dns = dns_str
                    new_stream_attr.extract_attr_from_pkt(pkt)
                else:
                    left_pkts.append(pkt)


    for pkt in left_pkts:
        tuple4 = get_4_tuple(pkt)
        key1, key2 = trans_tuple4_to_str(tuple4)
        if streams.has_key(key1):
            streams[key1].extract_attr_from_pkt(pkt)
        elif streams.has_key(key2):
            streams[key2].extract_attr_from_pkt(pkt)
        else:
            print "this pkt is not in any stream"
    out_fd = open(out_dir,'a')
    for v in streams.itervalues():
        if v.fin_time != 0 and v.client_data_send_time != invalid_time_stamp:
            if v.fin_time - v.client_data_send_time >= time_out_threshold:
                v.is_timeout = 1
        elif v.last_pkt_time != invalid_time_stamp and v.client_data_send_time != invalid_time_stamp:
            if v.last_pkt_time - v.client_data_send_time >= time_out_threshold:
                v.is_timeout = 1
        v.formate_write_file(out_fd)

