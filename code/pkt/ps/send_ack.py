#!/usr/bin/python

import os
import sys

if os.getuid() !=0:
    print ("""
            ERROR: This script requires root privileges. 
                Use 'sudo' to run it.
            """)
    quit()

from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "10.2.2.1" # replace it with your worker ip address
try:
    dst_mac = sys.argv[2]
except:
    dst_mac = "e8:eb:d3:58:9f:e4" # replace it with your worker mac_addr
try:
    iface = sys.argv[3]
except:
    iface="enp129s0f0np0"  # replace it with your ps iface



class INA(Packet):
    name = "INA"
    fields_desc = [ 
                    BitField("jobAndSeq", 1, 16),
                    BitField("workerID", 0, 8),
                    BitField("total_workers",2, 8),
                    BitField("data0", 61632*2, 32),
                    BitField("data1", 4, 32),
                    BitField("data2", 6, 32),
                    BitField("data3", 8, 32),
                    BitField("data4", 0, 32),
                    BitField("data5", 0, 32),
                    BitField("data6", 0, 32),
                    BitField("data7", 0, 32),
                    BitField("data8", 0, 32),
                    BitField("data9", 0, 32),
                    BitField("data10", 0, 32),
                    BitField("data11", 0, 32),
                    BitField("data12", 0, 32),
                    BitField("data13", 0, 32),
                    BitField("data14", 0, 32),
                    BitField("data15", 0, 32),
                    ByteField("isACK", 1),
                    BitField("hashID", 100, 32),
                    BitField("hashID2", 100, 32)
                    ]

ina_field = INA()
src_ip = "10.2.2.3" # replace with your ps ip_addr
src_mac = "e8:eb:d3:58:a0:0c" # replace with your ps mac_addr
p = (Ether(dst=dst_mac, src=src_mac)/
     IP(src=src_ip, dst=ip_dst, proto=17)/
     UDP(sport=50000,dport=50000)/
     ina_field)


p.show()
sendp(p, iface=iface) 


