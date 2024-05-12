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
    ip_dst = "10.2.2.3" # replace it with your ps ip_addr
try:
    dst_mac = sys.argv[2]
except:
    dst_mac = "e8:eb:d3:58:a0:0c" # replace it with your ps mac_addr
try:
    iface = sys.argv[3]
except:
    iface="enp129s0f0" # replace it with your iface



class INA(Packet):
    name = "INA"
    fields_desc = [ 
                    BitField("jobAndSeq", 1, 16),
                    BitField("workerID", 0, 8),
                    BitField("total_workers",2, 8),
                    BitField("data0", 61632, 32),
                    BitField("data1", 21427260, 32),
                    BitField("data2", 1422537, 32),
                    BitField("data3", 14479075, 32),
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
                    ByteField("isACK", 0),
                    BitField("hashID", 300, 16), # you can either compute the hashID on host or in the switch, in this example, we simply set it in host, make sure that hashID < 35000(capacity in p4)
                    BitField("hashID2", 300, 16)
                    ]

ina_field = INA() # you can define the pkt content. In this example, we use the above info.
src_ip = "10.2.2.1"
src_mac = "e8:eb:d3:58:9f:e4" # replace with your worker mac_addr
p = (Ether(dst=dst_mac, src=src_mac)/
     IP(src=src_ip, dst=ip_dst, proto=17)/
     UDP(sport=50000,dport=50000)/
     ina_field)

p.show()
sendp(p, iface=iface) 


