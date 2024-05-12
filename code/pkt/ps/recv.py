#!/usr/bin/python

import os
import sys

if os.getuid() !=0:
    print("""
            ERROR: This script requires root privileges. 
            Use 'sudo' to run it.
          """)
    quit()

from scapy.all import *
try:
    iface=sys.argv[1]
except:
    iface="enp129s0f0np0" # replace it with your ps iface
try:
    ip_addr = sys.argv[2]
except:
    ip_addr = "10.2.2.3" # replace it with your ps ip address

class INA(Packet):
    name = "INA"
    fields_desc = [ 
                    BitField("jobAndSeq", 0, 16),
                    BitField("workerID", 0, 8),
                    BitField("total_workers",0, 8),
                    BitField("data0", 0, 32),
                    BitField("data1", 0, 32),
                    BitField("data2", 0, 32),
                    BitField("data3", 0, 32),
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
                    BitField("hashID", 0, 16),
                    BitField("hash1", 0, 13),
                    BitField("hash2", 0, 3)
                    ]

bind_layers(UDP, INA, dport=50000)
bind_layers(UDP, INA, dport=50001)
print ("Sniffing on ", iface)
print ("Press Ctrl-C to stop...")
filt = "ip dst "+ip_addr
print(filt)
sniff(filter=filt, iface=iface, prn=lambda p: p.show())