# Parameter Sever example

In this example, we use the scapy lib to send INA packets. Assuming that you are currently in the worker directory, one way to run the send code is with the following commands:

```bash
sudo python3 send.py <PS IP address> <PS mac address> <NIC name>
```

The program will send an INA packet to the ps. During the path from workers to the PS, the switch will aggregate the INA packet and drop the packets. After receiving all the worker packets, the switch will send the aggregated packet to the PS.

