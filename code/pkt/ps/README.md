# Parameter Sever example

In this example, we use the scapy lib to monitor the NIC and show the results. Assuming that you are currently in the ps directory, one way to run the recv code is with the following commands:

```bash
sudo python3 recv.py <NIC name>
```

The program will continously monitor the NIC and print the received pakcets.

Once you receive a packet, run the send_ack code to send an ACK packet to the switch. Then the switch will clear the corresponding resources, one way to run the send_ack code is with the following commands:

```bash
sudo python3 send_ack.py <worker IP address> <worker mac address> <NIC name>
```
Note that the fields in AGQ header should be the same to the aggregated packet.