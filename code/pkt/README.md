# AGQ example

To let user fully experience the whole progress of INA, we give a runtime example of AGQ with the Python library **Scapy**. The server clients need to send INA packtes, receive aggregated results and send ACKs. See details in the corresonding directory.

## set the arp table

1. After you run the P4 program, you should first set the ARP table in both PS and workers. One way to do this is with the following commands:
   ```bash
    sudo arp -s <ip address> <mac address>
    ```

2. Running this command will set the ARP table. To test whether your configuration is working, try to ping other clients like the following commands:
   ```bash
    ping <ip address>
    ```
    If you ping other clients successfully, then you can continue to test the AGQ-INA process.
