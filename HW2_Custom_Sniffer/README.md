# Communication and Computing Course Sniffer
### For Computer Science B.Sc. Ariel University

**By Roy Simanovich and Yuval Yurzdichinsky**

## Description
This program gets a command line argument to which network interface card attach to
and sniff all incoming and outcoming TCP packets. This program designed to sniff TCP packets from Ex2.

Payload of the calculator packets is written to a file called "log.txt" in the same directory as the program.

Please note that the default filter is set to sniff only TCP packets in ports 9997 (default port for the server) and 9998 (default port for the proxy). The sniffer is designed to sniff packets from Ex2, so any other packets that are transmitted using ports 9997 or 9998 won't show any application header or payload, yet they will still sniffed and the basic headers information will be printed to the console (Link layer, Network layer, and Transport layer).

### What is a packet sniffer?
Packet sniffing is the practice of gathering, collecting, and logging some or all packets that pass through a computer network, regardless of how the packet is addressed. This is done to monitor network usage and troubleshoot network problems. Packet sniffing is also known as packet analysis, packet capture, and PCAP.

# Requirements
* Linux machine (Ubuntu 22.04 LTS recommanded)
* GNU C Compiler
* Make
* Libpcap (Packet Capture library)
* Root privileges (for sniffing, as it requires access to the network interface card)

## Building
```
# Installing libpcap, as it is required for the program to work
sudo apt install libpcap-dev

# Building all the necessary files & the main program
make all
```

## Running
* **NOTE:** Before running the sniffer, please check your network interface card (NIC).
```
# Sniffing TCP packets from Ex2.
sudo ./Sniffer <device name> or sudo ./Sniffer
```
