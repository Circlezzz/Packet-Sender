# Packet Sender

This is a python based network tool. 

## Installation
Python 3.x needed.

```
pip install PyQt5
pip install scapy
```

## Screenshots

## Features
You can build your own network packets and send it. You can capture packets like WireShark or follow the packet stream you just sent.

For Sender, you can custom src/des MAC, IP,payload etc. This tool provide the template of basic TCP/UDP/ICMP/DNS packets. You can custom the packet send speed/number/thread. 

For Capture, It provide the same function like WireShark, you can check packets info or filter packets captured. If you check the Intercept Packets checkbox, The packets will be discard after capture.