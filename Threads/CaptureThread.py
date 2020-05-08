#/usr/bin/env python3
#-*- coding:utf-8 -*-

from PyQt5.QtCore import QThread,pyqtSignal
from PyQt5.QtWidgets import QTableWidgetItem
from Data import CaptureQueue
from scapy.all import *
import time

class capturethread(QThread):
    newPkt=pyqtSignal(list,scapy.layers.l2.Ether)
    def __init__(self):
        super().__init__()
    
    def run(self):
        self.stopper=False
        self.count=1
        filter_queue=CaptureQueue.get_filter()
        if filter_queue.empty():
            self.pkts=sniff(prn=self.pkt_captured,stop_filter=self.sniff_stopper)
        else:
            self.pkts=sniff(prn=self.pkt_captured,stop_filter=self.sniff_stopper,filter=filter_queue.get())


    def sniff_stopper(self,pkt):
        return self.stopper

    def set_stopper(self,flag):
        self.stopper=flag
    
    def pkt_captured(self,packet):
        # CaptureQueue.get_pkt().put(packet)
        layers = []
        counter = 1
        while True:
            if packet.getlayer(counter) != None:
                layers.append(packet.getlayer(counter).name)
            else:
                break
            counter += 1
        
        if 'Raw' in layers:
            layers.remove('Raw')
        if 'Padding' in layers:
            layers.remove('Padding')
        packetType=layers[-1]

        # itemLabel='Protocol:{} '.format(packetType)
        # if 'IP' in layers:
        #     itemLabel+='IP.src:{} IP.dst:{}'.format(packet[IP].src,packet[IP].dst)
        # elif 'Ethernet' in layers:
        #     itemLabel+='Ethernet.src:{} Ethernet.dst:{}'.format(packet[Ether].src,packet[Ether].dst)

        # CaptureQueue.get_label().put(itemLabel)
        item_list=list()
        item_list.append(QTableWidgetItem(str(self.count)))  #packet No.
        item_list.append(QTableWidgetItem(str(time.time()))) #packet time
        if 'IP' in layers:
            item_list.append(QTableWidgetItem(packet[IP].src))  #packet src addr
            item_list.append(QTableWidgetItem(packet[IP].dst))  #packet dst addr
        else:
            item_list.append(QTableWidgetItem(packet[Ether].src))
            item_list.append(QTableWidgetItem(packet[Ether].dst))
        item_list.append(QTableWidgetItem(packetType))
        item_list.append(QTableWidgetItem(str(len(packet))))
        self.count+=1

        self.newPkt.emit(item_list,packet)

    
