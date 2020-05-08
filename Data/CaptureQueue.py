#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import queue

quick_view_queue=queue.Queue()  #label
detail_view_queue=queue.Queue() #packet
filter_queue=queue.Queue(maxsize=1) #filter
packet_to_filter=queue.Queue(maxsize=1) #packet to filter thread



def get_pkt():
    return detail_view_queue

def get_label():
    return quick_view_queue

def get_filter():
    return filter_queue

def get_packet_to_filter():
    return packet_to_filter

