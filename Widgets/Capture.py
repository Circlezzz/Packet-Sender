#!/usr/bin/env python3
#-*- coding:utf-8 -*-

from PyQt5.QtWidgets import (QWidget, QSplitter, QListWidget, QTreeWidget,
                             QTreeWidgetItem, QGridLayout, QHBoxLayout,
                             QLineEdit, QLabel, QVBoxLayout, QPushButton,
                             QCheckBox, QListView,QTableWidget,QAbstractItemView,QHeaderView)
from PyQt5.QtCore import Qt, QTimer, QStringListModel, QModelIndex,pyqtSignal
from scapy.all import *
import re
from collections import OrderedDict
from Threads.CaptureThread import capturethread
from Threads.FilterThread import filterthread
from Data import CaptureQueue
from Tools import scapy2ordereddict


class capture(QWidget):
    filterApplied=pyqtSignal()
    def __init__(self):
        super().__init__()
        self.initUI()
        self.packet_list=[]

    def initUI(self):
        mainLayout = QVBoxLayout(self)

        filter_layout = QHBoxLayout()
        filter_label = QLabel('Filter')
        self.filter_lineEdit = QLineEdit()
        filter_apply_btn = QPushButton('Apply')
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_lineEdit)
        filter_layout.addWidget(filter_apply_btn)
        mainLayout.addLayout(filter_layout)
        self.filter = ''

        splitterMain = QSplitter(Qt.Vertical, self)
        self.QuickView = QTableWidget(splitterMain)
        #self.QuickView.setUniformItemSizes(True)
        self.QuickView.setColumnCount(6)
        self.QuickView.setHorizontalHeaderLabels(['No.','Time','Source','Destination','Protocol','Size'])
        self.QuickView.setColumnWidth(0,60)
        self.QuickView.verticalHeader().setVisible(False)
        self.QuickView.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        # self.QuickView.horizontalHeader().setStretchLastSection(True)
        self.QuickView.setShowGrid(False)
        self.QuickView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.QuickView.setSelectionMode(QTableWidget.ExtendedSelection)
        self.QuickView.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # self.QuickView.setLayoutMode(QListView.Batched)
        # self.QuickView.setBatchSize(20)
        self.DetailView = QTreeWidget(splitterMain)
        self.DetailView.setColumnCount(2)
        self.DetailView.setHeaderLabels(['Item', 'Detail'])
        mainLayout.addWidget(splitterMain)

        bottomLayout = QHBoxLayout()
        self.start_btn = QPushButton('Start')
        self.stop_btn = QPushButton('Stop')
        self.restart_btn = QPushButton('Restart')
        self.clear_btn=QPushButton('Clear')
        self.intercept_CheckBox = QCheckBox('Intercept Packets')
        bottomLayout.addWidget(self.start_btn)
        bottomLayout.addWidget(self.stop_btn)
        bottomLayout.addWidget(self.restart_btn)
        bottomLayout.addWidget(self.clear_btn)
        bottomLayout.addWidget(self.intercept_CheckBox)
        bottomLayout.addStretch()
        self.stop_btn.setEnabled(False)
        self.restart_btn.setEnabled(False)
        mainLayout.addLayout(bottomLayout)

        self.start_btn.clicked.connect(self.start_sniff)
        # filter_apply_btn.clicked.connect(self.apply_filter)
        self.stop_btn.clicked.connect(self.stop_sniff)
        self.QuickView.currentItemChanged.connect(self.show_current_detail)
        self.restart_btn.clicked.connect(self.restart_sniff)
        self.clear_btn.clicked.connect(self.clear_widget)
        self.count=0

    def start_sniff(self):
        self.cap_thread = capturethread()
        self.cap_thread.newPkt.connect(self.init_display)
        self.cap_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.restart_btn.setEnabled(False)

    def init_display(self,item_list,pkt):
        self.packet_list.append(pkt)
        self.QuickView.insertRow(self.QuickView.rowCount())

        for i in range(6):
            self.QuickView.setItem(self.QuickView.rowCount()-1,i,item_list[i])

    # def apply_filter(self):
    #     filter_queue=CaptureQueue.get_filter()
    #     filter_queue.queue.clear()
    #     filter_queue.put(self.filter_lineEdit.text())
    #     if self.cap_thread.isRunning():
    #         self.cap_thread.set_stopper(True)
    #         self.cap_thread.wait()
    #     self.cap_thread.start()

    #     filter_pkt_queue=CaptureQueue.get_packet_to_filter()
    #     filter_pkt_queue.put(self.packet_list)
    #     filter_pkt_queue.put(self.filter_lineEdit.text())
    #     self.filter_thread=filterthread()
    #     self.filter_thread.start()
    #     self.filter_thread.filtered.connect(self.get_filtered_pkt)


    # def get_filtered_pkt(self,packetlist):
    #     pass


    # def formatString(self, tmp):
    #     self.final_dict = collections.OrderedDict()
    #     title_pattern = re.compile(r'###[ [a-zA-Z]+ ]###')  #abstract titles
    #     tmp_titles = title_pattern.findall(tmp)
    #     self.titles = []
    #     for title in tmp_titles:
    #         refine_pattern = re.compile(r'###\[ | \]###')
    #         self.titles.append(refine_pattern.sub('', title))
    #     #print(self.titles)

    #     content_split_pattern = title_pattern  #abstract contents
    #     tmp_content = re.split(content_split_pattern, tmp)
    #     self.contents = [i for i in tmp_content if i != '']
    #     #print(self.contents)

    #     for (title, content) in zip(self.titles, self.contents):
    #         tmp_dict = {}
    #         tmp_lists = re.split(r'\n', content)
    #         tmp_lists = [i.replace(' ', '') for i in tmp_lists if i != '']

    #         #print(tmp_lists)
    #         for i in tmp_lists:
    #             tmp_item = i.split('=')
    #             #print(tmp_item)
    #             if len(tmp_item) == 2:
    #                 tmp_dict[tmp_item[0]] = tmp_item[1]
    #         self.final_dict[title] = tmp_dict
    #     #print(self.final_dict)

    def buildTree(self):
        self.DetailView.clear()
        for title in self.packetDict.keys():
            tree_item = QTreeWidgetItem(self.DetailView)
            tree_item.setText(0, title)
            tree_item.setExpanded(True)
            detail_dic = self.packetDict[title]
            for i in detail_dic.keys():
                leaf = QTreeWidgetItem(tree_item, [i, str(detail_dic[i])])
                leaf.setToolTip(1,str(detail_dic[i]))
                tree_item.addChild(leaf)
            self.DetailView.addTopLevelItem(tree_item)

    def stop_sniff(self):
        self.cap_thread.set_stopper(True)

        self.start_btn.setEnabled(True)
        self.restart_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def restart_sniff(self):
        self.pkt_queue = CaptureQueue.get_pkt()
        self.label_queue = CaptureQueue.get_label()
        with self.label_queue.mutex:
            self.label_queue.queue.clear()
        with self.pkt_queue.mutex:
            self.pkt_queue.queue.clear()
        self.packet_list.clear()
        self.QuickView.clearContents()
        self.DetailView.clear()
        self.start_sniff()

    def show_current_detail(self):
        if self.packet_list:
            pkt=self.packet_list[self.QuickView.currentRow()]
            # self.text = FakeOut()
            # old = sys.stdout
            # sys.stdout = self.text
            # packet.show2()
            # sys.stdout = old
            # tmp = self.text.str
            # self.formatString(tmp)
            self.packetDict=scapy2ordereddict.to_dict(pkt)
            self.buildTree()

    def clear_widget(self):
        self.pkt_queue = CaptureQueue.get_pkt()
        self.label_queue = CaptureQueue.get_label()
        with self.label_queue.mutex:
            self.label_queue.queue.clear()
        with self.pkt_queue.mutex:
            self.pkt_queue.queue.clear()
        self.packet_list.clear()
        self.QuickView.clearContents()
        self.DetailView.clear()



class FakeOut:
    def __init__(self):
        self.str = ''

    def write(self, s):
        self.str += s

    def show(self):
        print(self.str)