#!/usr/bin/env python3
#-*- coding:utf-8 -*-

from PyQt5.QtWidgets import QApplication
import sys
from Widgets.MainWindow import MainWindow
from Widgets.Capture import capture
from Widgets.Sender import sender

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main = MainWindow()
    main.show()
    exit(app.exec_())