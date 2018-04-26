import sys
import os
import subprocess
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from mainwindow import Ui_MainWindow
import time
import socket



class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.show()

        host = '192.168.1.74'#'10.17.3.75' #set IP address we want to connect with
        port = 30001

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port)) #connect to the other host
        self.s = sock

        #self.printTraffic
        self.timer = QTimer() #set up timer
        self.timer.timeout.connect(self.printTraffic) #when the timer period ends, call printTraffic funtion to refresh data
        self.timer.start(3000) #set timer period

    def printTraffic(self):
        print("in printTraffic")
        sData = "Temp"
        self.s.send("Ready".encode()) #tell the other host we are ready to receive data
        sData = self.s.recv(4096) # store the data that the other host sends us

        print("ran receivefile")

        print("opened file")

        lineWeb = "" #variable that will be used to keep web addresses
        lineTime = "" #variable that will be used to store time stamps

        print("at for loop")

        sData = sData.decode().replace("\n\n", ",") #decode data received and replace \n\n with commas so we can correctly split the data
        sData = sData.strip().split(",") #split the data by commas
        print(sData)

        history = []
        last = False


        for i in range(len(sData)): #loop through all of the lines in the file
            if sData[i] != '': #if it is not an empty line
                if i % 2 == 0: #if it's an even index, we know that it is a web address
                    if sData[i] not in history:
                        lineWeb += sData[i] + "\n" #add the current web address to the list of web addresses
                        history.append(sData[i])
                        last = True
                    else:
                        last = False
                else: #otherwise it's an odd index, so we know it's a timestamp
                    if last:
                        lineTime += str(sData[i]) + "\n" #add the current time stamp to the list of times
        self.ui.timeInfo.setText(lineTime) #display the times in the gui
        self.ui.display_webtraffic.setText(lineWeb) #display the websites in the gui


app = QApplication(sys.argv)
w = AppWindow()
w.show()
sys.exit(app.exec_())
