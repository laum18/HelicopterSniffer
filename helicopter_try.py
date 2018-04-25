import sys
import os
import subprocess
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from mainwindow import Ui_MainWindow
#from receiveFile import *
# import threading
import time
import socket

# class GetFile(threading.Thread):
#     def __init__(self):
#         threading.Thread.__init__(self)
#
#     def run():
#         #os.system("python3 receiveFile.py")
#         print("in run")

class AppWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.show()

        host = '10.17.163.221'#'10.17.3.75'
        port = 30000

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        self.s = sock

        self.sFileName = "websites.txt"

        #self.printTraffic
        self.timer = QTimer() #set up timer
        self.timer.timeout.connect(self.printTraffic) #when the timer period ends, call printTraffic funtion to refresh data
        self.timer.start(3000) #set timer period



    def printTraffic(self):
        #subprocess.Popen(["python3","receiveFile.py"])
        #sys.exit(0)
        #    sock.send(sFileName)
        sData = "Temp"
        self.s.send("Ready".encode())
        sData = self.s.recv(1024)
        fDownloadFile = open(self.sFileName, "wb")
        while True:
            print("Waiting")
            fDownloadFile.write(sData)
            print("after fdownload")
            self.s.send("ready".encode())
            sData = self.s.recv(1024)
            print("after received call")
            print(sData)
            break
        # print("Download Completed")
            # time.sleep(45)
        #os.system("python3 receiveFile.py")

        print("ran receivefile")
        file = open(self.sFileName,"r") #open file that is passed through
        print("opened file")
        # line = file.read()
        # print(line)
        # while line:
        #     line = file.read()
        #     print(line + "-\n")
        listOfLines = file.readlines() #store all of the data from the file in a list
        lineWeb = "" #variable that will be used to keep web addresses
        lineTime = "" #variable that will be used to store time stamps
        currentLine = "" #for testing purposes
        print("at for loop")
        print(len(listOfLines))
        sData = sData.decode().replace("\n\n", ",")
        sData = sData.strip().split(",")
        print(sData)

        for i in range(len(sData)): #loop through all of the lines in the file
            #print(listOfLines[i])
            #currentLine = str(sData.strip().split(",") #strip white spaces, new lines, and split by commas
            #print(currentLine)
            if sData[i] != '': #if it is not an empty line
                if i % 2 == 0:
                    lineWeb += sData[i] + "\n" #add the current web address to the list of web addresses
                #print("\n"+currentLine[0])
                else:
                    lineTime += str(sData[i]) + "\n" #add the current time stamp to the list of times
        #     #print("\n"+currentLine[1])
        #print(line)
        self.ui.timeInfo.setText(lineTime) #display the times
        self.ui.display_webtraffic.setText(lineWeb) #display the websites
        file.close() #close the file

app = QApplication(sys.argv)
w = AppWindow()
w.show()
sys.exit(app.exec_())

