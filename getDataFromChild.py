import threading
from subprocess import call
import os

class DataLaunch(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        call(["./a.out"])
        return

class SendToParent():
    def run(self):
        os.system("python3.6 sendToParent.py")

if __name__ == "__main__":
    dl = DataLaunch()
    dl.start()
    stp = SendToParent()
    stp.run()
