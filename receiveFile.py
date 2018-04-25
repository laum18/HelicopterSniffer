import socket

host = '10.17.3.75'
port = 30000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

sFileName = "website.txt"
sData = "Temp"

while True:
#    sock.send(sFileName)
    sData = sock.recv(1024)
    fDownloadFile = open(sFileName, "wb")
    while sData:
        print("Waiting")
        fDownloadFile.write(sData)
        sData = sock.recv(1024)
    print("Download Completed")
    break

sock.close()


