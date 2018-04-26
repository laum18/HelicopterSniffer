import socket
import time

host = '127.0.0.1'
port = 30000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

while True:
    sock.send("Ready".encode())
    sData = sock.recv(1024)
    print(sData.decode())
    print("Download Completed")
    time.sleep(3)

sock.close()


