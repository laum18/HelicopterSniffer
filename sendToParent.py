import socket 
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("", 30000))
sock.listen(1)
print("waiting for connection")
(s, address) = sock.accept()
print("accepted connection")

while True:        
    s.setblocking(1)
    m = s.recv(1024)
    print(m)
    with open("websites_test.txt", 'r') as f:
        content = f.read(1024)
        while content:
            content = content.replace("\n\n", ",").split(",")
            data = []
            time = []
            toggle = True
            add = False
            for c in content:
                if toggle:
                    if c not in data:
                        data.append(c)
                        add = True
                    toggle = False
                else:
                    if add:
                        time.append(c)
                        add = False
                    toggle = True

            sendOver = ""
            for i in range(len(data)-1):
                sendOver += data[i]
                sendOver += "," + time[i] + "\n\n"
            s.send(sendOver.encode())
            print("data sent")
            content = f.read(1024)    
    print("Done sending")
    #print("sleeping")
    #time.sleep(5)
    
s.close()
sock.close()