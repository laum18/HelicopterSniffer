import socket 
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("", 30001))
sock.listen(1)
print("waiting for connection")
(s, address) = sock.accept()
print("accepted connection")

while True:        
    s.setblocking(1)
    m = s.recv(32768)
    print(m)
    with open("websites.txt", 'r') as f:
        content = f.read(32768)
        data = []
        time = []
        toggle = True
        add = False
        while content:
            content = content.replace("\n\n", ",").split(",")
            print("content ", content)
            for c in content:
                www = c.find("www.")
                if www != -1:
                    c = c[www+4:]
                    print("if www != -1:", c)

                c = c.strip()
                if toggle:
                    if c not in data:
                        print("appending to data", c)
                        data.append(c)
                        add = True
                    toggle = False
                else:
                    if add:
                        print("appending to time", c)
                        time.append(c)
                        add = False
                    toggle = True
            print("data:", data)
            sendOver = ""
            for i in range(len(data)-1):
                sendOver += data[i]
                print(data[i])
                sendOver += "," + time[i] + "\n\n"
            s.send(sendOver.encode())
            print("data sent")
            content = f.read(32768)
    print("Done sending")
    #print("sleeping")
    #time.sleep(5)
    
s.close()
sock.close()
