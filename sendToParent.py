import socket 

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("", 30000))
sock.listen(1)
print("waiting for connection")
(s, address) = sock.accept()
print("accepted connection")

with open("websites.txt", 'r') as f:
    content = f.read(1024)
    while content:
        s.send(content.encode())
        content = f.read(1024)
s.close()
sock.close()
    