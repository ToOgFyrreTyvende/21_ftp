import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Socket Created")
port = 2121
host = "127.0.0.1"
ip = socket.gethostbyname(host)

print(ip)
print("ip of " +host+ " is " +ip)

s.connect ((ip, port))
print("Socket Connected to "+host+" on ip "+ ip)

reply = ''
while True:
    message = "LIST\r\n"
    reply += str(s.recv(1024))
    if not reply:
        break
    if '220 Only anonymous FTP is allowed here' in reply:
        s.sendall(message)
        break    
reply += s.recv(65535)
print(reply)