import ftpclient as ftp
import os
if not os.path.exists("client-output"):
    os.makedirs("client-output")

ftp_client = ftp.FTPClient("127.0.0.1", 2121)
ftp_client.connect()
ftp_client.login()
print(ftp_client.retrlines("LIST"))
print(ftp_client.retrlines("RETR test"))
print(ftp_client.send_cmd("CWD testdir"))
print(ftp_client.retrlines("RETR test2"))
file = open("uploadtest", "r")
print(ftp_client.storlines("STOR uploadedfile", file))
print(ftp_client.retrlines("LIST"))
