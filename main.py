import ftp
import time
client = ftp.FTPClient("localhost", 2121)
client.connect()
client.login()
print(client.retrlines("list"))
