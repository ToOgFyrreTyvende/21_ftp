# Group 21's FTP client submission
This is the FTP client assignment submission for Group 21. Course: 62577 Datakommunikation F19.

# Running the program
In order to run the implementation we've made, one must first install the pyftpdlib. This is done with
`pip install -r requirements.txt`
We use pyftpdlib to run the **SERVER** not the client.

The server is configured to run on port 2121. This lets us run the program without elevated privileges from the OS. The server also allows anonymous file uploads.
Run the server with `python ftp-server/ftpserver.py`. With the server running, in another terminal session, run `python main.py` to run the ftp client program. 

The `main.py` file 
 1. Connects to the FTP server running on 127.0.0.1:2121 
 2. Logs in as an anonymous user
 3. Issues "LIST" (list directory contents) FTP protocol command to the FTP control socket connection
 4. Retrieves "LIST" data on data socket connection
 5. Issues "RETR" (retrieve file) FTP protocol command for file "test" on control
 6. Retrieves file contents on data connection
 7. Issues "CWD" (change working directory) FTP protocol command for directory "testdir" on control
 8. Repeat steps 5-6 for file "test2" (we're now in directory "testdir") 
 9. Attempts to upload file "uploadtest" from root directory of source files onto the server (note: we're still in directory "testdir" so this is where it will be put)
 10. Repeat step 3-4
