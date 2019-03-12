import socket

# **Heavily borrowed from FTPLib**

MAXBYTES = 1024
CRLF = '\r\n'
B_CRLF = b'\r\n'

# The FTP specication is in RFC 959
# https://tools.ietf.org/html/rfc959#section-7 
class FTPClient():
    host = ""
    port = 21
    ftp_socket = ""
    file = ""

    def __init__(self, host, port):
        self.host = host
        self.port = port

    # Connecting the way FTPLib does. We use makefile, such that reading/writing to tje socket
    # is more "pythonic"
    # This connection establishes the control socket
    def connect(self):
        address = self.host
        port = self.port
        try:
            #We connect to a TCP socket on (addres, port)
            _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _socket.connect((address, port))
            print("\nControl Connection to server has been established on port %s." % port)
        except socket.error as socket_error:
            print("Socket Error: %s" % socket_error)
            return
        # FTP is a class, so we assign the connected socket to the attribute in the class
        self.ftp_socket = _socket
        # We use makefile to wrap the communication in a python file object
        self.file = self.ftp_socket.makefile('r', encoding="latin-1")
        # When we initially connect to the FTP client, the FTP client sends a greeting repsonse
        # we clear this from the file buffer and throw it into the void 
        self.getresp()
     
    def login(self):
        user = 'anonymous'
        passwd = 'anonymous@'

        resp = self.send_cmd('USER ' + user)
        # We check for a positive status code
        if resp[0] == '3':
            resp = self.send_cmd('PASS ' + passwd)
        # We check for a positive status code again, we raise an error if itøs not a 2xx FTP status code
        if resp[0] != '2':
            raise ValueError("Could not log in! " + str(resp))
        return resp

    def send_cmd(self, cmd):
        self.putline(cmd)
        return self.getresp()

    def putline(self, line):
        if '\r' in line or '\n' in line:
            raise ValueError('an illegal newline character should not be contained')
        line = line + CRLF
        print('*put*', line)
        self.ftp_socket.sendall(line.encode("latin1"))

    def getline(self):
        line = self.file.readline(MAXBYTES)
        if not line:
            raise ValueError("Line is not really a line :(")
        # IF the last 2 elements from the end is a carriage return line feed, 
        # we set the retrieved line as everything but the CRLF
        if line[-2:] == CRLF:
            line = line[:-2]
        # Even if we just have either a carriage return or new line, 
        # we do the same as the above
        elif line[-1:] in CRLF:
            line = line[:-1]
        return line

    def getmultiline(self):
        line = self.getline()
        # first line will begin with the exact required reply code, 
        # followed immediately by a Hyphen, "-". Therefore, we check for that at text index 3
        if line[3:4] == '-':
            # The status code is everything up untill index 3
            code = line[:3]
            while 1:
                # Of course we sill get next lines one by one
                nextline = self.getline()
                # Line will contian a proper representation of the whole data stream
                line = line + ('\n' + nextline)
                # If we somehow encounter a new status code wit ha hyphen, we are at the next 
                # data response, so we break
                if nextline[:3] == code and nextline[3:4] != '-':
                    break
        # line wil contain all lines in the response concatenated by a \n new line escaped char.
        return line

    # we wrap our final message in this getresp method.
    def getresp(self):
        resp = self.getmultiline()
        c = resp[:1]
        # Since we know status codes 1, 2 and 3 are generally "good"
        if c in {'1', '2', '3'}:
            return resp

        raise ValueError(resp)

    def retrlines(self, cmd):
        resp = self.send_cmd('TYPE A')
        with self.transfercmd(cmd) as conn, conn.makefile('r', encoding="latin1") as fp:
            acc_bytes = 1
            split_cmd = cmd.split()
            possible_file = None
            if len(split_cmd) == 2 and split_cmd[0] == "RETR":
                possible_file = open("./client-output/" +  split_cmd[1],"w+")
                print("Starting file print of file " + split_cmd[1])
            while 1:
                line = fp.readline(MAXBYTES)
                if not line:
                    break
                # If the accumulative number of bytes does not exceed 1024 (maxbytes)
                # we print the file contents to terminal
                if acc_bytes <= MAXBYTES:
                    print(repr(line)[0:(MAXBYTES-acc_bytes)])
                # Same logic as in getline. We check if there is a line ending in the current data stream 
                if possible_file:
                     possible_file.write(line)

                if line[-2:] == CRLF:
                    line = line[:-2]
                elif line[-1:] == '\n':
                    line = line[:-1]
                # We have an accumulative byte variable to keep track of what we need to print
                acc_bytes += len(line)
        return self.voidresp()

    def transfercmd(self, cmd):
        # We make sure we follow up on the Data connection creation that the 
        # server negotiates
        with self.makeport() as sock:
            resp = self.send_cmd(cmd)
            # See above.
            if resp[0] == '2':
                resp = self.getresp()
            if resp[0] != '1':
                raise ValueError(resp)
            conn, _ = sock.accept()
        return conn

    #This method is not changed from FTPLib.
    def makeport(self):
        #Create a new socket and send a PORT command for it.
        err = None
        sock = None
        for res in socket.getaddrinfo(None, 0, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, _, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
                print(sa)
                sock.bind(sa)
            except OSError as _:
                err = _
                if sock:
                    sock.close()
                sock = None
                continue
            break
        if sock is None:
            if err is not None:
                raise err
            else:
                raise OSError("getaddrinfo returns an empty list")
        sock.listen(1)
        port = sock.getsockname()[1] # Get proper port
        host = self.ftp_socket.getsockname()[0] # Get proper host
        resp = self.sendport(host, port)
        return sock

    # This method is also borrowed from FTPLib
    def sendport(self, host, port):
        #Send a PORT command with the current host and the given port number.
        hbytes = host.split('.')
        pbytes = [repr(port//256), repr(port%256)]
        bytes = hbytes + pbytes
        cmd = 'PORT ' + ','.join(bytes)
        return self.voidcmd(cmd)

    def voidcmd(self, cmd):
        self.putline(cmd)
        return self.voidresp()

    def voidresp(self):
        resp = self.getresp()
        if resp[:1] != '2':
            raise ValueError(resp)
        return resp

    def storlines(self, cmd, fp):
        # we set transfer type to Ascii with the "TYPE" FTP command
        self.voidcmd('TYPE A')
        with self.transfercmd(cmd) as conn:
            while 1:
                buf = fp.readline(MAXBYTES)
                if len(buf) > MAXBYTES:
                    raise Error("got more than %d bytes" % MAXBYTES)
                if not buf:
                    break
                # Here B_CRLF is used, which is a binary string that can be used in place of a byte type
                if buf[-2:] != B_CRLF:
                    if buf[-1].encode('ascii') in B_CRLF: buf = buf[:-1]
                    buf = buf.encode('ascii') + B_CRLF
                conn.sendall(buf)
        return self.voidresp()
