from cmd import Cmd
from sys import exit
from os import system
import re
import socket
import os.path

# **Heavily borrowed from FTPLib**

MAXLINE = 8192
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

    # Connecting the way FTPLib does. We use makefile, such that reading/writing to hte socket
    # is more "pythonic"
    def connect(self):
        address = self.host
        port = self.port
        try:
            #We connect to a TCP socket on (addres, port)
            _socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            _socket.connect((address, port))
            print("\nConnection to server has been established on port %s ." % port)
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
 
    def login(self,):
        user = 'anonymous'
        passwd = 'anonymous@'
        acct = ''

        resp = self.send_cmd('USER ' + user)
        if resp[0] == '3':
            resp = self.send_cmd('PASS ' + passwd)
        if resp[0] == '3':
            resp = self.send_cmd('ACCT ' + acct)
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
        line = self.file.readline(MAXLINE + 1)
        if len(line) > MAXLINE:
            raise Error("got more than %d bytes" % MAXLINE)
        if not line:
            raise EOFError
        if line[-2:] == CRLF:
            line = line[:-2]
        elif line[-1:] in CRLF:
            line = line[:-1]
        return line

    def getmultiline(self):
        line = self.getline()
        if line[3:4] == '-':
            code = line[:3]
            while 1:
                nextline = self.getline()
                line = line + ('\n' + nextline)
                if nextline[:3] == code and \
                        nextline[3:4] != '-':
                    break
        return line

    def getresp(self):
        resp = self.getmultiline()
        c = resp[:1]
        if c in {'1', '2', '3'}:
            return resp
        if c == '4':
            raise error_temp(resp)
        if c == '5':
            raise error_perm(resp)
        raise error_proto(resp)

    def retrlines(self, cmd):
        resp = self.send_cmd('TYPE A')
        with self.transfercmd(cmd) as conn, \
                 conn.makefile('r', encoding="latin1") as fp:
            while 1:
                line = fp.readline(MAXLINE + 1)
                if len(line) > MAXLINE:
                    raise Error("got more than %d bytes" % MAXLINE)
                print('*retr*', repr(line))
                if not line:
                    break
                if line[-2:] == CRLF:
                    line = line[:-2]
                elif line[-1:] == '\n':
                    line = line[:-1]
            # shutdown ssl layer
        return self.voidresp()

    def transfercmd(self, cmd, rest=None):
        size = None
        with self.makeport() as sock:
            if rest is not None:
                self.send_cmd("REST %s" % rest)
            resp = self.send_cmd(cmd)
            # See above.
            if resp[0] == '2':
                resp = self.getresp()
            if resp[0] != '1':
                raise error_reply(resp)
            conn, sockaddr = sock.accept()
        if resp[:3] == '150':
            # this is conditional in case we received a 125
            size = parse150(resp)
        return conn
    def makeport(self):
        '''Create a new socket and send a PORT command for it.'''
        err = None
        sock = None
        for res in socket.getaddrinfo(None, 0, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
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
    def sendport(self, host, port):
        '''Send a PORT command with the current host and the given
        port number.
        '''
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