# Import modules
from cmd import Cmd
from sys import exit
from os import system
import constants as const
import re
import socket
import os.path


class ClientFtpInterface(Cmd):
    """Simple FTP prompt for client"""

    # store host address and host socket
    host_address = ''
    ftp_cmd_socket = ''
    # override Cmd defaults
    prompt = "ftp> "
    intro = "Type: 'help' for a list of commands"

    ################################
    #    Prompt Command Methods    #
    ################################
    def do_get(self, request):
        """Get command structure for downloading a file form the host
        :type request string
        """
        filename = self.get_file_name(request)

        # loop to get file from server
        if filename:
            self.ftp_cmd_socket.send("%s|%s" % (const.COMMAND_GET, filename))
            self.receive_file()
        else:
            print "Incorrect usage, type 'help' for formatting."

    def do_put(self, request):
        """Op method for sending a file to the host
        :type request string
        """
        file_name = self.get_file_name(request)
        file_path = "%s%s%s" % (const.CLIENT_DOWNLOAD_FOLDER, const.FILE_SEPARATOR, file_name)
        exists = os.path.isfile(file_path)

        if not exists:
            print "No file exists by that the name: %s" % file_name
            return

        # loop to get file from server
        if file_name and exists:
            self.ftp_cmd_socket.send("%s|%s" % (const.COMMAND_PUT, file_name))
            self.send_file(file_name, file_path)
        else:
            print "Incorrect usage, type 'help' for formatting."
            return

    def do_ls(self, args):
        """Query command for host file listing in ftp directory"""
        response = self.make_request(const.COMMAND_LS)
        print response

    def do_clear(self, args):
        """Clears the prompt"""
        system('clear')
        return

    def do_quit(self, args):
        """Quits the program"""
        response = self.make_request(const.COMMAND_QUIT)
        self.ftp_cmd_socket.close()
        exit(response)

    ################################
    #    Command Helper Methods    #
    ################################
    def help_get(self):
        """Describes the get command"""
        self.print_help_method("get", "Download file from host", "get <file>")
        return

    def help_put(self):
        """Describes the put command"""
        self.print_help_method("put", "Upload file from host", "put <file>")
        return

    def help_ls(self):
        """Describes the ls command"""
        self.print_help_method("ls", "List files on the host", "ls")

    def help_clear(self):
        """Describes the clear command"""
        self.print_help_method("clear", "Clear the terminal", "clear")

    def help_quit(self):
        """Describes the quit command"""
        self.print_help_method("quit", "Quits the interface", "quit")

    ################################
    #        Utility Methods       #
    ################################
    def emptyline(self):
        """This overrides the default action for when an emptyline is
        submitted via the prompt window.
        """
        pass

    def print_help_method(self, command, description, example):
        """This prints the formatted help description for a command"""
        msg = "\nHelp for command: %s" \
              "\n========================================" \
              "\n  -Description: %s" \
              "\n  -Example: %s" % (command, description, example)
        print msg

    def store_host_details(self, host_address, sock):
        self.host_address = host_address
        self.ftp_cmd_socket = sock

    def make_request(self, cmd):
        """Send request to server"""
        self.ftp_cmd_socket.send(cmd)
        response = self.ftp_cmd_socket.recv(const.BUFFER_SIZE)
        return response

    def get_file_name(self, args):
        """Gets filename from input string
        :type args string
        :rtype regex match substring
        """
        reg = re.compile("(\w*\.\w*)")
        match = reg.match(args)
        if match:
            return match.group()
        else:
            return None

    def receive_file(self):
        """Receive file from the server"""
        # receive port for file transfer
        transfer_port = self.receive_bytes(self.ftp_cmd_socket, const.HEADER_SIZE)
        transfer_port = int(transfer_port)

        # check if port works
        if transfer_port:
            # Establish connection with host to transfer file
            ftp_transfer_socket = self.create_socket(self.host_address, transfer_port)

            # if we established a connection
            if ftp_transfer_socket:
                file_name_header = self.receive_bytes(ftp_transfer_socket, const.FILENAME_SIZE)
                file_name = file_name_header.translate(None, '0')
                # get header which contains size of file to be transferred
                file_size_header = self.receive_bytes(ftp_transfer_socket, const.HEADER_SIZE)

                file_size = int(file_size_header)
                print "Receiving... %d bytes of data." % file_size
                file_data = self.receive_bytes(ftp_transfer_socket, file_size)

                file_path = "%s%s%s" % (const.CLIENT_DOWNLOAD_FOLDER, const.FILE_SEPARATOR, file_name)

                transfer_file = open(file_path, 'w')
                transfer_file.write(file_data)
                transfer_file.close()

    def send_file(self, file_name, file_path):
        """Get file from host and send to client
        :type file_name string
        :type file_path string
        """
        # use with to ensure file is closed after ops
        with open(file_path, 'r') as file_object:
            # receive port for file transfer
            transfer_port = self.receive_bytes(self.ftp_cmd_socket, const.HEADER_SIZE)
            transfer_port = int(transfer_port)

            # check if port works
            if transfer_port:
                # Establish connection with host to transfer file
                ftp_transfer_socket = self.create_socket(self.host_address, transfer_port)

                if ftp_transfer_socket:
                    # read file, put file size in padded header, prepend header to data
                    data = file_object.read()
                    bytes_sent = 0

                    # receive headers for file
                    file_name_header = self.buffer_header(file_name, const.FILENAME_SIZE)
                    file_size_header = self.buffer_header(str(len(data)), const.HEADER_SIZE)

                    # prepend file name and file size
                    file_data = file_name_header + file_size_header + data

                    # upload data
                    while len(file_data) > bytes_sent:
                        try:
                            bytes_sent += ftp_transfer_socket.send(file_data[bytes_sent:])
                        except socket.error as e:
                            print e
                            return
                    ftp_transfer_socket.close()
                    return

    def receive_bytes(self, sock, size=None):
        """Receives size number of bytes from server
        :type sock socket.socketobject
        :type size integer
        :rtype received string
        """
        # if a size is passed
        if sock and size:
            # initialize local vars
            temp_buffer = ""
            received = ""

            # read input
            while len(temp_buffer) < size:
                temp_buffer = sock.recv(size)

                # if nothing returns
                if not temp_buffer:
                    print "Error: no bytes received from server."
                    break

                # add to received
                received += temp_buffer

            return received
        else:
            print "Error: receive size error."

    def create_socket(self, address, port):
        """Create socket on address and port"""
        # try-except to create socket
        try:
            create_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            create_socket.connect((address, port))
            print "\nConnection to server has been established on port %s ." % port
        except socket.error as socket_error:
            print "Socket Error: %s" % socket_error
            return
        return create_socket

    def buffer_header(self, header, size=10):
        """Buffer the header of a file transfer or response
        :type header string
        :type size int
        :rtype data_size string (padded)
        """
        header = str(header)
        while len(header) < size:
            header = "0" + header
        return header
