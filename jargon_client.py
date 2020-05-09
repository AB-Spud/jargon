import json
import selectors
import socket
import sys
import types

from jargon_message import Message
from jargon_database import DBClient

class Client(object):
    def __init__(self, config, sid):
        self.HOST = config['HOST']
        self.PORT = config['PORT']
        self.BUFFSIZE = config['BUFFSIZE']
        self.KEY = config['KEY']
        self.UID = config['UID']
        self.SID = sid

        self.connection_status = False
        self.server = None
    
    def connect(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.connect((self.HOST, self.PORT))
            self.server_name = self.server.getpeername()
            self.send_data(self.SID, 'client_data')
            return True
        except Exception as error:
            return False
    
    def disconnect_from_server(self):
        self.send_data('disconnect_request', 'disconnect_request')
        self.server.shutdown(2)
        self.server.close()

    def recieve_data(self):
        try:
            self.package  = self.server.recv(self.BUFFSIZE)
            self.msg = Message(self.package, self.KEY)
            self.msg.unpack()
            self.msg.decrypt()

            return f"{self.msg.msg_info.uid}: {self.msg.msg_info.msg}"
        except Exception as error:
            if type(error) == ConnectionResetError:
                # raise error
                print("connection reset")
            else:
                raise error
    
    def send_data(self, data, header):
        # Check headers first to decide if info was sent that needs to be updated - such as connected users
        try:
            if header == 'message':
                self.package = {'header': 'message', 'message': data, 'uid': self.UID}

            elif header == 'client_data':
                self.package = {'header': 'client_data', 'sid': data, 'uid': self.UID}
            
            elif header == 'disconnect_request':
                self.package = {'header': 'disconnect_request', 'data': data}
            
            self.msg = Message(self.package, self.KEY)
            self.msg.encrypt()
            self.msg.pack()

            self.server.send(self.msg.package)
        except Exception as error:
            if type(error) == ConnectionResetError:
                return error
            else:
                raise error

if __name__ == '__main__':
    with open("key", 'rb') as data:
        key = data.read(16)

    cfg = {"HOST": "127.0.0.1","PORT": 9999,"BACKLOG": 10,"BUFFSIZE": 4096,"KEY": key,"UID": "Server"}
    dbclient = DBClient(cfg)
    dbclient.connect()
    r = dbclient.login('1', '1')
    print(r.resp, r.res)
    config = r.srv_lst['local_host']
    print(r.uid)
    config['KEY'] = key
    config['UID'] = r.uid

    client = Client(config, '8970')

    while True:
        a = client.recieve_data()
        print(a)
        b = input('--> ')
        client.send_data(b, 'message')
    
