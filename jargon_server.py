import selectors
import socket
import sys
import types
import hashlib

from jargon_message import Message
from jargon_database import DBClient

class Server(object):
    def __init__(self, config, in_key):
        self.HOST = config['HOST']
        self.PORT = config['PORT']
        self.BACKLOG = config['BACKLOG']
        self.BUFFSIZE = config['BUFFSIZE']
        self.UID = config['UID']
        self.SID = config['SID']
        self.KEY = in_key
        self.sel = selectors.DefaultSelector()

        self.clients = {}

    def __event_loop__(self):
        while True:
            self.events = self.sel.select(timeout=None)
            for self.key, self.mask in self.events:
                if self.key.data is None:
                    self.accept_connection(self.key.fileobj)
                else:
                    if self.server.connect_ex(self.key.data.addr):
                        self.__service_conn__(self.key, self.mask, self.events)
                    else:
                        self.sel.unregister(self.key.fileobj)
                        self.key.fileobj.close()
                        self.send_server_msg(f"{self.key.data.addr} disconnected")

    def __service_conn__(self, key, mask, events):
        self.sock = key.fileobj
        self.data = key.data

        try:
            if mask & selectors.EVENT_READ:
                self.recv_data = self.sock.recv(self.BUFFSIZE) 
                if self.recv_data:
                    self.msg = Message(self.recv_data, self.KEY)
                    self.msg.unpack()
                    self.msg.decrypt()
                    if self.msg.package['header'] == 'message':
                        self.__start_send_requests__(events, self.recv_data)
                    elif self.msg.package['header'] == 'status_request':
                        self.send_status_data(self.msg.namespace.req, self.sock)  
                    elif self.msg.package['header'] == 'client_data':
                        self.manage_clients(key, self.msg.namespace)
                    elif self.msg.package['header'] == 'disconnect_request':
                        self.sel.unregister(self.sock)
                        self.sock.close()
                        self.send_server_msg(f"{self.data.addr} disconnected...")
                        print(f"{self.data.addr} disconnected...")
                else:
                    try:
                        self.sel.unregister(self.sock)
                        self.sock.close()
                        self.send_server_msg(f"Disconnected '{self.data.addr}' client stopped sending data...")
                        print(f"Disconnected '{self.data.addr}' client stopped sending data...")
                    except Exception as error:
                        raise error
            else:
                pass

        except Exception as error:
            if type(error) is ConnectionResetError:
                print(f"{self.data.addr} disconnected...")
                self.sel.unregister(self.sock)
                self.sock.close()
                self.send_server_msg(f"{self.data.addr} disconnected")
            else:
                raise error

    def __send_data__(self, key, mask, outb_data):
        self.sock = key.fileobj
        self.data = key.data

        if self.data.uid == None:
            self.sock.close()
            self.sel.unregister(self.sock)
            print('Client did not send client_data pack.')
        else:
            try:
                if mask & selectors.EVENT_WRITE:
                    self.sock.send(outb_data)
                    print('sent data to: ', self.data.addr)
            except Exception as error:
                if type(error) == ConnectionResetError:
                    self.sel.unregister(self.sock)
                    self.sock.close()
                    self.send_server_msg(f"Disconnected '{self.data.addr}' client lost connection...")

                else:
                    raise error
    
    def __start_send_requests__(self, events, outb_data):
        for self.key, self.mask in events:
            if self.key.data is None:
                pass
            else:
                self.__send_data__(self.key, self.mask, outb_data)
    
    def send_status_data(self, request, sock):
        if request == 'connected_clients':
            pass
        # sock.send('')

    def send_server_msg(self, msg):
        self.events = self.sel.select(timeout=None)
        self.package = {'header': 'message', 'message': msg, 'uid': self.UID}
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()

        self.__start_send_requests__(self.events, self.msg.package)
    
    def manage_clients(self, key, cdata):
        self.sock = key.fileobj
        self.data = key.data
        if hashlib.sha256(cdata.sid.encode('utf-8')).hexdigest() == self.SID:
            self.clients[cdata.uid] = self.data.addr
            self.data.uid = cdata.uid
        else:
            print(f"Disconnected {self.data.addr} invalid SID...")
            self.sel.unregister(self.sock)
            self.sock.close()
            self.send_server_msg(f"Disconnected {self.data.addr} invalid SID")
            
        self.send_server_msg(f"{self.data.addr} connected...")
        print(f"{self.data.addr} connected...")
                    
    def accept_connection(self, sock):
        self.conn, self.addr = sock.accept()
        self.conn.setblocking(False)
        self.data = types.SimpleNamespace(addr=self.addr, uid=None)
        self.events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(self.conn, self.events, data=self.data)

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.HOST, self.PORT))
        self.server.listen(self.BACKLOG)
        self.server.setblocking(False)
        self.sel.register(self.server, selectors.EVENT_READ, data=None)
        print("Server started...")

        self.__event_loop__()

if __name__ == '__main__':
    with open("key", 'rb') as data:
        key = data.read(16)

    cfg = {"HOST": "127.0.0.1","PORT": 9999,"BACKLOG": 10,"BUFFSIZE": 4096,"KEY": key,"UID": "Server"}
    client = DBClient(cfg)
    client.connect()
    r = client.request_server('local_host', '1234')
    print(r.resp, "," ,r.res)
    server = Server(r.srv_cfg, key)
    server.start()

