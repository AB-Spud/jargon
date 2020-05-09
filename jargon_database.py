import json
import selectors
import socket
import sys
import os
import types
import hashlib

from jargon_message import Message

# Add versioning to Chat_Client and Chat_Server

class DBClient(object):
    def __init__(self, config):
        self.HOST = config['HOST']
        self.PORT = config['PORT']
        self.BUFFSIZE = config['BUFFSIZE']
        self.KEY = config['KEY']
        self.sel = selectors.DefaultSelector()
    
    def connect(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.connect((self.HOST, self.PORT))
            print(f'Connected to: {self.HOST}:{self.PORT}')
            return True
        except Exception as error:
            return False
            raise error       

    def login(self, username, password):
        self.package = {'header': 'login_request', 'pwrd': password, 'uid': username}
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()

        try:
            self.server.send(self.msg.package)
        except Exception as error:
            raise error

        try:
            self.recv_data = self.server.recv(self.BUFFSIZE)
        except Exception as error:
            raise error

        self.msg = Message(self.recv_data, self.KEY)
        self.msg.unpack()
        self.msg.decrypt()
        self.response = self.msg.namespace

        return self.response
    
    def signup(self, username, password):
        self.package = {'header': 'signup_request', 'pwrd': password, 'uid': username}
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()

        try:
            self.server.send(self.msg.package)
        except Exception as error:
            raise error

        try:
            self.recv_data = self.server.recv(self.BUFFSIZE)
        except Exception as error:
            raise error

        self.msg = Message(self.recv_data, self.KEY)
        self.msg.unpack()
        self.msg.decrypt()
        self.response = self.msg.namespace

        return self.response
    
    def request_server(self, server_name, password):
        self.package = {'header': 'server_request', 'pwrd': password, 'uid': server_name}
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()

        try:
            self.server.send(self.msg.package)
        except Exception as error:
            raise error

        try:
            self.recv_data = self.server.recv(self.BUFFSIZE)
        except Exception as error:
            raise error

        self.msg = Message(self.recv_data, self.KEY)
        self.msg.unpack()
        self.msg.decrypt()
        self.response = self.msg.namespace

        return self.response
    
    def register_server(self, config, server_name, password, server_id):
        self.config = str(json.dumps(config))
        self.package = {'header': 'register_server', 'srv_cfg': self.config,'pwrd': password, 'uid': server_name, 'sid': server_id}
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()

        try:
            self.server.send(self.msg.package)
        except Exception as error:
            raise error

        try:
            self.recv_data = self.server.recv(self.BUFFSIZE)
        except Exception as error:
            raise error

        self.msg = Message(self.recv_data, self.KEY)
        self.msg.unpack()
        self.msg.decrypt()
        self.response = self.msg.namespace

        return self.response   

    def unregister_server(self, server_name, password):
        self.package = {'header': 'unregister_server','pwrd': password, 'uid': server_name}
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()

        try:
            self.server.send(self.msg.package)
        except Exception as error:
            raise error

        try:
            self.recv_data = self.server.recv(self.BUFFSIZE)
        except Exception as error:
            raise error

        self.msg = Message(self.recv_data, self.KEY)
        self.msg.unpack()
        self.msg.decrypt()
        self.response = self.msg.namespace

        return self.response

    def delete_account(self, username, password):
        self.package = {'header': 'delete_request', 'pwrd': password, 'uid': username}
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()

        try:
            self.server.send(self.msg.package)
        except Exception as error:
            raise error

        try:
            self.recv_data = self.server.recv(self.BUFFSIZE)
        except Exception as error:
            raise error

        self.msg = Message(self.recv_data, self.KEY)
        self.msg.unpack()
        self.msg.decrypt()
        self.response = self.msg.namespace

        return self.response  

class DBServer(object):
    def __init__(self, config):
        self.HOST = config['HOST']
        self.PORT = config['PORT']
        self.BACKLOG = config['BACKLOG']
        self.BUFFSIZE = config['BUFFSIZE']
        self.KEY = config['KEY']
        self.UID = config['UID']
        self.DB = DBManager(config['DB_path'])
        self.sel = selectors.DefaultSelector()

    def __accept_connection__(self, sock):
        self.conn, self.addr = sock.accept()
        self.conn.setblocking(False)
        self.data = types.SimpleNamespace(addr=self.addr)
        self.events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(self.conn, self.events, data=self.data)

        print(f"Connected: {self.data.addr} - Client Connection")
    
    def __handle_request__(self, rdata, key):
        self.sock = key.fileobj
        self.sock_data = key.data

        print(f"Request from: {self.sock_data.addr}")

        self.data = Message(rdata, self.KEY)
        self.data.unpack()
        self.data.decrypt()

        if self.data.header == 'signup_request':
            self.signup_info = self.data.namespace
            self.check = self.DB.sign_up(self.signup_info.uid, self.signup_info.pwrd)

            if self.check:
                self.srv_lst = self.DB.get_servers()
                self.package = {'header': 'signup_response', 'uid': self.signup_info.uid,'resp': 'accepted', 'res': 'sign-up success','srv_lst': self.srv_lst}
            else:
                self.package = self.package = {'header': 'signup_response', 'uid': self.signup_info.uid, 'resp': 'denied', 'res': 'username is taken','srv_lst': str(json.dumps({'None': 'None'}))}
            
        elif self.data.header == 'login_request':
            self.login_info = self.data.namespace
            self.check = self.DB.login(self.login_info.uid, self.login_info.pwrd)

            if self.check:
                self.srv_lst = self.DB.get_servers()
                self.package = self.package = {'header': 'login_response', 'uid': self.login_info.uid,'resp': 'accepted', 'res': 'login success', 'srv_lst': self.srv_lst}
            else:
                self.package = self.package = {'header': 'login_response', 'uid': self.login_info.uid, 'resp': 'denied','res': 'no such user exists / invalid credentials', 'srv_lst': str(json.dumps({'None': 'None'}))}
        
        elif self.data.header == 'delete_request':
            self.delete_info = self.data.namespace
            self.check = self.DB.delete_account(self.delete_info.uid, self.delete_info.pwrd)

            if self.check:
                self.package = self.package = {'header': 'delete_response', 'resp': 'accepted', 'res': 'account was deleted'}
            else:
                self.package = self.package = {'header': 'delete_response', 'resp': 'denied','res': 'invalid credentials'}

        elif self.data.header == 'server_request':
            self.server_info = self.data.namespace
            self.check = self.DB.request_server(self.server_info.uid, self.server_info.pwrd)

            if self.check:
                self.srv_cfg = self.DB.get_server(self.server_info.uid)
                self.package = self.package = {'header': 'server_response', 'resp': 'accepted', 'res': 'server config was sent', 'srv_cfg': self.srv_cfg}
            else:
                self.package = self.package = {'header': 'server_response', 'resp': 'denied','res': 'incorrect credentials', 'srv_cfg': str(json.dumps({'None': 'None'}))}

        elif self.data.header == 'register_server':
            self.register_info = self.data.namespace
            self.check = self.DB.register_server(self.register_info.srv_cfg, self.register_info.uid, self.register_info.pwrd, self.register_info.sid)

            if self.check:
                self.package = self.package = {'header': 'register_response', 'resp': 'accepted', 'res': 'server was registered'}
            else:
                self.package = self.package = {'header': 'register_response', 'resp': 'denied','res': 'server already registered'}
    
        elif self.data.header == 'unregister_server':
            self.unregister_info = self.data.namespace
            self.check = self.DB.unregister_server(self.unregister_info.uid, self.unregister_info.pwrd)

            if self.check:
                self.package = self.package = {'header': 'unregister_response', 'resp': 'accepted', 'res': 'server was unregistered'}
            else:
                self.package = self.package = {'header': 'unregister_response', 'resp': 'denied','res': 'invalid server credentials'}

        print(f"Sent response to: {self.sock_data.addr}")
        self.msg = Message(self.package, self.KEY)
        self.msg.encrypt()
        self.msg.pack()
        self.sock.send(self.msg.package)

    def __service_connection__(self, key, mask, events):
        self.sock = key.fileobj
        self.data = key.data

        try:
            if mask & selectors.EVENT_READ:
                self.recv_data = self.sock.recv(self.BUFFSIZE)
                if self.recv_data:
                    self.__handle_request__(self.recv_data, key)
                else:
                    self.sel.unregister(self.sock)
                    self.sock.close()
                    print(f"Disconnected: {self.data.addr} - Client Closed_1")
            else:
                pass

        except Exception as error:
            if type(error) is ConnectionResetError:
                print(f"Disconnected: {self.data.addr} - Client Closed_2")
                self.sel.unregister(self.sock)
                self.sock.close()
                
            else:
                raise error
            
    def __event_loop__(self):
        while True:
            self.events = self.sel.select(timeout=None)
            for self.key, self.mask in self.events:
                if self.key.data is None:
                    self.__accept_connection__(self.key.fileobj)
                else:
                    self.__service_connection__(self.key, self.mask, self.events)

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.HOST, self.PORT))
        self.server.listen(self.BACKLOG)
        self.server.setblocking(False)
        self.sel.register(self.server, selectors.EVENT_READ, data=None)
        print("Database is now online...")
        self.__event_loop__()

class DBManager(object):
    def __init__(self, location):
        self.path_ = '\\'.join(location.split('\\')[:-1])
        self.location = location
        self.database = json.load(open(location))
    
    def __save_db_state__(self):
        try:
            json.dump(self.database, open(self.location, "w"), indent=4)
            print(f"Data Base Updated!")
        except Exception as error:
            raise error
    
    def manage_server_status(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for self.kval in self.database['servers'].keys():
            self.host = self.database['servers'][self.kval]['HOST']
            self.port = self.database['servers'][self.kval]['PORT']
            self.result = self.sock.connect_ex((self.host,self.port))
            if self.result == 0:
                self.database['servers'][self.kval]['STATUS'] = True
            else:
                self.database['servers'][self.kval]['STATUS'] = False
        
        self.__save_db_state__()
    
    def get_dkey(self):
        self.key_path = os.path.join(self.path_, 'key')
        if os.path.isfile(self.key_path):
            with open("key", 'rb') as self.data:
                self.dkey = self.data.read(16)
                self.data.close()
            return self.dkey
        else:
            return 'could not find path to key file'

    def get_servers(self):
        return str(json.dumps(self.database['servers']))
    
    def get_server(self, server_name):
        return str(json.dumps(self.database['servers'][server_name]))

    def request_server(self, server_name, pwrd):
        self.pwrd = pwrd.encode('utf-8')
        self.hashed_pwrd = hashlib.sha256(self.pwrd).hexdigest()
        if server_name in self.database['server_registry'].keys():
            if self.database['server_registry'][server_name] == self.hashed_pwrd and server_name in self.database['servers'].keys():
                del self.hashed_pwrd
                return True
            else:
                del self.hashed_pwrd
                return False
        else:
            del self.hashed_pwrd
            return False 
    
    def register_server(self, config, uid, pwrd, sid):
        self.pwrd = pwrd.encode('utf-8')
        self.hashed_pwrd = hashlib.sha256(self.pwrd).hexdigest()
        
        if uid in self.database['server_registry'].keys():
            del self.hashed_pwrd
            return False
        else:
            self.database['server_registry'][uid] = self.hashed_pwrd
            self.add_server(uid, config, sid)
            self.__save_db_state__()
            return True

    def add_server(self, server_name, config, sid):
        self.sid = sid.encode('utf-8')
        self.hashed_sid = hashlib.sha256(self.sid).hexdigest()

        self.database['servers'][server_name] = config
        self.database['servers'][server_name]['SID'] = self.hashed_sid
        self.__save_db_state__()
    
    def unregister_server(self, server_name, pwrd):
        if self.server_login(server_name, pwrd):
            del self.database['server_registry'][server_name]
            self.remove_server(server_name)
            self.__save_db_state__()
            return True
        else:
            return False

    def remove_server(self, server_name):
        del self.database['servers'][server_name]
        self.__save_db_state__()    

    def update_server_var(self, server_name, var, new_var):
        self.database['servers'][server_name][var] = new_var
        self.__save_db_state__()

    def server_login(self, uid, pwrd):
        self.pwrd = pwrd.encode('utf-8')
        self.hashed_pwrd = hashlib.sha256(self.pwrd).hexdigest()
        if uid in self.database['server_registry'].keys():
            if self.database['server_registry'][uid] == self.hashed_pwrd:
                del self.hashed_pwrd
                return True
            else:
                del self.hashed_pwrd
                return False
        else:
            del self.hashed_pwrd
            return False 

    def login(self, uid, pwrd):
        self.pwrd = pwrd.encode('utf-8')
        self.hashed_pwrd = hashlib.sha256(self.pwrd).hexdigest()
        if uid in self.database['client_data'].keys():
            if self.database['client_data'][uid] == self.hashed_pwrd:
                del self.hashed_pwrd
                return True
            else:
                del self.hashed_pwrd
                return False
        else:
            del self.hashed_pwrd
            return False     
    
    def sign_up(self, uid, pwrd):
        self.pwrd = pwrd.encode('utf-8')
        self.hashed_pwrd = hashlib.sha256(self.pwrd).hexdigest()

        if uid in self.database['client_data'].keys():
            del self.hashed_pwrd
            return False
        else:
            self.database['client_data'][uid] = self.hashed_pwrd
            self.__save_db_state__()
            return True
    
    def delete_account(self, uid, pwrd):
        if self.login(uid, pwrd):
            del self.database['client_data'][uid]
            self.__save_db_state__()
            return True
        else:
            return False


if __name__ == "__main__":
    pass
