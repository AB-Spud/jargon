import ast
import json
import types

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class Message(object):
    def __init__(self, *args):
        self.package = args[0]
        self.key = args[1]
    
    def __gen_namespace__(self):
        self.var_list = ['ver', 'uid', 'pwrd', 'sid', 'resp', 'res', 'srv_cfg', 'srv_lst', 'msg', 'req']
        self.namespace = types.SimpleNamespace(uid=None, pwrd=None, sid=None, req=None,resp=None, res=None, msg=None, srv_lst=None, srv_cfg=None)
        for self.var in self.var_list:
            if self.var not in self.package.keys():
                self.package[self.var] = None
                
        self.namespace = types.SimpleNamespace(ver=self.package['ver'], uid=self.package['uid'], pwrd=self.package['pwrd'], sid=self.package['sid'], req=self.package['req'],resp=self.package['resp'], res=self.package['res'], msg=self.package['msg'], srv_lst=self.package['srv_lst'], srv_cfg=self.package['srv_cfg'])   

    
    def pack(self):
        try:
            self.package = json.dumps(self.package).encode('utf-8')
        except Exception as error:
            raise error
    
    def unpack(self):
        try:
            self.package = self.package.decode()
            self.package = ast.literal_eval(self.package)
        except Exception as error:
            raise error
      
    def encrypt(self):
        try:
            self.cipher = AES.new(self.key, AES.MODE_CBC)
            for self.key_val in self.package.keys():
                if self.key_val != 'header':
                    if self.key_val != 'srv_lst':
                        if self.key_val != 'srv_cfg':
                            self.val = self.package[self.key_val].encode('utf-8')
                            self.ct_bytes = self.cipher.encrypt(pad(self.val, AES.block_size))
                            self.package[self.key_val] = b64encode(self.ct_bytes).decode('utf-8')

            self.package['init_vector'] = b64encode(self.cipher.iv).decode('utf-8')

        except Exception as error:
            raise error
        
    def decrypt(self):
        self.init_vector = b64decode(self.package['init_vector'])
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.init_vector)
        for self.key_val in self.package.keys():
            if self.key_val == 'header':
                self.header = self.package[self.key_val]
                
            elif self.key_val == 'init_vector':
                self.package['init_vector'] = b64decode(self.package['init_vector'])

            elif self.key_val == 'srv_lst':
                self.package['srv_lst'] = json.loads(self.package['srv_lst'])

            elif self.key_val == 'srv_cfg':
                self.package['srv_cfg'] = json.loads(self.package['srv_cfg'])

            else:
                self.val = b64decode(self.package[self.key_val])
                self.package[self.key_val] = unpad(self.cipher.decrypt(self.val), AES.block_size).decode('utf-8')

        self.__gen_namespace__()

    def encrypt_str(self, string):
        self.str_inf = types.SimpleNamespace(string=None, iv=None)
        try:
            self.cipher = AES.new(self.key, AES.MODE_CBC)
            self.string = string.encode('utf-8')
            self.ct_bytes = self.cipher.encrypt(pad(self.string, AES.block_size))
            self.str_inf.string = b64encode(self.ct_bytes).decode('utf-8')
            self.str_inf.iv = b64encode(self.cipher.iv).decode('utf-8')
        except Exception as error:
            raise error
            
    def decrypt_str(self, string, iv):
        try:
            self.init_vector = b64decode(iv)
            self.cipher = AES.new(self.key, AES.MODE_CBC, self.init_vector)
            self.string = unpad(self.cipher.decrypt(b64decode(string)), AES.block_size).decode('utf-8')
            self.str_inf = types.SimpleNamespace(string=self.string, iv=self.init_vector)
        except Exception as error:
            raise error

if __name__ == "__main__":
    key = get_random_bytes(16)
    package = {'header': 'message', 'message': '1234', 'uid': 'will'}
    # msg.encrypt_str('hi')
    # print(msg.str_inf.string)
    # msg.decrypt_str(msg.str_inf.string, msg.str_inf.iv)
    # print(msg.str_inf.string)
    msg = Message(package, key)
    msg.encrypt()
    msg.pack()
    print(msg.package)
    msg.unpack()
    msg.decrypt()
    print(msg.package)