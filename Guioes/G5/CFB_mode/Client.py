# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import os
import asyncio
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


conn_port = 8888
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0
    
    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt +=1
        # ALTERAR AQUI COMPORTAMENTO DO CLIENTE #
        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        #----------------------------------#
        # Encriptation
        key, salt = passwd() #key and salt
        
        cipher = AES.new(key, AES.MODE_CFB) #cipher
        iv = cipher.iv
      
        print('Input message to send (empty to finish)') #ask for the msg
        new_msg = input().encode() #transform in bytes
        
        ct_bytes = cipher.encrypt(new_msg)
        
        #ciphertext, tag = cipher.encrypt_and_digest(new_msg) #ciphertext and validation tag
        #final_msg = nonce + salt + tag + ciphertext #sends ciphertext and nonce,salt,and tag to verify 
        final_msg = salt + iv + ct_bytes
    
        #----------------------------------#
        #final_msg = final_msg + b"welelele" #testar comprometer a mensagem
        return final_msg if len(final_msg)>0 else None


#------------------------PASSWORD TO KEYSTREAM-------------------------------------#

def passwd():
    backend = default_backend()
    salt = os.urandom(16)
    # PBKDF2 derivation function
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
    )
    # pass-phrase
    password = b"1920-TC-G4"
    # Encrypt password with PBKDF2
    key = kdf.derive(password)
    # Return key and salt
    return key, salt


#----------------------------------------------------------------------------------#
#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1',
                                                        conn_port, loop=loop)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()