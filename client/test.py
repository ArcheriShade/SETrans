import sys
from socket import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256



# import flag
#
# data = flag.CONN_INITOK
# data += "Connection succeeded".encode()
#
# print(data)
#
# code = data[0].to_bytes(1, 'big')
#
# print(type(code), code)
# if code == flag.CONN_INITOK:
#     print("same")
#
# s = data[1:]
# print(type(s), s)
# s = data[1:].decode()
# print(type(s), s)



# # 生成client的公私钥
# c_key = RSA.generate(2048)
# c_pri_key = c_key.export_key()
# with open("./keys/c_private.pem", 'wb') as file_obj:
#     file_obj.write(c_pri_key)
#
# c_pub_key = c_key.publickey().export_key()
# with open("./keys/c_public.pem", 'wb') as file_obj:
#     file_obj.write(c_pub_key)


socket = socket(AF_INET, SOCK_STREAM)
socket.connect(("10.10.10.1", 7777))
input()
socket.close()

