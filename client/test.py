import os
import sys
import json
import shutil
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


# socket = socket(AF_INET, SOCK_STREAM)
# socket.connect(("10.10.10.1", 7777))
# input()
# socket.close()





# file_info = []
# file_ls = os.listdir("./filehub")
# print(type(file_ls), len(file_ls))
#
# ls_data = json.dumps(file_ls)
# print(type(ls_data), len(ls_data))
#
# enc_data = ls_data.encode()
# print(type(enc_data), len(enc_data))
#
# ls = json.loads(enc_data)
# print(type(ls), len(ls))

file_info = []
file_ls = os.listdir("./filehub")
for file in file_ls:
    file_info.append((file, os.stat(f"./filehub/{file}").st_size))
print(file_info)

ls_data = json.dumps(file_info)
print(type(ls_data), len(ls_data))

enc_data = ls_data.encode()
print(type(enc_data), len(enc_data))

ls = json.loads(enc_data)
print(type(ls), len(ls))

total_b, used_b, free_b = shutil.disk_usage("./filehub")
print(f"可用空间：{free_b} byte")
