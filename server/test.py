import sys
import re
from socket import *

import pymysql
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from flag import *


# # 生成server的公私钥
# s_key = RSA.generate(2048)
# s_pri_key = s_key.export_key()
# with open("./keys/s_private.pem", 'wb') as file_obj:
#     file_obj.write(s_pri_key)
#
# s_pub_key = s_key.publickey().export_key()
# with open("./keys/s_public.pem", 'wb') as file_obj:
#     file_obj.write(s_pub_key)



# sess_key = get_random_bytes(16)
# # 生成会话密钥的摘要
# digest = SHA256.new(sess_key)
# # 用client-公钥对会话密钥进行加密
# with open("./keys/c_public.pem", 'rb') as file_obj:
#     c_pub_key = RSA.import_key(file_obj.read())
# en_sess_key = PKCS1_OAEP.new(c_pub_key).encrypt(sess_key)
# # 用server-私钥对摘要进行签名
# with open("./keys/s_private.pem", 'rb') as file_obj:
#     s_pri_key = RSA.import_key(file_obj.read())
# signature = pkcs1_15.new(s_pri_key).sign(digest)
# # 将加密后的会话密钥和签名发送给client
# data = CONN_KEYSEND + en_sess_key + signature
#
# print(data)

# c_socket.send(data)


# sess_key = get_random_bytes(16)
# data = ACON_SIGN
# cipher = AES.new(sess_key, AES.MODE_EAX)
# enc_data, tag = cipher.encrypt_and_digest(data)
# cipher_data = cipher.nonce + tag + enc_data
#
# print(len(cipher_data))
#
# nonce, tag, enc_data = cipher_data[:16], cipher_data[16:32], cipher_data[32:]
# cipher = AES.new(sess_key, AES.MODE_EAX, nonce)
# data = cipher.decrypt_and_verify(enc_data, tag)
#
# if data == ACON_SIGN:
#     print("ha")



# name, psw = "", ""
# data = ACON_SIGN + f"archeriss/Zsd2asd5354".encode()
# ls = data[1:].decode().split("/")
# if len(ls) != 2:
#     print("Oops")
# else:
#     name, psw = ls[0], ls[1]
#
# print(name)
#
# res = re.match(r"^[a-zA-Z0-9_-]{4,16}$", name)
# if res:
#     print("s")
# print(res)
#
# res = re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,16}$", psw)
# if res:
#     print("pass")
# print(res)


# salt = get_random_bytes(32).hex()
# print(type(salt), len(salt), salt)

# name = "hashtest2"
# user_type = "normal"
# psw = "password1"
#
# db = pymysql.connect(
#     host="localhost",
#     port=3306,
#     user="root",
#     password="toor",
#     database="SETrans",
#     charset='utf8mb4'
# )
#
# cursor = db.cursor()
#
#
#
登录
salt = b""
with open("./keys/saltlist", 'r') as file_obj:
    line = file_obj.readline()
    while line:
        if not line.startswith(name + ":"):
            line = file_obj.readline()
            continue
        else:
            salt = bytes.fromhex(line.split(":")[1].strip())
            break

data = psw.encode() + salt
psw_hash = SHA256.new(data).hexdigest()

sql = "SELECT * FROM user WHERE username=%s and password=%s;"

if cursor.execute(sql, (name, psw_hash)):
    print("login successed")
else:
    print("username or password error")




# # 注册
# sql = "SELECT * FROM user WHERE username=%s;"
# res = cursor.execute(sql, (name))
#
# if res > 0:
#     print("exist")
# else:
#     salt = get_random_bytes(32)
#     with open("./keys/saltlist", 'a') as file_obj:
#         file_obj.write(name + ":" + salt.hex() + "\n")
#     data = psw.encode() + salt
#     psw_hash = SHA256.new(data).hexdigest()
#     print(type(psw_hash), len(psw_hash), psw_hash)
#     sql = "INSERT INTO user(username, usertype, password) VALUES(%s, %s, %s);"
#     cursor.execute(sql, (name, user_type, psw_hash))





# db.commit()
# db.close()

