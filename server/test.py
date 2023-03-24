import sys
from socket import *
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


sess_key = get_random_bytes(16)
data = ACON_SIGN
cipher = AES.new(sess_key, AES.MODE_EAX)
enc_data, tag = cipher.encrypt_and_digest(data)
cipher_data = cipher.nonce + tag + enc_data

print(len(cipher_data))

nonce, tag, enc_data = cipher_data[:16], cipher_data[16:32], cipher_data[32:]
cipher = AES.new(sess_key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(enc_data, tag)

if data == ACON_SIGN:
    print("ha")
