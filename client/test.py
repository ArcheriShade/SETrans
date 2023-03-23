import flag

data = flag.CONN_INITOK
data += "Connection succeeded".encode()

print(data)

code = data[0].to_bytes(1, 'big')

print(type(code), code)
if code == flag.CONN_INITOK:
    print("same")

s = data[1:]
print(type(s), s)
s = data[1:].decode()
print(type(s), s)
