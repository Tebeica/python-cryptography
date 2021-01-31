

a=1
b=2

a = a.to_bytes(4,'big')
b = b.to_bytes(4,'big')
print("<"+a.hex()+">", "<"+b.hex()+">")

