import socket
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import sympy
import time
from sympy import *
import math
import secrets
#HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
#PORT = 65432  
HOST = '127.0.4.18'
PORT = 31802

def hashBytes(a, b):
    concat = b"".join([a,b])
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(concat)
    return int.from_bytes(digest.finalize(), 'big')
    

N = 0 
q = 0
isPrime = False
#the smallest number of 511 bits
lowerBound = 0x40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
while (not isPrime):
    q = sympy.randprime(lowerBound, pow(2,511)+1)
    while(not sympy.isprime(q)):
        q = secrets.randbits(511)
    N = 2*q + 1
    if(sympy.isprime(N)):
        isPrime = True

    
print("Server: N =", str(N))
sys.stdout.flush()

findG = False
while (not findG):
    g = secrets.randbelow(N-1)
    if(pow(g, (N-1)//2, N) != 1):
        if(pow(g, (N-1)//g, N) != 1):
            findG = True
print("Server: g =", str(g))
sys.stdout.flush()

nBytes = N.to_bytes(64, 'big')
gBytes = g.to_bytes(64, 'big')

k = hashBytes(nBytes, gBytes)
print("Server: k =", str(k))


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    print("server listening...")
    sys.stdout.flush()
    s.listen()
    conn, addr = s.accept()
    
    with conn:
        print("Connected by ", addr)
        sys.stdout.flush()
        
        
        
        #Send over a tuple (N, g) as bytes
        toSend = b"".join([nBytes, gBytes])
        #print("Server: Sending (N, g)","<"+nBytes.hex()+">", "'", "<"+gBytes.hex()+">")      
        print("Server: Sending N", "<"+nBytes.hex()+">")
        print("Server: Sending g", "<"+gBytes.hex()+">")
        sys.stdout.flush()
        conn.send(toSend)
        
        
        #takes out the useless byte
        useless = conn.recv(1)
        print("Server: flag =", useless.decode('utf-8'))
        #records the lenght of the username that was encoded as 4 bytes
        unameLength = conn.recv(4)
        unameBytes = conn.recv(int.from_bytes(unameLength, 'big'))
        print("Server: |I| =", int.from_bytes(unameLength, 'big'))
        #saves the user's name
        user = unameBytes.decode('utf-8')
        print("Server: I =", "'"+user+"'")
        
        #records salt received
        saltBytes = conn.recv(16)
        salt = int.from_bytes(saltBytes, 'big')
        print("Server: s =", "<"+saltBytes.hex()+">")
        
        #records the variable v received
        vBytes = conn.recv(64)
        v = int.from_bytes(vBytes, 'big')
        print("Server: v =", str(v))
        sys.stdout.flush()
        
        print("Server: Registration successful.")
        sys.stdout.flush()
        
    s.listen()
    conn, addr = s.accept()
    with conn:
        print("Connected by", addr)
        #sys.stdout.flush()
        
        conn.send(nBytes)
        print("Server: Sending N", "<"+nBytes.hex()+">")
        sys.stdout.flush()
        conn.send(gBytes)
        print("Server: Sending g", "<"+gBytes.hex()+">")
        sys.stdout.flush()
        
        #receive ('r', |I|, I, A)
        flagBytes = conn.recv(1)
        flag = flagBytes.decode('utf-8')
        print("Server: flag =", flag)
        
        userLengthBytes = conn.recv(4)
        userLength = int.from_bytes(userLengthBytes, 'big')
        print("Server: |I| =", userLength)
        
        userBytes = conn.recv(userLength)
        username2 = userBytes.decode('utf-8')
        print("Server: I =", "'"+username2+"'")

        aBytes = conn.recv(64)
        A = int.from_bytes(aBytes, 'big')
        print("Server: A =", str(A))
        
        
        #generate a random value b, use it to compute B
        b = secrets.randbelow(N-1)
        print("Server: b =", str(b))
        sys.stdout.flush()

        B = ((k * v) % N + pow(g,b,N)) % N
        sys.stdout.flush()

        
        #send server authentication (s, B)
        auth_key = b"".join([saltBytes, B.to_bytes(64, 'big')])
        conn.send(auth_key)
        print("Server: Sending s", "<"+saltBytes.hex()+">")
        sys.stdout.flush()
        print("Server: Sending B", "<"+B.to_bytes(64, "big").hex()+">")
        sys.stdout.flush()
        
        #compute u = H(A, B)
        u = hashBytes(aBytes, B.to_bytes(64, 'big')) % N
        print("Server: u =", str(u))
        sys.stdout.flush()
        
    
        #generate K_server = (A(v^u))b % N
        first = pow(A, b, N)
        second = pow(v, (u*b), N)
        k_server = (first * second) % N
        print("Server: K_server =", str(k_server))
        
        
        #receive M_1 to be verified
        M1_bytes = conn.recv(64)
        M1 = int.from_bytes(M1_bytes, 'big')
        print("Server: M1 =", "<"+M1_bytes.hex()+">")
        
        
        #server computes a derivation of M1 using k_server
        checker_1 = b"".join([aBytes, B.to_bytes(64, 'big')])
        checker = hashBytes(checker_1, k_server.to_bytes(64, 'big'))
        
        #check negotiation 
        if (checker == M1):
            print("Server: Negotiation successful.")
            sys.stdout.flush()
        else: 
            print("Server: Negotiation unsuccessful.")
            sys.stdout.flush()
            conn.close()
            
        #server computes and sends M_2 in order to confirm to client
        M_2_1 = b"".join([aBytes, M1_bytes])
        M_2 = hashBytes(M_2_1, k_server.to_bytes(64, 'big'))
        conn.send(M_2.to_bytes(32, 'big'))
       
        print("Server: Sending M2", "<"+M_2.to_bytes(32, 'big').hex()+">")
        sys.stdout.flush()
        