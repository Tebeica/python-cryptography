import socket
import secrets
import sys, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import sympy
#HOST = '127.0.0.1'  # The server's hostname or IP address. This is the local host address
#PORT = 65432 
HOST = '127.0.4.18'
PORT = 31802


# Function that takes in two byte arrays as argument, concatenates them
#and then outputs the SHA256 hash as an integer
def hashBytes(a, b):
    concat = b"".join([a,b])
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(concat)
    return int.from_bytes(digest.finalize(), 'big')
    

#Initialization protocol
print("Please enter a username: ")
uname = sys.stdin.readline().strip()
#encode it as bytes
unameBytes = uname.encode('utf-8')
#store length of bytes
unamelength = len(unameBytes).to_bytes(4, 'big')

#
print("Please enter a password: ")
pword = sys.stdin.readline().strip()


#Generates a salt using a secure random number generator
salt = secrets.randbits(128)
saltBytes = salt.to_bytes(16, 'big')


#Registration protocol
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    conn.connect((HOST, PORT))
    
    #receive N and g from the server
    nBytes = conn.recv(64)         
    gBytes = conn.recv(64)
            
    #convert from bytes to int
    g = int.from_bytes(gBytes, 'big')
    N = int.from_bytes(nBytes, 'big')
    

    #computes x = H(s||p)
    x = hashBytes(saltBytes, pword.encode('utf-8'))
    
    
    #computes v = g^x (mod N)
    v = pow(g,x,N)
    
    
    #computes k = H(N,g)
    k = hashBytes(nBytes, gBytes)


    print("Client: I =", "'"+uname+"'")
    sys.stdout.flush()
    print("Client: p =", pword)
    print("Client: N =", str(N))
    sys.stdout.flush()
    print("Client: g =", str(g))
    print("Client: k =", str(k))
    print("Client: s =", "<"+saltBytes.hex()+">")
    sys.stdout.flush()
    print("Client: x =", str(x))
    sys.stdout.flush()
    #discard of x
    x = 0
    print("Client: v =", str(v))
    
    
    print("Client: Sending flag", "<"+"r".encode('utf-8').hex()+">")
    sys.stdout.flush()
    print("Client: Sending |I|", "<"+unamelength.hex()+">")
    sys.stdout.flush()
    print("Client: Sending I", "<"+unameBytes.hex()+">")
    sys.stdout.flush()
    
    toSend = b"".join(["r".encode('utf-8'), unamelength, uname.encode('utf-8'), saltBytes, v.to_bytes(64, 'big')])
    conn.send(toSend)
    print("Client: Sending v", "<"+v.to_bytes(64, 'big').hex()+">")

    print("Client: Registration successful.")
    sys.stdout.flush()
    #close connection after registration
    conn.close()


#Negotiation protocol
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
    conn.connect((HOST, PORT))
    
    #receive N and g from the server, again
    nBytes = conn.recv(64)
    gBytes = conn.recv(64)
    #convert N and g from byte to int
    N = int.from_bytes(nBytes, 'big')
    g = int.from_bytes(gBytes, 'big')
    
    print("Client: N =", str(N))
    print("Client: g =", str(g))
    
    print("Client: k =", str(k))
    #Protocol begins
    a = secrets.randbelow(N-2)        #must geq to p-1, check documentation
    A = pow(g, a, N)
    print("Client: a =", str(a))
    print("Client: A =", str(A))
    sys.stdout.flush()

    
    print("Client: Sending flag", "<"+b'p'.hex()+">")
    conn.send(b"p")
    sys.stdout.flush()
    
    print("Client: Sending |I|", "<"+unamelength.hex()+">")
    sys.stdout.flush()
    conn.send(unamelength)
    
    print("Client: Sending I", "<"+unameBytes.hex()+">")
    sys.stdout.flush()
    conn.send(unameBytes)
    
    print("Client: Sending A", "<"+ A.to_bytes(64, 'big').hex()+">")
    sys.stdout.flush()
    conn.send(A.to_bytes(64, 'big'))
    
    
    #receive salt back from server
    serverSaltBytes = conn.recv(16)
    print("Client: s =", "<"+serverSaltBytes.hex()+">")
    
    #receive server's authentication bytes
    serverAuthBytes = conn.recv(64)                     #refers to B
    serverAuth = int.from_bytes(serverAuthBytes, 'big')
    print("Client: B =", str(serverAuth))
    
    
    #compute u
    u = hashBytes(A.to_bytes(64, 'big'), serverAuthBytes) % N
    print("Client: u =", str(u))
    sys.stdout.flush()
    
    #compute x again
    x = hashBytes(saltBytes, pword.encode('utf-8'))
    
    
    #compute K_client
    k_client = pow((serverAuth-(k*v)), (a+(u*x)), N)
    print("Client: k_client =", str(k_client))
    
    #compute and send M_1
    M_1_1 = b"".join([A.to_bytes(64, 'big'), serverAuthBytes])
    M_1 = hashBytes(M_1_1, k_client.to_bytes(64, 'big'))
    print("Client: M1 =", "<"+M_1.to_bytes(32, 'big').hex()+">")
    #print("Client: M1 =", "<"+M_1.to_bytes(64, 'big').hex()+">")
    sys.stdout.flush()
    
    #print("Client: Sending M_1", "<"+M_1.to_bytes(64, 'big').hex()+">") 
    #sys.stdout.flush()
    conn.send(M_1.to_bytes(32, 'big'))
    
    #receive M_2 to be checked and confirm negotiation
    M2_bytes = conn.recv(32)
    M_2 = int.from_bytes(M2_bytes, 'big')
    print("Client: M2 =", "<"+M2_bytes.hex()+">")
    
    #compute a derivation of M_2 and check if matching
    checker_1 = b"".join([A.to_bytes(64, 'big'), M_1.to_bytes(32, 'big')])
    checker = hashBytes(checker_1, k_client.to_bytes(64,'big'))
    
    #check if negotiation was successful and print confirmation
    if (checker == M_2):
        print("Client: Negotiation successful.")
        sys.stdout.flush()
    else:
        print("Client: Negotiation unsuccessful.")
        sys.stdout.flush()
        conn.close()
    conn.close()