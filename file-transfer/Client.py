#!/usr/bin/env python3

###### INCLUDES

import os

import secrets
from shared import *
import socket
import sys

import time


###### VARIABLES

# temp storage, to ensure these have proper scope
N = 0
g = 0
a = 0
A = 0
A_bytes = 0


###### METHODS

def send_I_s_v( sock, I, s, v ):

    len_I = int_to_bytes(len(I), 4)

    sendbytes( sock, [ \
            (b'r','mode'), (len_I,'len(username)'), \
            (I,'username'), (s,'salt'), (v,'v')], 'Client' )

def send_I_A( sock, I, A ):

    len_I = int_to_bytes(len(I), 4)

    sendbytes( sock, [ \
            (b'p','mode'), (len_I,'len(username)'), \
            (I,'username'), (A,'A')] , 'Client' )


###### MAIN

print( "Input username: ", end='' )
sys.stdout.flush()
uname = sys.stdin.readline().encode('utf-8')[:-1] # encode and trim off the LF

print( "Input password: ", end='' )
sys.stdout.flush()
pw = sys.stdin.readline().encode('utf-8')[:-1]


salt = int_to_bytes( secrets.randbits( SALT_BYTES<<3 ), \
        SALT_BYTES )
print( f"Client: s = <{salt.hex()}>" )


x_bytes = hash_bytes( salt + pw )
x       = int.from_bytes(x_bytes, 'big')
print( f"Client: x = {x}" )


# create a socket connection to the server, 5 second timeout
with socket.create_connection( (HOST, PORT), 5) as sock:

    # enable keepalive
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1 )

    # retrieve N and q
    N_bytes = recvbytes( sock, MIN_BYTES )
    N       = int.from_bytes( N_bytes, 'big' )
    print( f"Client: N = {N}" )

    g_bytes = recvbytes( sock, MIN_BYTES )
    g       = int.from_bytes( g_bytes, 'big' )
    print( f"Client: g = {g}" )


    a = secrets.randbelow(N-1)
    print( f"Client: a = {a}" );

    A = pow(g, a, N);
    print( f"Client: A = {A}" );
    A_bytes = int_to_bytes(A, MIN_BYTES)

    v = pow(g, x % (N-1), N )
    print( f"Client: v = {v}" );
    v_bytes = int_to_bytes(v, MIN_BYTES)


    send_I_s_v( sock, uname, salt, v_bytes )
    print("Client: Registration successful.")

    sock.shutdown( socket.SHUT_RDWR )
    sock.close()

time.sleep(1)

with socket.create_connection( (HOST, PORT), 5) as sock:

    # enable keepalive
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1 )

    # retrieve N and q
    N_bytes = recvbytes( sock, MIN_BYTES )
    g_bytes = recvbytes( sock, MIN_BYTES )

    N       = int.from_bytes( N_bytes, 'big' )
    print( f"Client: N = {N}" )
    g       = int.from_bytes( g_bytes, 'big' )
    print( f"Client: g = {g}" )

    print( "Client: Sending ('p',I,A)." )
    send_I_A( sock, uname, A_bytes )


    # Receive s and B from the server
    salt    = recvbytes( sock, SALT_BYTES )
    B_bytes = recvbytes( sock, MIN_BYTES )

    print( f"Client: s = <{salt.hex()}>" )
    B       = int.from_bytes(B_bytes, 'big')
    print( f"Client: B = {B}" )


    u_bytes = hash_bytes(A_bytes + B_bytes)
    u       = int.from_bytes(u_bytes, 'big')
    print( f"Client: u = {u}" )

    k_bytes = hash_bytes( N_bytes + g_bytes )
    k       = int.from_bytes( k_bytes, 'big' )
    print( f"Client: k = {k}" )


    # compute the shared secret
    client_base = (B - k*v) % N
    client_exp  = (a + u*x) % (N-1)
    k_client    = pow(client_base, client_exp, N)

    print( f"Client: k_client = {k_client}" )
    k_client_bytes = int_to_bytes( k_client, MIN_BYTES )


    # validate said shared secret
    M1 = hash_bytes( A_bytes + B_bytes + k_client_bytes )
    print( f"Client: M1 = <{M1.hex()}>" )
    sendbytes( sock, [(M1,'M1')], 'Client' )

    M2 = recvbytes( sock, len(M1) )

    print( f"Client: M2 = <{M2.hex()}>" )
    M2_client = hash_bytes( A_bytes + M1 + k_client_bytes )


    if M2 == M2_client:
        print( "Client: Negotiation successful." )
    else:
        print( "Client: Negotiation unsuccessful." )
        raise ValueError()

    sock.shutdown( socket.SHUT_RDWR )
    sock.close()

