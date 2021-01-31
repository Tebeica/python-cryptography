#!/usr/bin/env python3

###### INCLUDES

import secrets
from shared import *
import socket
import sys


###### VARIABLES

# map usernames to salt/scrambled hash pairs
uname_db = dict()


###### METHODS

def send_N_q( sock, N_bytes, g_bytes ):
    sendbytes( sock, [(N_bytes,'N'), (g_bytes,'g')] )


def send_salt_B( sock, salt, B_bytes ):
    sendbytes( sock, [(salt,'salt'), (B_bytes,'B')] )


def recv_I( sock ):

    # the length of the username, followed by the username itself
    uname_len = int.from_bytes( recvbytes(sock, 4), 'big' )
    uname = recvbytes( sock, uname_len )

    print( f"Server: Username = '{uname.decode('utf-8')}'." )
    return uname


def do_protocol( sock, I=None, A_bytes=None ):
    global N, N_bytes, g, g_bytes, k, uname_db

    # this offers implementation flexibility
    if I is None:
        I    = recv_I( sock )

    if I not in uname_db:

        print( f"Server: Client asked for user '{I.decode('utf-8')}', who hasn't", end='')
        print(  " been registered. Closing socket." )

        return False

    # defer on checking I until after we've secured A

    if A_bytes is None:
        A_bytes = recvbytes( sock, MIN_BYTES )

    A       = int.from_bytes(A_bytes, 'big')
    print( f"Server: A = {A}" )


    # pull the salt and v from storage
    salt, v = uname_db[I]
    print( f"Server: s = <{salt.hex()}>" )
    print( f"Server: v = {v}" )


    # calculate B
    b       = secrets.randbelow(N-1)
    print( f"Server: b = {b}" )

    B_power = pow(g, b, N)
    B       = (k*v + B_power) % N
    B_bytes = int_to_bytes( B, MIN_BYTES )

    print( f"Server: B = {B}" )

    send_salt_B( sock, salt, B_bytes )

    u_bytes = hash_bytes(A_bytes + B_bytes)
    u = int.from_bytes(u_bytes, 'big')
    print( f"Server: u = {u}" )

    k_server = pow( A*pow(v,u,N), b, N )
    print( f"Server: k_server = {k_server}" )
    k_server_bytes = int_to_bytes( k_server, MIN_BYTES )

    M1_server = hash_bytes( A_bytes + B_bytes + k_server_bytes )

    # wait for M1
    M1 = recvbytes( sock, MIN_BYTES )
    print( f"Server: M1 = <{M1.hex()}>" )

    if M1 == M1_server:

        # don't bother with M2 in the failure case
        M2 = hash_bytes( A_bytes + M1 + k_server_bytes )
        print( f"Server: M2 = <{M2.hex()}>" )

        sendbytes( sock, [(M2,'M2')] )
        print( "Server: Negotiation successful." )
        return True

    else:

        print( "Server: Negotiation unsuccessful.")
        return False


def do_register( sock, I=None, salt=None, v=None ):
    global uname_db

    # this offers implementation flexibility
    if I is None:
        I    = recv_I( sock )

    if salt is None:
        salt = recvbytes( sock, SALT_BYTES )

    if v is None:
        v_bytes = recvbytes( sock, MIN_BYTES )
        v       = int.from_bytes(v_bytes, 'big')

    print( f"Server: s = <{salt.hex()}>" )
    print( f"Server: v = {v}" )

    uname_db[I] = (salt,v)
    print( f"Server: user {I.decode('utf-8')} registered." )

    return True


###### MAIN

# generate a safe prime and generator of the appropriate size
print( "Server: Generating N ...", end='' )
N = safeprime( MIN_BITS )
print( " done." )

print( "Server: Generating g ...", end='' )
g = get_prim( N )

print( " done." )

print( f"Server: N = {N}" )
print( f"Server: g = {g}" )

N_bytes = int_to_bytes( N, MIN_BYTES )
g_bytes = int_to_bytes( g, MIN_BYTES )

k_bytes = hash_bytes( N_bytes + g_bytes )
k = int.from_bytes( k_bytes, 'big' )
print( f"Server: k = {k}" )


# create a socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    print( 'Server: Listening for client (Ctrl-C to kill).' )
    s.bind((HOST, PORT))

    # loop until we're told to stop
    while True:

        print( f"Server: Waiting for a connection." )

        s.listen()
        conn, addr = s.accept()

        print( f"Server: Client connected from {addr}." )

        # join the new socket created during acceptance
        with conn as c:

            try:
                # set a reasonable timeout
                c.settimeout( 15 )

                # start with the shared functionality
                send_N_q( c, N_bytes, g_bytes )

                good = True
                while good:         # loop until something breaks

                    # what sort of packet are we dealing with?
                    mode = c.recv( 1 )
                    print( f"Server: mode = '{mode.decode('utf-8')}'" )

                    if mode == b'p':
                        good = do_protocol( c )

                    elif mode == b'r':
                        good = do_register( c )

                    else:
                        print( f"Server: Got unknown mode {mode}, closing socket." )
                        raise ValueError()


                    sys.stdout.flush()


            except:
                print( "Exception caught: {}: {}".format( *sys.exc_info()[:2] ) )
            finally:
                sys.stdout.flush()
                c.shutdown( socket.SHUT_RDWR )
                c.close()
