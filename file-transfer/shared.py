###### INCLUDES

import math
import secrets
import sympy
import sys
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


###### VARIABLES

# math params
MIN_BYTES = 64
MIN_BITS = MIN_BYTES << 3

SALT_BYTES = 16

# networking params
HOST = '127.0.4.18'
PORT = 31802


###### METHODS

def int_to_bytes( val, bytelen=None ):

    if bytelen is None:
        bytelen = (val.bit_length() + 7) >> 3

    return val.to_bytes(bytelen, 'big')

def safeprime( bits=512 ):

    # q must be one bit less than N
    maximum = 1 << bits
    q = secrets.randbits(bits-1) | (1 << (bits-2))    # the high bit must be set

    if (q != 2):   # rule out even numbers, excluding 2
        q |= 1

    while True:     # TODO: check if entire range has been exhausted

        if sympy.isprime( q ):
            cand = (q<<1) + 1
            if sympy.isprime( cand ):
                return cand

        if q == 2:      # rule out even numbers, special-casing 2
            q = 3
        else:
            q += 2

        if q >= maximum:
            q = 1 << (bits-2)

#checks if a is a primitive root of p where p is a prime
def check_prim(n,g):

    if sympy.gcd(n,g) != 1:
        return False;

    group   = n-1
    factors = sympy.ntheory.primefactors(n-1)
    exp = [(group//i) for i in factors]

    for e in exp:
        if pow(g, e, n) == 1:
            return False
    return True

def get_prim(n):
    for i in range(2,n):
        if check_prim(n,i):
            return i
    return 0;


def hash_bytes(b, backend=default_backend()):

    this_hash = hashes.Hash( hashes.SHA256(), backend )
    this_hash.update(bytes( b ))
    return this_hash.finalize()

def recvbytes( sock, length ):
    """Loop until a specific number of bytes has been received."""

    old_timeout = sock.gettimeout()
    sock.settimeout(1)

    retVal = bytes()
    remain = length - len(retVal)
    while remain > 0:
        try:
            retVal += sock.recv(remain)
        except:
            pass    # prevent the exception from propagating up
        finally:
            sock.settimeout( old_timeout )
            return retVal
        remain = length - len(retVal)

    return retVal

def sendbytes( sock, array, source='Server' ):
    """Send at least one byte array across the given socket."""

    for pair in array:
        bytearr, name = pair
        print( f"{source}: Sending {name} <{bytearr.hex()}>" )
        sock.sendall( bytearr )
