import modifyFile
import fileinput
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes





##############################################################################
def main():

    # Error check to make sure the correct number of arguments
    if(len(sys.argv) < 3):
        print("Error no filename supplied.")
        raise IndexError

    # hashes the password with SHA1
    hashout = modifyFile.hash_string_SHA1(sys.argv[3])
    # truncates the hash output so that it can act as an AES key
    hashout = hashout[0:16]

    modifyFile.hash_then_encrypt(hashout, sys.argv[1], sys.argv[2])
    # attack portion


if __name__ == '__main__':
    main()
