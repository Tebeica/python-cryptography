# Name: Tebeica Teodor
# UCID: 30046038
# CPSC418 Tutorial 04
# Assignment 1 - Question 6
# Name: encryptFile.py


from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography
import os
import sys

backend = default_backend()
# reads command line arguments and assigns to propper variables
plainTextfile = sys.argv[1]
cipherTextfile = sys.argv[2]
passDate = bytes(sys.argv[3], "utf-8")

#Converts the plaintext to a byte array
with open(plainTextfile, "rb") as inputFile:
    giveMeBytes = bytearray(inputFile.read())   # <-- byte array of plaintext

#computes hash tag on the plaintext and appends it to byte array
digest = hashes.Hash(hashes.SHA1(), backend)
digest.update(giveMeBytes)
partDigest = digest.finalize()[:16]

#generates new 16-byte array
iv = os.urandom(16)

# creates an extended plain text by concatenating the original byte array
# with the digest (hash)
extendedPlainText = giveMeBytes
extendedPlainText.join([extendedPlainText, partDigest])

# creates password digest by hashing the password text using SHA1
passDigest = hashes.Hash(hashes.SHA1(), backend)
passDigest.update(passDate)
key = passDigest.finalize()[:16]

# use PKCS7 to pad the modified file in order to be able to use it in 
# AES-128-CBC
padder = padding.PKCS7(128).padder()
paddedArray = padder.update(bytes(extendedPlainText))

# encrypts the extended byte array
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
ciphText = cipher.encryptor().update(paddedArray) + cipher.encryptor().finalize()

# writes the encrypted text to a file
with open(cipherTextfile, "wb") as outputFile:
    out = iv + ciphText
    outputFile.write(out)


inputFile.close()
outputFile.close()