from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography
import os
import sys

backend = default_backend()
plainTextfile = sys.argv[1]
cipherTextfile = sys.argv[2]
passDate = bytes(sys.argv[3],'utf-8')

#Converts the plaintext to a byte array
with open(plainTextfile, "rb") as inputFile:
    giveMeBytes = bytearray(inputFile.read())   # <-- byte array of plaintext

#computes hash tag on the plaintext and appends it to byte array
digest = hashes.Hash(hashes.SHA1(), backend)
digest.update(giveMeBytes)
some = digest.finalize()[:16]       #check out
iv = os.urandom(16)

extendedPlainText = giveMeBytes
extendedPlainText.join([extendedPlainText,some])

passDigest = hashes.Hash(hashes.SHA1(), backend)
passDigest.update(passDate)

key = passDigest.finalize()[:16]

padder = padding.PKCS7(128).padder()
paddedArray = padder.update(bytes(extendedPlainText))

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
ciphText = cipher.encryptor().update(paddedArray) + cipher.encryptor().finalize()

with open(cipherTextfile, "wb") as outputFile:
    out = iv + ciphText
    outputFile.write(out)


inputFile.close()
outputFile.close()
