# Name: Tebeica Teodor
# UCID: 30046038
# CPSC418 Tutorial 04
# Assignment 1 - Question 6
# Name: modifyFile.py

# Note: The file created by this program is called tampFile 

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys
import os
import cryptography
from datetime import timedelta, date

backend = default_backend()

# Create an array of possible date values of the formate YYYYMMDD
# code reference: 
# https://www.w3resource.com/python-exercises/date-time-exercise/python-date-time-exercise-50.php
def daterange(date1, date2):
    for n in range(int ((date2 - date1).days)+1):
        yield date1 + timedelta(n)

start_dt = date(1984, 1, 1)
end_dt = date(2020, 2, 12)
password = []
for dt in daterange(start_dt, end_dt):
    password.append(dt.strftime("%Y%m%d"))

# opens the ciphertext file and casts it to byte array
cipherTextFile = sys.argv[1]
with open(cipherTextFile, "rb") as inputFile:
    giveMeBytes = bytearray(inputFile.read())

# runs through every possible password to determine the one used to 
# derive the encryption key 
# decrypts the ciphertext using this key
for i in range(0,len(password)):
    var = password[i]
    digest = hashes.Hash(hashes.SHA1(), backend)
    digest.update(bytes(var, "utf-8"))
    
    key = digest.finalize()
    key = key[:16]
    
    iv = giveMeBytes[:16]       #exclusive 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
    decryptor = cipher.decryptor()
    dec = decryptor.update(giveMeBytes[16:]) + decryptor.finalize()
    
    if b"FOXHOUND" in dec:
        foundPass = password[i]
        decryption = dec
        print("The original plaintext: ")
        print(dec)
        print("\nThe password used to encrypt is: " + password[i])
        break
    
# checks the resulting plaintext for the phrase CODE-RED, replaces that
# with CODE-BLUE
if b"CODE-RED" in dec:
    dec = dec.replace(b"CODE-RED", b"CODE-BLUE")
    print("\nThe modified plaintext: ")
    print(dec)

# writes the output to a new file
output = open("tampFile", "wb")
output.write(dec)
