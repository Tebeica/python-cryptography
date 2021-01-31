import fileinput
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes


# this code encrypts the file inName using AES and writes the output to outName
# the bitlength of key indicates the level of AES, it is assumed to be 128 in this case.
def AESencrypt(key, inName, outName):
    back = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=back)
    enc = cipher.encryptor()



    with open(outName, 'wb') as outfile:

        outfile.write(iv)                               #write the iv to the outfile


        padded_data = pad(inName)
        ctxt = enc.update(padded_data) + enc.finalize()
        outfile.write(ctxt)

def AESdecrypt(key, inName, outName):
    blocksize = 16;
    back = default_backend()

    with open(inName, 'rb') as infile:
        # read in the IV, create cipher.decryptor object
        iv = infile.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=back)
        dec = cipher.decryptor()

        padtxt = bytes(0)

        with open(outName, 'wb') as outfile:
            # read blocks of infile into the decryptor, which finalizes once there is no more to read
            while True:
                block = infile.read(blocksize)
                if len(block) == 0:
                    break
                padtxt += dec.update(block)
            padtxt += dec.finalize()

            # strips the padding from the text and writes to file.
            unpadder = padding.PKCS7(128).unpadder()
            ptxt = unpadder.update(padtxt) + unpadder.finalize()
            #print(ptxt)

            outfile.write(ptxt)


# Input: inbytes, old, new are all bytearrays/bytes
# Scans inbytes and replaces any occurrence of old with new
def bytes_modify(inbytes, old, new):
    mytext = old.encode('utf-8')
    mynewtext = new.encode('utf-8')
    if inbytes.find(mytext):
        #print(inbytes.find(mytext))
        print("found substring, replacing text")
        inbytes = inbytes.replace(mytext, mynewtext)
        return inbytes


# Modified AES decryption, tries to find a substring CODE to check that the
# correct key has been used, then strips padding and alters the file.
# note that the strings are hardcoded, obviously this can be generalized
# the output can now be reencrypted
# return value indicates whther the codeword was found .
def AESdecryptMod(key, inName, outName):
    #print("Running decrypt and modify routine")
    blocksize = 16;
    back = default_backend()

    with open(inName, 'rb') as infile:
        #filesize = int(infile.read(16))
        iv = infile.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=back)
        dec = cipher.decryptor()

        padtxt = bytes(0)

        # decrypts the ciphertext
        with open(outName, 'wb') as outfile:
            while True:
                block = infile.read(blocksize)
                if len(block) == 0:
                    break
                padtxt += dec.update(block)
            padtxt += dec.finalize()

        # scans for bitstring of the keyword
            #print("Finding keyword FOXHOUND")
            if padtxt.find(b'FOXHOUND') > -1:
                print("Bit pattern found")
                unpadder = padding.PKCS7(128).unpadder()
                padtxt = unpadder.update(padtxt) + unpadder.finalize()
                print("padtxt ", padtxt)
                padtxt = bytes_modify(padtxt, "CODE-RED", "CODE-BLUE")
                padtxt = padtxt[0:-20]
                outfile.write(padtxt)

                return 1
            else:
                return 0

##############################################################################
##############################################################################

def pad_oracle(padtxt):
    checkbyte = padtxt[-1];

    goodpad = False
    if checkbyte == 0:
        goodpad = True
    if checkbyte > len(padtxt):
        return 0
    for i in range(checkbyte):
        padtxt[-(i+1)]
        if padtxt[-(i+1)] == checkbyte:
            goodpad = True
        else:
            goodpad = False
            break
            # if you try to use the provided unpadder it yields an error,
            # so you have to check padding yourself
    return goodpad


def pad(inName):
    with open(inName, 'rb') as infile:
        padder = padding.PKCS7(128).padder()
        padded_data = bytes(0)
        blocksize = 16
        while True:
            block = infile.read(blocksize)
            if len(block) == 0:
                break
            padded_data+= padder.update(block)
        padded_data += padder.finalize()
    return padded_data




def hash_string_SHA1(in_string):
    back = default_backend()
    output = ""
    this_hash = hashes.Hash(hashes.SHA1(),back)
    this_hash.update(in_string.encode('utf-8'))
    output = this_hash.finalize()
    return output

def hash_file_SHA1(inName):
    back = default_backend()
    blocksize = 16
    output = ""
    this_hash = hashes.Hash(hashes.SHA1(),back)

    with open(inName, 'rb') as infile:
        while True:
            block = infile.read()
            if len(block) == 0:
                break
            this_hash.update(block)
        output = this_hash.finalize()
        #print("hash length",len(output))
    return output


#takes in a string and returns an appropriately sized
# bytes object using SHA1 and truncating
def get_AESkey(in_string):
    digest = hash_string_SHA1(in_string)
    digest = digest[0:16]
    return digest
##############################################################################
def append_digest(inName, dfile):
    outName = dfile

    inDigest = hash_file_SHA1(inName)
    with open(inName, 'rb') as infile:
        with open(outName, 'wb') as outfile:
            blocksize = 16
            while True:
                block = infile.read(blocksize)
                if len(block) ==0:
                    break
                outfile.write(block)
            outfile.write(inDigest)


def hash_then_encrypt(key, inName, outName):
    intermediate = "digested-"+inName
    append_digest(inName, intermediate)

    AESencrypt(key, intermediate, outName)


    mybytearray = bytes(0)

##############################################################################
##############################################################################
def main():

## check enough arguments
    if(len(sys.argv) < 2):
        print("Error no filename supplied.")
        raise IndexError

    # attack portion, brute force key and scan for keyword
    for i in range(1984, 2021):
        for j in range(1,13):
            for k in range(1,32):
                hashinput = str(i)
                if j < 10:
                    hashinput += str(0)
                hashinput += str(j)
                if k < 0:
                    hashinput+= str(0)
                hashinput += str(k)

                hashout = hash_string_SHA1(hashinput)
                hashout = hashout[0:16]
                flag1 = AESdecryptMod(hashout, sys.argv[1], "modified.txt")
                if flag1 ==1:
                    print("Password found: ", hashinput)
                    return
        if flag1 ==1:
            return



if __name__ == '__main__':
    main()
