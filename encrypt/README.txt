README - CPSC418 Introduction to Cryptography - Assignment 1
Name - Teodor Tebeica

Files submitted: modifyFile.py, encryptFile.py

    modifyFile.py  
        Parementers:
            [ciphertext-filename]: file to be read, decrypted and potentially
            modified. 
            This program creates a list of all the dates possible 
            between 1984 (January 1st) and 2020 (February 12th) in the format
            YYYYMMDD and uses that to find the password that Bob used to encrypt
            his file -- for each password (date), the program applies Bob's hash-
            then-encrypt routine to check if we can turn the ciphertext into plaintext.
            It iterates through every password and checks the plaintext it creates for
            the phrase "FOXHOUD" -- if found, then we have the right password. And it can now
            be displayed to the command line. It also looks for all instances of "CODE-RED"
            and replaces them with "CODE-BLUE" and writes this plaintext to a new 
            file called "tampFile".
    
    encryptFile.py
        Parameters:
            [plaintext-filename]: file to read potentially modified plaintext
            [tampered-filename]: name of file to write the encrypted text to
            [password]: correc tpassword found in previous algorithm and was printed
            to the command line
            THis program implements Bob's hash-then-encrypt routine and applies it to 
            the plaintext file using the password. The result is written to a new file
            (tampered-filename).
        