from Crypto.Cipher import AES
from Crypto import Random
import sys
import os
import struct

def encrypt():
    filename = raw_input("Please enter the filename to be encrypted with its path: ")
    outfilename = filename + ".enc"
    ivgen = Random.new()
    iv = ivgen.read(AES.block_size)
    modechoice = raw_input("Please specify the mode to use.\n1) CBC\n2) ECB\n3) CFB\n4) CTR\n5) OFB\nEnter: ")
    mode = AES.MODE_CBC
    if modechoice == '1':
        mode = AES.MODE_CBC
    elif modechoice == '2':
        mode = AES.MODE_ECB
    elif modechoice == '3':
        mode = AES.MODE_CFB
    elif modechoice == '4':
        mode = AES.MODE_CTR
    elif modechoice == '5':
        mode = AES.MODE_OFB
    else:
        print "Not a valid choice"
        sys.exit(1)
    key = raw_input("Please provide a key of length 16, 24, or 32: ")
    keylength = len(key)
    if keylength - 16 != 0 and keylength - 24 != 0 and keylength - 32 != 0:
        print 'Incorrect key length'
        sys.exit(1)
    encryptor = AES.new(key,mode, iv)
    filesize = os.path.getsize(filename)

    with open(filename, 'rb') as filetoencrypt:
        with open(outfilename, 'wb') as encryptedfile:
            encryptedfile.write(struct.pack('<Q', filesize))
            encryptedfile.write(iv)

            while True:
                chunk = filetoencrypt.read(64)
                length = len(chunk)
                if length == 0:
                    break
                elif length % 16 != 0: # if chunk not big enough then pad with spaces
                    chunk += ' ' * (16 - length % 16)

                encryptedfile.write(encryptor.encrypt(chunk))

def decrypt():
    filename = raw_input("Please enter the filename to be decrypted with its path: ")
    modechoice = raw_input("Please enter the mode used.\n1) CBC\n2) ECB\n3) CFB\n4) CTR\n5) OFB\nEnter: ")
    mode = AES.MODE_CBC
    if modechoice == '1':
        mode = AES.MODE_CBC
    elif modechoice == '2':
        mode = AES.MODE_ECB
    elif modechoice == '3':
        mode = AES.MODE_CFB
    elif modechoice == '4':
        mode = AES.MODE_CTR
    elif modechoice == '5':
        mode = AES.MODE_OFB
    else:
        print "Not a valid choice"
        sys.exit(1)
    key = raw_input("Please provide the key used of length 16, 24, or 32: ")
    keylength = len(key)
    if keylength - 16 != 0 and keylength - 24 != 0 and keylength - 32 != 0:
        print 'Incorrect key length'
        sys.exit(1)

    outname = filename[:-4]

    with open(filename, 'rb') as encryptedfile:
        filesize = struct.unpack('<Q', encryptedfile.read(struct.calcsize('Q')))[0]
        iv = encryptedfile.read(AES.block_size)
        decryptor = AES.new(key, mode, iv)

        with open(outname, 'wb') as decryptedfile:
            while True:
                chunk = encryptedfile.read(64)
                if len(chunk) == 0:
                    break
                decryptedfile.write(decryptor.decrypt(chunk))

            decryptedfile.truncate(filesize) # gets rid of space padding






encOrDec = raw_input("Enter 1 for encrypt, 2 for decrypt: ")
if encOrDec == '1':
    encrypt()
elif encOrDec == '2':
    decrypt()
else:
    print "Not a valid entry"
    sys.exit(1)
