# pip install pycryptodomex

import os
from zipfile import ZipFile
from Cryptodome.Hash import SHA3_512
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.Padding import unpad


def printChoices0() -> None:
    print("")
    print("")
    print("\tWhat do You want?")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(1) Symmetrically EnCrypt a file\t -> E(m, k)")
    print("\t(2) Symmetrically DeCrypt a file\t -> D(m, k)")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")
    print("\t(q) Terminate program")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")

def hashFile(fileName: str) -> None:
    file1 = open(fileName, "rb")
    fileIn1 = file1.read()
    file1.close()

    hash1 = SHA3_512.new()
    hash1.update(fileIn1)

    file1 = open("hash.txt", "w")
    file1.write(hash1.hexdigest())
    file1.close()
    
    return None


def verifyHash(fileName: str) -> bool:
    file1 = open(fileName, "rb")
    fileIn1 = file1.read()
    file1.close()

    hash1 = SHA3_512.new()
    hash1.update(fileIn1)

    hash1 = hash1.hexdigest()

    file1 = open("hash.txt", "r")
    hash2 = file1.read()
    file1.close()

    if hash1 == hash2:
        print("OK - hashes are equal")
        return True
    else:
        print("WARNING - hashes are NOT equal")
        return False


def symCrypt(fileName: str) -> None:
    mFile = open(fileName, "rb")
    msg = mFile.read()
    mFile.close()
    
    keyIn = input("key: ")
    hash1 = SHA3_512.new()
    hash1.update(keyIn.encode())
    hash1 = hash1.hexdigest()
    hash1 = hash1[0:32]
    key = hash1.encode()

    cipher = AES.new(key, AES.MODE_CBC)

    iv = cipher.iv
    fileIv = open("iv.txt", "wb")
    fileIv.write(iv)
    fileIv.close()

    ciphertext = cipher.encrypt(pad(msg, 16))

    fileCipher = open(fileName + ".c", "wb")
    fileCipher.write(ciphertext)
    fileCipher.close()
    
    return None


def symDeCrypt(fileName: str) -> None:
    cFile = open(fileName, "rb")
    cip = cFile.read()
    cFile.close()

    keyIn = input("key: ")
    hash1 = SHA3_512.new()
    hash1.update(keyIn.encode())
    hash1 = hash1.hexdigest()
    hash1 = hash1[0:32]
    key = hash1.encode()

    ivFile = open("iv.txt", "rb")
    iv = ivFile.read()
    ivFile.close()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    msg = unpad(cipher.decrypt(cip), 16)

    fileMsg = open(fileName[0:len(fileName) - 2], "wb")
    fileMsg.write(msg)
    fileMsg.close()
    
    return None


def main():
    print("\t\t## Cryptography software ##")

    while 1 == 1:
        printChoices0()

        userInput = input("Your choice: ")
        try:
            choice = int(userInput)
        except ValueError:
            print("Program terminated")
            return None

        print("")

        if choice == 1:
            # Symmetrically EnCrypt a file
            userInput = input("File (example: my_file.txt): ")
            
            hashFile(userInput)
            symCrypt(userInput)
            
            zipEnvelope = ZipFile(userInput+".zip", "w")
            zipEnvelope.write(userInput+".c")
            zipEnvelope.write("iv.txt")
            zipEnvelope.write("hash.txt")
            zipEnvelope.close()
            
            os.remove("iv.txt")
            os.remove(userInput+".c")
            os.remove("hash.txt")
            
            print("Done")

        else:
            # Symmetrically DeCrypt a file
            userInput = input("File (example: my_file.txt.zip): ")
            
            zipEnvelope = ZipFile(userInput, "r")
            zipEnvelope.extractall()
            zipEnvelope.close()
            
            symDeCrypt(userInput[0:len(userInput) - 4]+".c")
            verifyHash(userInput[0:len(userInput) - 4])
            
            os.remove("iv.txt")
            os.remove(userInput[0:len(userInput) - 4]+".c")
            os.remove("hash.txt")
            
            print("Done")


if __name__ == '__main__':
    main()

