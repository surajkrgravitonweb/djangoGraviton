from Crypto.Cipher import AES
import hashlib
from binascii import hexlify, unhexlify

def pad(data):
    length = 16 - (len(data) % 16)
    data += chr(length)*length
    return data

def unpad(data):
    return data[0:-ord(data[-1])] 

def encrypt(plainText, workingKey):
    iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'.encode("utf-8")
    plainText = pad(plainText)
    bytearrayWorkingKey = bytearray()
    bytearrayWorkingKey.extend(map(ord, workingKey))
    enc_cipher = AES.new(hashlib.md5(bytearrayWorkingKey).digest(), AES.MODE_CBC, iv)
    return hexlify(enc_cipher.encrypt(plainText.encode("utf-8"))).decode('utf-8')

def decrypt(cipherText, workingKey):
    iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    encryptedText = unhexlify(cipherText)
    bytearrayWorkingKey = bytearray()
    bytearrayWorkingKey.extend(map(ord, workingKey))
    decCipher = AES.new(hashlib.md5(bytearrayWorkingKey).digest(), AES.MODE_CBC, iv)
    return unpad(decCipher.decrypt(encryptedText).decode('utf-8'))