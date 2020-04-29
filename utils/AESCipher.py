from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto import Random

# class to encrypt and decrypt using AES CBC algorithm
class AESCipher:
    # class init to pass the generated key
    def __init__(self, key, iv):
        self.iv = iv
        self.key = key

    # padding method to encrypt the message
    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    # encryption method of AES
    def encrypt(self, message):
        message = self.pad(message)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.iv + cipher.encrypt(message)

    # decryption method of AES
    def decrypt(self, ciphertext):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")


# key = get_random_bytes(16) # returns key in bytes
# iv = Random.new().read(AES.block_size)
# aes = AESCipher(key, iv) # text is in string

# while True:
#     text = str(input('Input - '))
#     cipher = aes.encrypt(text.encode())
#     text = aes.decrypt(cipher).decode()
#     print(text)
