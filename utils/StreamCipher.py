from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
import struct
import uuid

# counter class for stream cipher
class Counter:
    def __init__(self, nonce):
        assert(len(nonce) == 8)
        self.nonce = nonce
        self.count = 0

    def __call__(self):
        righthalf = struct.pack('>Q', self.count)
        self.count += 1
        return self.nonce.encode() + righthalf

# class for generating the cipher using streamcipher algo and decrypt it
class StreamCipher:
    def __init__(self, key, nonce):
        self.nonce = nonce
        self.key = key

    def generate(self, plaintext):
        cipher_ctr = AES.new(self.key, mode=AES.MODE_CTR, counter=Counter(self.nonce))
        return cipher_ctr.encrypt(plaintext)

    def decrypt(self, enc):
        cipher_ctr = AES.new(self.key, mode=AES.MODE_CTR, counter=Counter(self.nonce))
        return cipher_ctr.decrypt(enc)


# nonce = str(uuid.uuid4())[:8] # string
# key = get_random_bytes(16) # bytes
# stream_cipher = StreamCipher(key, nonce)

# while True:
#     text = str(input('Input - '))
#     cipher = stream_cipher.generate(text)
#     text = stream_cipher.decrypt(cipher).decode()
#     print(text)
