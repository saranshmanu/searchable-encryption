import re
import os
import sys
import traceback
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from utils.AESCipher import AESCipher
from utils.StreamCipher import StreamCipher
import base64

ENCRYPTION_KEY = b'Sixteen byte key'
iv = Random.new().read(AES.block_size)

xorWord = lambda ss,cc: ''.join(chr(s^c) for s,c in zip(ss,cc))

def nextWord(fileobj):
    r_word = re.compile("(\w[\w']*\w|\w)")
    for line in fileobj:
        for word in r_word.findall(line.decode()):
            yield word

def encryptionScheme():
    w_aes_cipher = AESCipher(ENCRYPTION_KEY, iv)
    s_aes_cipher = AESCipher(ENCRYPTION_KEY, iv)
    for filename in os.listdir("./raw/"):
        with open(os.path.join('./raw/', filename), 'rb') as in_file:
            path = os.getcwd() + '/ciphertext/' + filename + '.enc'
            with open(path, 'wb') as out_file:
                for word in nextWord(in_file):
                    my_word = word.ljust(32, '.')
                    EWi = w_aes_cipher.encrypt(my_word.encode())
                    out_file.write(EWi)

def searchScheme():
    w_aes_cipher = AESCipher(ENCRYPTION_KEY, iv)
    s_aes_cipher = AESCipher(ENCRYPTION_KEY, iv)
    while True:
        try:
            word2search = str(input('\nEnter a word to search: '))
            if not word2search:
                print('Must enter some text to proceed')
                continue
            word2search_padded = word2search.ljust(16, '.') 
            for filename in os.listdir('./ciphertext/'):
                success = 0
                with open(os.path.join('./ciphertext/', filename), 'rb') as in_file:
                    in_data = in_file.read(32)
                    while in_data:
                        if(s_aes_cipher.decrypt(in_data).decode() == word2search_padded):
                            success = 1
                            break
                        in_data = in_file.read(32)
                print ('Present in {0}'.format(filename) if success==1 else 'Not present in {0}'.format(filename))
        except EOFError:
            print ('\nQuitting...\n')
            sys.exit(0)
        except Exception as e:
            print(traceback.format_exc())

encryptionScheme()
searchScheme()
