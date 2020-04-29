from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from utils.AESCipher import AESCipher
from utils.StreamCipher import StreamCipher
import base64

uuid_column_name = "id"
uuid_column_index = 0

ENCRYPTION_KEY = b'Sixteen byte key'
iv = Random.new().read(AES.block_size)
aes = AESCipher(ENCRYPTION_KEY, iv)

with open('raw/data.csv', 'rb') as input_file:
    columns = input_file.readline().decode()
    columns = columns.split(',')
    count = 0
    for column in columns:
        if(uuid_column_name in column):
            uuid_column_index = count
            break
        count += 1
    with open('ciphertext/data.enc', 'wb') as output_file:
        data = input_file.readline().decode()
        while data:
            values = data.split(',')
            uuid = values[uuid_column_index]
            data_to_write = uuid.ljust(32, '.') + ',' + data
            encrypted_uuid = aes.encrypt(uuid.ljust(32, '.').encode())
            encrypted_values = aes.encrypt(data.encode())
            encrypted_data = base64.b64encode(encrypted_uuid + encrypted_values)
            output_file.write(encrypted_data + b'END_OF_LINE_')
            data = input_file.readline().decode()

uuid_to_search = '9010018'

with open('ciphertext/data.enc', 'rb') as input_file:
    data = input_file.read().decode()
    records = data.split('END_OF_LINE_')
    records = [ base64.b64decode(record) for record in records ]
    records.pop()
    for record in records:
        encrypted_uuid = record[:64]
        uuid = aes.encrypt(uuid_to_search.ljust(32, '.').encode())
        if uuid == encrypted_uuid:
            values = aes.decrypt(record[64:]).decode()
            print(values)
            break
        
