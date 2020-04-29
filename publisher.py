import flask
from flask import request, jsonify
import base64
from Crypto import Random
from utils.AESCipher import AESCipher

app = flask.Flask(__name__)
app.config["DEBUG"] = True

def encrypt_database_function(ENCRYPTION_KEY, SECONDARY_KEY):
    uuid_column_name = "id"
    uuid_column_index = 0
    aes = AESCipher(ENCRYPTION_KEY, SECONDARY_KEY)
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

@app.route('/api/v1/encrypt_database', methods=['GET'])
def encrypt_database():
    body = request.json
    primary_key = body['primary_key']
    secondary_key = body['secondary_key']
    ENCRYPTION_KEY = base64.b64decode(primary_key.encode())
    SECONDARY_KEY = base64.b64decode(secondary_key.encode())
    encrypt_database_function(ENCRYPTION_KEY, SECONDARY_KEY)
    return jsonify({
        'status': True
    })

def search_encrypted_database_function(search_term):
    uuid_to_search = search_term
    with open('ciphertext/data.enc', 'rb') as input_file:
        data = input_file.read().decode()
        records = data.split('END_OF_LINE_')
        records = [ base64.b64decode(record) for record in records ]
        records.pop()
        for record in records:
            encrypted_uuid = record[:64]
            uuid = search_term
            if uuid == encrypted_uuid:
                return base64.b64encode(record[64:]).decode()
                break
    return ""

@app.route('/api/v1/search_database', methods=['GET'])
def search_database():
    body = request.json
    search_term = base64.b64decode(body['search_text'].encode())
    values = search_encrypted_database_function(search_term)
    return jsonify({
        "status": True,
        "values": values
    })

app.run()
