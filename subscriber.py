import flask
from flask import request, jsonify
from Crypto.Cipher import AES
from Crypto import Random
import uuid
import base64
import requests
from utils.AESCipher import AESCipher

app = flask.Flask(__name__)
app.config["DEBUG"] = True

@app.route('/api/v1/create_keys', methods=['GET'])
def generate_keys():
    ENCRYPTION_KEY = base64.b64encode(Random.new().read(AES.block_size)).decode()
    SECONDARY_KEY = base64.b64encode(str(uuid.uuid4())[:16].encode()).decode()
    return jsonify({
        "primary_key": ENCRYPTION_KEY,
        "secondary_key": SECONDARY_KEY
    })

@app.route('/api/v1/encrypt_database', methods=['GET'])
def encrypt_database():
    body = request.json
    primary_key = body['primary_key']
    secondary_key = body['secondary_key']
    data = {
        "primary_key": primary_key,
        "secondary_key": secondary_key
    }
    response = requests.get(url = 'http://localhost:5000/api/v1/encrypt_database', json = data) 
    return jsonify({
        "status": True
    })


@app.route('/api/v1/search_database', methods=['GET'])
def search():
    body = request.json
    primary_key = body['primary_key']
    secondary_key = body['secondary_key']
    search_text = body['search_text']
    ENCRYPTION_KEY = base64.b64decode(primary_key.encode())
    SECONDARY_KEY = base64.b64decode(secondary_key.encode())
    aes = AESCipher(ENCRYPTION_KEY, SECONDARY_KEY)
    encrypted_search_text = aes.encrypt(search_text.ljust(32, '.').encode())
    data = { "search_text": base64.b64encode(encrypted_search_text).decode()}
    response = requests.get(url = 'http://localhost:5000/api/v1/search_database', json = data) 
    response = response.json()
    values = aes.decrypt(base64.b64decode(response['values'].encode())).decode()
    return jsonify({
        "value": values
    })

app.run('0.0.0.0', 3444)