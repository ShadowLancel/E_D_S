from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import secrets

app = Flask(__name__)

# Генерация ключей сервера (при старте приложения)
server_key = RSA.generate(2048)
server_public_key = server_key.publickey()

# Хранилище публичных ключей клиентов (client_id -> RSA.PublicKey)
clients_public_keys = {}


@app.route('/register_client_public_key', methods=['POST'])
def register_client_public_key():
    """
    Клиент отправляет свой публичный ключ в PEM-формате.
    {
      "client_id": "clientA",
      "public_key": "<PEM-строка>"
    }
    """
    data = request.json
    client_id = data['client_id']
    pub_key_pem = data['public_key']

    # Импортируем публичный ключ из PEM
    pub_key = RSA.import_key(pub_key_pem)
    clients_public_keys[client_id] = pub_key

    return jsonify({'status': 'ok', 'message': f'Registered public key for {client_id}'})


@app.route('/verify', methods=['POST'])
def verify():
    """
    Клиент отправляет сообщение и подпись для проверки:
    {
      "client_id": "clientA",
      "message": "Hello",
      "signature": "<hex>"
    }
    """
    data = request.json
    client_id = data['client_id']
    message = data['message'].encode('utf-8')  # строку переводим в bytes
    signature = bytes.fromhex(data['signature'])  # hex -> bytes

    # Проверяем, зарегистрирован ли такой client_id
    if client_id not in clients_public_keys:
        return jsonify({'status': 'error', 'message': 'Unknown client_id'}), 400

    # Получаем публичный ключ клиента
    pub_key = clients_public_keys[client_id]

    # Считаем хеш сообщения
    h = SHA256.new(message)

    # Проверяем подпись
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return jsonify({'status': 'ok', 'message': 'Signature is valid'})
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid signature'}), 400


@app.route('/server_public_key', methods=['GET'])
def get_server_public_key():
    """
    Возвращает публичный ключ сервера (в PEM-формате).
    """
    return server_public_key.export_key(format='PEM')


@app.route('/generate_random_message', methods=['GET'])
def generate_random_message():
    """
    Генерирует случайное сообщение, подписывает его приватным ключом сервера
    и отправляет клиенту (для сценария 2).
    Возвращаем JSON:
    {
      "random_message": "<str>",
      "signature": "<hex>"
    }
    """
    # Генерируем случайную строку (16 байт в hex = 32 символа)
    random_message = secrets.token_hex(16)

    # Хешируем и подписываем
    h = SHA256.new(random_message.encode('utf-8'))
    signature = pkcs1_15.new(server_key).sign(h)

    return jsonify({
        'random_message': random_message,
        'signature': signature.hex()
    })


if __name__ == '__main__':
    # Запускаем Flask-сервер на 5000 порту
    app.run(port=5000, debug=True)