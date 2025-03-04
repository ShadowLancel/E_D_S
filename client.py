import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

SERVER_URL = 'http://127.0.0.1:5000'

def main():
    # Генерируем ключи клиента
    client_key = RSA.generate(2048)
    client_public_key = client_key.publickey()

    client_id = 'clientA'

    # 1) Регистрируем публичный ключ клиента на сервере
    pub_key_pem = client_public_key.export_key(format='PEM').decode('utf-8')
    resp = requests.post(f'{SERVER_URL}/register_client_public_key', json={
        'client_id': client_id,
        'public_key': pub_key_pem
    })
    print("Register client public key:", resp.json())

    # ===== СЦЕНАРИЙ 1 =====
    print("\n Сценарий 2:")

    # Клиент подписывает сообщение
    message = "Hello from client A!"
    h = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(client_key).sign(h)

    # Отправляем на сервер для проверки
    resp = requests.post(f'{SERVER_URL}/verify', json={
        'client_id': client_id,
        'message': message,
        'signature': signature.hex()
    })
    print("Scenario 1 verify response:", resp.json())

    # ===== СЦЕНАРИЙ 2 =====
    print("\n Сценарий 1:")

    # 1) Получаем публичный ключ сервера
    resp = requests.get(f'{SERVER_URL}/server_public_key')
    server_pub_key_pem = resp.content  # это bytes
    server_pub_key = RSA.import_key(server_pub_key_pem)

    # 2) Запрашиваем у сервера «случайное сообщение» + подпись
    resp = requests.get(f'{SERVER_URL}/generate_random_message')
    data = resp.json()
    random_message = data['random_message']
    server_signature_hex = data['signature']
    server_signature = bytes.fromhex(server_signature_hex)

    # 3) Проверяем подпись сервера локально
    h = SHA256.new(random_message.encode('utf-8'))
    try:
        pkcs1_15.new(server_pub_key).verify(h, server_signature)
        print("Scenario 2: signature from server is VALID")
    except (ValueError, TypeError):
        print("Scenario 2: signature from server is INVALID")


if __name__ == '__main__':
    main()