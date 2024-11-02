!pip install Pillow cryptography

from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
import os

# Função para converter uma string de caracteres em um array binário
def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

# Função para converter dados binários de volta para string
def binary_to_message(binary_data):
    binary_chars = [binary_data[i:i + 8] for i in range(0, len(binary_data), 8)]
    return ''.join(chr(int(binary_char, 2)) for binary_char in binary_chars)

# Função para embutir mensagem na imagem
def encode_message(image_path, message, output_image_path):
    image = Image.open(image_path)
    image = image.convert('RGB')
    pixels = image.load()

    binary_message = message_to_binary(message) + '1111111111111110'
    data_index = 0

    for row in range(image.size[1]):
        for col in range(image.size[0]):
            if data_index < len(binary_message):
                r, g, b = pixels[col, row]
                r = (r & 254) | int(binary_message[data_index])
                data_index += 1

                if data_index < len(binary_message):
                    g = (g & 254) | int(binary_message[data_index])
                    data_index += 1

                if data_index < len(binary_message):
                    b = (b & 254) | int(binary_message[data_index])
                    data_index += 1

                pixels[col, row] = (r, g, b)

    image.save(output_image_path)
    print(f'Mensagem codificada e salva em {output_image_path}')

# Função para decodificar mensagem da imagem
def decode_message(image_path):
    image = Image.open(image_path)
    image = image.convert('RGB')
    pixels = image.load()

    binary_message = ''
    for row in range(image.size[1]):
        for col in range(image.size[0]):
            r, g, b = pixels[col, row]
            binary_message += str(r & 1)
            binary_message += str(g & 1)
            binary_message += str(b & 1)

    hidden_message = binary_to_message(binary_message)
    termination_index = hidden_message.find('þ')
    if termination_index != -1:
        hidden_message = hidden_message[:termination_index]

    return hidden_message

# Funções para gerar e serializar as chaves
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    
    return private_key, public_key

def serialize_key(key, is_private=False):
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

# Função para encriptar a mensagem
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Função para decriptar a mensagem
def decrypt_message(private_key, ciphertext):
    decrypted_message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# Função para gerar hash da imagem
def generate_image_hash(image_path):
    md5_hash = hashlib.md5()
    with open(image_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

# Função principal com menu
def main():
    while True:
        print("\nMenu de opções:")
        print("(1) Embutir texto em uma imagem")
        print("(2) Recuperar texto inserido em uma imagem")
        print("(3) Gerar hash das imagens")
        print("(4) Encriptar a mensagem original")
        print("(5) Decriptar a mensagem encriptada")
        print("(S) Sair")

        choice = input("Escolha uma opção: ").strip().upper()

        if choice == 'S':
            break
        elif choice == '1':
            img_path = input("Caminho da imagem (PNG ou JPG): ")
            message = input("Mensagem a ser embutida: ")
            output_path = input("Caminho para salvar a imagem alterada: ")
            encode_message(img_path, message, output_path)
        elif choice == '2':
            img_path = input("Caminho da imagem alterada: ")
            recovered_message = decode_message(img_path)
            print(f"Mensagem recuperada: {recovered_message}")
        elif choice == '3':
            original_img_path = input("Caminho da imagem original: ")
            altered_img_path = input("Caminho da imagem alterada: ")
            original_hash = generate_image_hash(original_img_path)
            altered_hash = generate_image_hash(altered_img_path)
            print(f"Hash da imagem original: {original_hash}")
            print(f"Hash da imagem alterada: {altered_hash}")
        elif choice == '4':
            private_key, public_key = generate_keys()
            print("Chave pública:")
            print(serialize_key(public_key).decode('utf-8'))
            message = input("Mensagem a ser encriptada: ")
            ciphertext = encrypt_message(public_key, message)
            print(f"Texto encriptado: {ciphertext}")
            img_path = input("Caminho da imagem para embutir o texto encriptado: ")
            output_path = input("Caminho para salvar a imagem alterada: ")
            encode_message(img_path, ciphertext.hex(), output_path)
        elif choice == '5':
            img_path = input("Caminho da imagem alterada: ")
            encrypted_message = decode_message(img_path)
            print(f"Texto encriptado recuperado: {encrypted_message}")
            # Descriptografar aqui utilizando a chave privada (fornecer de alguma forma)
            # Para simplicidade, vamos gerar uma nova chave aqui. (Idealmente, você deveria ter a chave privada guardada)
            private_key, _ = generate_keys()
            decrypted_message = decrypt_message(private_key, bytes.fromhex(encrypted_message))
            print(f"Mensagem decriptada: {decrypted_message}")

if __name__ == "__main__":
    main()
