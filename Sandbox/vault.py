import struct
import binascii
import os

# --- ChaCha20 Implementation ---

def rotl(x, n):
    return ((x << n) & 0xffffffff) | (x >> (32 - n))

def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotl(x[b] ^ x[c], 7)

def chacha20_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x796b2d32, 0x6b206574]
    inp = constants + list(struct.unpack('<8I', key)) + [counter] + list(struct.unpack('<3I', nonce))
    state = list(inp)

    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)

    return b''.join(struct.pack('<I', (s + i) & 0xffffffff) for s, i in zip(state, inp))

def chacha20_crypt(key, counter, nonce, data):
    encrypted = bytearray(len(data))
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        chunk_len = min(64, len(data) - i)
        for j in range(chunk_len):
            encrypted[i + j] = data[i + j] ^ block[j]
    return bytes(encrypted)

# --- Poly1305 Implementation ---

def poly1305_mac(msg, key):
    r = int.from_bytes(key[:16], 'little')
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], 'little')
    
    acc = 0
    p = (1 << 130) - 5
    
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        n = int.from_bytes(chunk, 'little')
        n += (1 << (len(chunk) * 8))
        acc = (acc + n) * r
        acc %= p
        
    acc += s
    return (acc & 0xffffffffffffffffffffffffffffffff).to_bytes(16, 'little')

# --- AEAD Construction (ChaCha20-Poly1305) ---

def pad16(data):
    if len(data) % 16 == 0:
        return b''
    return b'\x00' * (16 - (len(data) % 16))

def chacha20_poly1305_encrypt(key, nonce, plaintext, associated_data=b''):
    if len(key) != 32: raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12: raise ValueError("Nonce must be 12 bytes")
    
    # Generate Poly1305 key using the first block of ChaCha20
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    
    # Encrypt plaintext (starting counter at 1)
    ciphertext = chacha20_crypt(key, 1, nonce, plaintext)
    
    # Calculate MAC
    mac_data = (associated_data + pad16(associated_data) +
                ciphertext + pad16(ciphertext) +
                struct.pack('<Q', len(associated_data)) +
                struct.pack('<Q', len(ciphertext)))
    tag = poly1305_mac(mac_data, poly1305_key)
    
    return ciphertext, tag

def chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, associated_data=b''):
    if len(key) != 32: raise ValueError("Key must be 32 bytes")
    if len(nonce) != 12: raise ValueError("Nonce must be 12 bytes")
    
    poly1305_key = chacha20_block(key, 0, nonce)[:32]
    
    mac_data = (associated_data + pad16(associated_data) +
                ciphertext + pad16(ciphertext) +
                struct.pack('<Q', len(associated_data)) +
                struct.pack('<Q', len(ciphertext)))
    calc_tag = poly1305_mac(mac_data, poly1305_key)
    
    if calc_tag != tag:
        return None # Auth failure
    
    return chacha20_crypt(key, 1, nonce, ciphertext)

# --- Helper Wrapper ---

def encrypt_text(key_hex, text):
    """
    Удобная функция для шифрования текста.
    Аргументы:
      key_hex: 64-символьная hex-строка (32 байта) ключа.
      text: Текст для шифрования.
    Возвращает:
      Словарь с 'nonce', 'ciphertext', 'tag' в hex формате.
    """
    key = binascii.unhexlify(key_hex)
    nonce = os.urandom(12)
    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, text.encode())
    return {
        'nonce': binascii.hexlify(nonce).decode(),
        'ciphertext': binascii.hexlify(ciphertext).decode(),
        'tag': binascii.hexlify(tag).decode()
    }

def decrypt_text(key_hex, encrypted_dict):
    """
    Удобная функция для расшифровки текста.
    Аргументы:
      key_hex: 64-символьная hex-строка ключа.
      encrypted_dict: Словарь с 'nonce', 'ciphertext', 'tag' (hex строки).
    Возвращает:
      Расшифрованный текст или None, если проверка целостности не удалась.
    """
    key = binascii.unhexlify(key_hex)
    nonce = binascii.unhexlify(encrypted_dict['nonce'])
    ciphertext = binascii.unhexlify(encrypted_dict['ciphertext'])
    tag = binascii.unhexlify(encrypted_dict['tag'])
    
    decrypted = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)
    return decrypted.decode() if decrypted else None

# --- ИНСТРУКЦИЯ ---
# 1. Генерируем ключ (один раз):
#    key = binascii.hexlify(os.urandom(32)).decode()
#    print(f"Ваш ключ: {key}")
# 2. Шифруем:
#    res = encrypt_text(key, "Секретное сообщение")
#    print(res)
# 3. Расшифровываем:
#    text = decrypt_text(key, res)
#    print(text)

if __name__ == "__main__":
    print("--- Self Test ---")
    # Тест
    test_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    msg = "Hello Poly1305ChaCha20!"
    
    print(f"Key: {test_key}")
    print(f"Msg: {msg}")
    
    encrypted = encrypt_text(test_key, msg)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt_text(test_key, encrypted)
    print(f"Decrypted: {decrypted}")
    
    if decrypted == msg:
        print("SUCCESS: Decryption matches original.")
    else:
        print("FAILURE: Decryption failed.")
