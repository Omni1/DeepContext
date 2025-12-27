# Context Report

Target: `C:\Users\IOT\SynapseCore`

## Project Structure
```text
SynapseCore/
├── .wrangler
│   └── tmp
├── ContextAnalyzer
│   └── analyzer.py
├── Sandbox
│   ├── ContextAnalyzer
│   └── vault.py
├── src
│   └── index.ts
├── d1_info.json
├── d1_info_utf8.json
├── deploy_output.txt
├── deploy_output_utf8.txt
├── models.json
├── models_utf8.json
├── package-lock.json
├── package.json
├── payload.json
├── schema.sql
└── wrangler.toml
```

## File Contents

--- FILE: ContextAnalyzer\analyzer.py ---

```python
import os
import argparse
import fnmatch
from pathlib import Path

# Extensions to ignore (media, binary, etc.)
IGNORE_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.tiff', '.webp',
    # Video/Audio
    '.mp4', '.mkv', '.avi', '.mov', '.mp3', '.wav', '.flac', '.aac',
    # Archives/Binaries
    '.zip', '.tar', '.gz', '.7z', '.rar', '.exe', '.dll', '.so', '.dylib', '.bin', '.iso',
    # Python/System
    '.pyc', '.pyo', '.pyd', '.db', '.sqlite', '.sqlite3'
}

# Directories to always ignore
IGNORE_DIRS = {'.git', '__pycache__', 'node_modules', '.idea', '.vscode', 'venv', 'env', '.gemini'}

def load_gitignore(root_path):
    """Reads .gitignore and returns a list of patterns."""
    gitignore_path = root_path / '.gitignore'
    patterns = []
    if gitignore_path.exists():
        try:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
        except Exception as e:
            print(f"Warning: Could not read .gitignore: {e}")
    return patterns

def should_ignore(path, root_path, gitignore_patterns):
    """Checks if a path should be ignored based on global rules and gitignore."""
    name = path.name
    rel_path = str(path.relative_to(root_path)).replace(os.sep, '/')

    # 1. Check strict directory ignores
    if path.is_dir() and name in IGNORE_DIRS:
        return True
    
    # Check if any parent part is in IGNORE_DIRS (optimization for deep files)
    for part in path.parts:
        if part in IGNORE_DIRS:
            return True

    # 2. Check extensions (only for files)
    if path.is_file() and path.suffix.lower() in IGNORE_EXTENSIONS:
        return True
        
    # 3. Check gitignore patterns
    # We need to check if the path or any of its parents matches a pattern
    # fnmatch isn't perfect for gitignore rules (e.g. negation), but it serves 90% of cases.
    # For a robust solution, we'd need a proper gitignore parser, but this is a lightweight script.
    
    for pattern in gitignore_patterns:
        # Handle directory-specific patterns (ending with /)
        if pattern.endswith('/'):
            if path.is_dir() and fnmatch.fnmatch(name, pattern[:-1]):
                return True
            if fnmatch.fnmatch(rel_path + '/', pattern): # Match 'dir/' against 'dir/'
                 return True
        else:
            if fnmatch.fnmatch(name, pattern):
                return True
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            
    return False

def generate_tree(root_path, gitignore_patterns):
    """Generates a tree-like string structure."""
    tree_lines = []
    
    def _add_to_tree(directory, prefix=''):
        original_contents = list(directory.iterdir())
        # Sort: directories first, then files
        contents = []
        for p in original_contents:
             if not should_ignore(p, root_path, gitignore_patterns):
                 contents.append(p)
        
        contents.sort(key=lambda x: (not x.is_dir(), x.name.lower()))
        
        count = len(contents)
        for i, path in enumerate(contents):
            is_last = (i == count - 1)
            connector = '└── ' if is_last else '├── '
            tree_lines.append(f"{prefix}{connector}{path.name}")
            
            if path.is_dir():
                extension = '    ' if is_last else '│   '
                _add_to_tree(path, prefix + extension)

    tree_lines.append(root_path.name + "/")
    _add_to_tree(root_path)
    return "\n".join(tree_lines)

def get_files_recursively(root_path, gitignore_patterns):
    """Yields valid files recursively."""
    for root, dirs, files in os.walk(root_path):
        # Filter directories in-place to prevent os.walk from entering them
        # We need to convert to Path for consistent checking
        root_p = Path(root)
        
        # Determine strict ignore dirs first to modify dirs list
        # This is a bit tricky with os.walk since we need to check full paths against our should_ignore
        # But should_ignore checks the full relative path.
        
        # Let's filter dirs manually
        # modifying the 'dirs' list in-place tells os.walk to skip them
        dirs[:] = [d for d in dirs if not should_ignore(root_p / d, root_path, gitignore_patterns)]
        
        for file in files:
            file_path = root_p / file
            if not should_ignore(file_path, root_path, gitignore_patterns):
                yield file_path

def generate_report(target_dir, output_file):
    root_path = Path(target_dir).resolve()
    gitignore_patterns = load_gitignore(root_path)
    
    print(f"Analyzing: {root_path}")
    print(f"Output to: {output_file}")
    
    report_content = []
    
    # 1. Header
    report_content.append("# Context Report")
    report_content.append(f"\nTarget: `{root_path}`")
    
    # 2. Tree Structure
    print("Generating tree...")
    tree_str = generate_tree(root_path, gitignore_patterns)
    report_content.append("\n## Project Structure")
    report_content.append("```text")
    report_content.append(tree_str)
    report_content.append("```")
    
    # 3. File Contents
    print("Reading files...")
    report_content.append("\n## File Contents")
    
    files = list(get_files_recursively(root_path, gitignore_patterns))
    # Sort files by path for deterministic output
    files.sort(key=lambda p: str(p.relative_to(root_path)))
    
    for file_path in files:
        rel_path = file_path.relative_to(root_path)
        report_content.append(f"\n--- FILE: {rel_path} ---")
        
        # Determine language for markdown syntax highlighting (dumb heuristic)
        ext = file_path.suffix.lower()
        lang = ''
        if ext == '.py': lang = 'python'
        elif ext == '.js': lang = 'javascript'
        elif ext == '.ts': lang = 'typescript'
        elif ext == '.html': lang = 'html'
        elif ext == '.css': lang = 'css'
        elif ext == '.json': lang = 'json'
        elif ext == '.md': lang = 'markdown'
        elif ext == '.sql': lang = 'sql'
        elif ext == '.sh': lang = 'bash'
        
        report_content.append(f"\n```{lang}")
        
        try:
            text = file_path.read_text(encoding='utf-8', errors='replace')
            report_content.append(text)
        except Exception as e:
            report_content.append(f"[Error reading file: {e}]")
            
        report_content.append("```")

    # Write Report
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(report_content))
    
    print("Done!")

def main():
    parser = argparse.ArgumentParser(description="Generate a context report for a codebase.")
    parser.add_argument("path", nargs='?', default=".", help="Path to the directory to analyze (default: current directory)")
    parser.add_argument("-o", "--output", default="context_report.md", help="Output file name (default: context_report.md)")
    
    args = parser.parse_args()
    
    target_path = args.path
    if not os.path.exists(target_path):
        print(f"Error: Directory '{target_path}' does not exist.")
        return

    generate_report(target_path, args.output)

if __name__ == "__main__":
    main()

```

--- FILE: Sandbox\vault.py ---

```python
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

```

--- FILE: d1_info.json ---

```json
��[ 
 
     { 
 
         " u u i d " :   " 7 e a e d 0 1 8 - 7 8 7 b - 4 6 3 b - b 1 d a - 1 6 4 f a b 5 6 f 5 8 6 " , 
 
         " n a m e " :   " s y n a p s e _ d b " , 
 
         " c r e a t e d _ a t " :   " 2 0 2 5 - 1 2 - 2 3 T 0 5 : 5 2 : 3 8 . 1 8 2 Z " , 
 
         " v e r s i o n " :   " p r o d u c t i o n " , 
 
         " n u m _ t a b l e s " :   0 , 
 
         " f i l e _ s i z e " :   1 2 2 8 8 , 
 
         " j u r i s d i c t i o n " :   n u l l 
 
     } 
 
 ] 
 
 
```

--- FILE: d1_info_utf8.json ---

```json
﻿[
  {
    "uuid": "7eaed018-787b-463b-b1da-164fab56f586",
    "name": "synapse_db",
    "created_at": "2025-12-23T05:52:38.182Z",
    "version": "production",
    "num_tables": 0,
    "file_size": 12288,
    "jurisdiction": null
  }
]

```

--- FILE: deploy_output.txt ---

```
��
 
   � � � � � �   w r a n g l e r   3 . 1 1 4 . 1 6   ( u p d a t e   a v a i l a b l e   4 . 5 6 . 0 ) 
 
 - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
 
 
 
 T o t a l   U p l o a d :   0 . 1 9   K i B   /   g z i p :   0 . 1 6   K i B 
 
 Y o u r   w o r k e r   h a s   a c c e s s   t o   t h e   f o l l o w i n g   b i n d i n g s : 
 
 -   D 1   D a t a b a s e s : 
 
     -   D B :   s y n a p s e _ d b   ( 7 e a e d 0 1 8 - 7 8 7 b - 4 6 3 b - b 1 d a - 1 6 4 f a b 5 6 f 5 8 6 ) 
 
 U p l o a d e d   m y - g e m i n i - b o t   ( 7 . 2 2   s e c ) 
 
 D e p l o y e d   m y - g e m i n i - b o t   t r i g g e r s   ( 1 . 5 4   s e c ) 
 
     h t t p s : / / m y - g e m i n i - b o t . a l e x - w o r k e r s . w o r k e r s . d e v 
 
 C u r r e n t   V e r s i o n   I D :   f d e 9 6 4 6 a - d c c 5 - 4 4 c 1 - 8 1 d d - d c 2 a 1 1 0 c 7 0 f 3 
 
 
```

--- FILE: deploy_output_utf8.txt ---

```
﻿
 Ôøà´©Å wrangler 3.114.16 (update available 4.56.0)
-----------------------------------------------

Total Upload: 0.19 KiB / gzip: 0.16 KiB
Your worker has access to the following bindings:
- D1 Databases:
  - DB: synapse_db (7eaed018-787b-463b-b1da-164fab56f586)
Uploaded my-gemini-bot (7.22 sec)
Deployed my-gemini-bot triggers (1.54 sec)
  https://my-gemini-bot.alex-workers.workers.dev
Current Version ID: fde9646a-dcc5-44c1-81dd-dc2a110c70f3

```

--- FILE: models.json ---

```json
��{ 
 
     " m o d e l s " :   [ 
 
         { 
 
             " n a m e " :   " m o d e l s / g e m i n i - 2 . 5 - f l a s h " , 
 
             " v e r s i o n " :   " 0 0 1 " , 
 
             " d i s p l a y N a m e " :   " G e m i n i   2 . 5   F l a s h " , 
 
             " d e s c r i p t i o n " :   " S t a b l e   v e r s i o n   o f   G e m i n i   2 . 5   F l a s h ,   o u r   m i d - s i z e   m u l t i m o d a l   m o d e l   t h a t   s u p p o r t s   u p   t o   1   m i l l i o n   t o k e n s ,   r e l e a s e d   i n   J u n e   o f   2 0 2 5 . " , 
 
             " i n p u t T o k e n L i m i t " :   1 0 4 8 5 7 6 , 
 
             " o u t p u t T o k e n L i m i t " :   6 5 5 3 6 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " g e n e r a t e C o n t e n t " , 
 
                 " c o u n t T o k e n s " , 
 
                 " c r e a t e C a c h e d C o n t e n t " , 
 
                 " b a t c h G e n e r a t e C o n t e n t " 
 
             ] , 
 
             " t e m p e r a t u r e " :   1 , 
 
             " t o p P " :   0 . 9 5 , 
 
             " t o p K " :   6 4 , 
 
             " m a x T e m p e r a t u r e " :   2 , 
 
             " t h i n k i n g " :   t r u e 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / g e m i n i - 2 . 5 - p r o " , 
 
             " v e r s i o n " :   " 2 . 5 " , 
 
             " d i s p l a y N a m e " :   " G e m i n i   2 . 5   P r o " , 
 
             " d e s c r i p t i o n " :   " S t a b l e   r e l e a s e   ( J u n e   1 7 t h ,   2 0 2 5 )   o f   G e m i n i   2 . 5   P r o " , 
 
             " i n p u t T o k e n L i m i t " :   1 0 4 8 5 7 6 , 
 
             " o u t p u t T o k e n L i m i t " :   6 5 5 3 6 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " g e n e r a t e C o n t e n t " , 
 
                 " c o u n t T o k e n s " , 
 
                 " c r e a t e C a c h e d C o n t e n t " , 
 
                 " b a t c h G e n e r a t e C o n t e n t " 
 
             ] , 
 
             " t e m p e r a t u r e " :   1 , 
 
             " t o p P " :   0 . 9 5 , 
 
             " t o p K " :   6 4 , 
 
             " m a x T e m p e r a t u r e " :   2 , 
 
             " t h i n k i n g " :   t r u e 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / g e m i n i - 2 . 0 - f l a s h " , 
 
             " v e r s i o n " :   " 2 . 0 " , 
 
             " d i s p l a y N a m e " :   " G e m i n i   2 . 0   F l a s h " , 
 
             " d e s c r i p t i o n " :   " G e m i n i   2 . 0   F l a s h " , 
 
             " i n p u t T o k e n L i m i t " :   1 0 4 8 5 7 6 , 
 
             " o u t p u t T o k e n L i m i t " :   8 1 9 2 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " g e n e r a t e C o n t e n t " , 
 
                 " c o u n t T o k e n s " , 
 
                 " c r e a t e C a c h e d C o n t e n t " , 
 
                 " b a t c h G e n e r a t e C o n t e n t " 
 
             ] , 
 
             " t e m p e r a t u r e " :   1 , 
 
             " t o p P " :   0 . 9 5 , 
 
             " t o p K " :   4 0 , 
 
             " m a x T e m p e r a t u r e " :   2 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / g e m i n i - 2 . 0 - f l a s h - 0 0 1 " , 
 
             " v e r s i o n " :   " 2 . 0 " , 
 
             " d i s p l a y N a m e " :   " G e m i n i   2 . 0   F l a s h   0 0 1 " , 
 
             " d e s c r i p t i o n " :   " S t a b l e   v e r s i o n   o f   G e m i n i   2 . 0   F l a s h ,   o u r   f a s t   a n d   v e r s a t i l e   m u l t i m o d a l   m o d e l   f o r   s c a l i n g   a c r o s s   d i v e r s e   t a s k s ,   r e l e a s e d   i n   J a n u a r y   o f   2 0 2 5 . " , 
 
             " i n p u t T o k e n L i m i t " :   1 0 4 8 5 7 6 , 
 
             " o u t p u t T o k e n L i m i t " :   8 1 9 2 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " g e n e r a t e C o n t e n t " , 
 
                 " c o u n t T o k e n s " , 
 
                 " c r e a t e C a c h e d C o n t e n t " , 
 
                 " b a t c h G e n e r a t e C o n t e n t " 
 
             ] , 
 
             " t e m p e r a t u r e " :   1 , 
 
             " t o p P " :   0 . 9 5 , 
 
             " t o p K " :   4 0 , 
 
             " m a x T e m p e r a t u r e " :   2 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / g e m i n i - 2 . 0 - f l a s h - l i t e - 0 0 1 " , 
 
             " v e r s i o n " :   " 2 . 0 " , 
 
             " d i s p l a y N a m e " :   " G e m i n i   2 . 0   F l a s h - L i t e   0 0 1 " , 
 
             " d e s c r i p t i o n " :   " S t a b l e   v e r s i o n   o f   G e m i n i   2 . 0   F l a s h - L i t e " , 
 
             " i n p u t T o k e n L i m i t " :   1 0 4 8 5 7 6 , 
 
             " o u t p u t T o k e n L i m i t " :   8 1 9 2 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " g e n e r a t e C o n t e n t " , 
 
                 " c o u n t T o k e n s " , 
 
                 " c r e a t e C a c h e d C o n t e n t " , 
 
                 " b a t c h G e n e r a t e C o n t e n t " 
 
             ] , 
 
             " t e m p e r a t u r e " :   1 , 
 
             " t o p P " :   0 . 9 5 , 
 
             " t o p K " :   4 0 , 
 
             " m a x T e m p e r a t u r e " :   2 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / g e m i n i - 2 . 0 - f l a s h - l i t e " , 
 
             " v e r s i o n " :   " 2 . 0 " , 
 
             " d i s p l a y N a m e " :   " G e m i n i   2 . 0   F l a s h - L i t e " , 
 
             " d e s c r i p t i o n " :   " G e m i n i   2 . 0   F l a s h - L i t e " , 
 
             " i n p u t T o k e n L i m i t " :   1 0 4 8 5 7 6 , 
 
             " o u t p u t T o k e n L i m i t " :   8 1 9 2 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " g e n e r a t e C o n t e n t " , 
 
                 " c o u n t T o k e n s " , 
 
                 " c r e a t e C a c h e d C o n t e n t " , 
 
                 " b a t c h G e n e r a t e C o n t e n t " 
 
             ] , 
 
             " t e m p e r a t u r e " :   1 , 
 
             " t o p P " :   0 . 9 5 , 
 
             " t o p K " :   4 0 , 
 
             " m a x T e m p e r a t u r e " :   2 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / g e m i n i - 2 . 5 - f l a s h - l i t e " , 
 
             " v e r s i o n " :   " 0 0 1 " , 
 
             " d i s p l a y N a m e " :   " G e m i n i   2 . 5   F l a s h - L i t e " , 
 
             " d e s c r i p t i o n " :   " S t a b l e   v e r s i o n   o f   G e m i n i   2 . 5   F l a s h - L i t e ,   r e l e a s e d   i n   J u l y   o f   2 0 2 5 " , 
 
             " i n p u t T o k e n L i m i t " :   1 0 4 8 5 7 6 , 
 
             " o u t p u t T o k e n L i m i t " :   6 5 5 3 6 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " g e n e r a t e C o n t e n t " , 
 
                 " c o u n t T o k e n s " , 
 
                 " c r e a t e C a c h e d C o n t e n t " , 
 
                 " b a t c h G e n e r a t e C o n t e n t " 
 
             ] , 
 
             " t e m p e r a t u r e " :   1 , 
 
             " t o p P " :   0 . 9 5 , 
 
             " t o p K " :   6 4 , 
 
             " m a x T e m p e r a t u r e " :   2 , 
 
             " t h i n k i n g " :   t r u e 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / e m b e d d i n g - 0 0 1 " , 
 
             " v e r s i o n " :   " 0 0 1 " , 
 
             " d i s p l a y N a m e " :   " E m b e d d i n g   0 0 1 " , 
 
             " d e s c r i p t i o n " :   " O b t a i n   a   d i s t r i b u t e d   r e p r e s e n t a t i o n   o f   a   t e x t . " , 
 
             " i n p u t T o k e n L i m i t " :   2 0 4 8 , 
 
             " o u t p u t T o k e n L i m i t " :   1 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " e m b e d C o n t e n t " 
 
             ] 
 
         } , 
 
         { 
 
             " n a m e " :   " m o d e l s / t e x t - e m b e d d i n g - 0 0 4 " , 
 
             " v e r s i o n " :   " 0 0 4 " , 
 
             " d i s p l a y N a m e " :   " T e x t   E m b e d d i n g   0 0 4 " , 
 
             " d e s c r i p t i o n " :   " O b t a i n   a   d i s t r i b u t e d   r e p r e s e n t a t i o n   o f   a   t e x t . " , 
 
             " i n p u t T o k e n L i m i t " :   2 0 4 8 , 
 
             " o u t p u t T o k e n L i m i t " :   1 , 
 
             " s u p p o r t e d G e n e r a t i o n M e t h o d s " :   [ 
 
                 " e m b e d C o n t e n t " 
 
             ] 
 
         } 
 
     ] 
 
 } 
 
 
```

--- FILE: models_utf8.json ---

```json
﻿{
  "models": [
    {
      "name": "models/gemini-2.5-flash",
      "version": "001",
      "displayName": "Gemini 2.5 Flash",
      "description": "Stable version of Gemini 2.5 Flash, our mid-size multimodal model that supports up to 1 million tokens, released in June of 2025.",
      "inputTokenLimit": 1048576,
      "outputTokenLimit": 65536,
      "supportedGenerationMethods": [
        "generateContent",
        "countTokens",
        "createCachedContent",
        "batchGenerateContent"
      ],
      "temperature": 1,
      "topP": 0.95,
      "topK": 64,
      "maxTemperature": 2,
      "thinking": true
    },
    {
      "name": "models/gemini-2.5-pro",
      "version": "2.5",
      "displayName": "Gemini 2.5 Pro",
      "description": "Stable release (June 17th, 2025) of Gemini 2.5 Pro",
      "inputTokenLimit": 1048576,
      "outputTokenLimit": 65536,
      "supportedGenerationMethods": [
        "generateContent",
        "countTokens",
        "createCachedContent",
        "batchGenerateContent"
      ],
      "temperature": 1,
      "topP": 0.95,
      "topK": 64,
      "maxTemperature": 2,
      "thinking": true
    },
    {
      "name": "models/gemini-2.0-flash",
      "version": "2.0",
      "displayName": "Gemini 2.0 Flash",
      "description": "Gemini 2.0 Flash",
      "inputTokenLimit": 1048576,
      "outputTokenLimit": 8192,
      "supportedGenerationMethods": [
        "generateContent",
        "countTokens",
        "createCachedContent",
        "batchGenerateContent"
      ],
      "temperature": 1,
      "topP": 0.95,
      "topK": 40,
      "maxTemperature": 2
    },
    {
      "name": "models/gemini-2.0-flash-001",
      "version": "2.0",
      "displayName": "Gemini 2.0 Flash 001",
      "description": "Stable version of Gemini 2.0 Flash, our fast and versatile multimodal model for scaling across diverse tasks, released in January of 2025.",
      "inputTokenLimit": 1048576,
      "outputTokenLimit": 8192,
      "supportedGenerationMethods": [
        "generateContent",
        "countTokens",
        "createCachedContent",
        "batchGenerateContent"
      ],
      "temperature": 1,
      "topP": 0.95,
      "topK": 40,
      "maxTemperature": 2
    },
    {
      "name": "models/gemini-2.0-flash-lite-001",
      "version": "2.0",
      "displayName": "Gemini 2.0 Flash-Lite 001",
      "description": "Stable version of Gemini 2.0 Flash-Lite",
      "inputTokenLimit": 1048576,
      "outputTokenLimit": 8192,
      "supportedGenerationMethods": [
        "generateContent",
        "countTokens",
        "createCachedContent",
        "batchGenerateContent"
      ],
      "temperature": 1,
      "topP": 0.95,
      "topK": 40,
      "maxTemperature": 2
    },
    {
      "name": "models/gemini-2.0-flash-lite",
      "version": "2.0",
      "displayName": "Gemini 2.0 Flash-Lite",
      "description": "Gemini 2.0 Flash-Lite",
      "inputTokenLimit": 1048576,
      "outputTokenLimit": 8192,
      "supportedGenerationMethods": [
        "generateContent",
        "countTokens",
        "createCachedContent",
        "batchGenerateContent"
      ],
      "temperature": 1,
      "topP": 0.95,
      "topK": 40,
      "maxTemperature": 2
    },
    {
      "name": "models/gemini-2.5-flash-lite",
      "version": "001",
      "displayName": "Gemini 2.5 Flash-Lite",
      "description": "Stable version of Gemini 2.5 Flash-Lite, released in July of 2025",
      "inputTokenLimit": 1048576,
      "outputTokenLimit": 65536,
      "supportedGenerationMethods": [
        "generateContent",
        "countTokens",
        "createCachedContent",
        "batchGenerateContent"
      ],
      "temperature": 1,
      "topP": 0.95,
      "topK": 64,
      "maxTemperature": 2,
      "thinking": true
    },
    {
      "name": "models/embedding-001",
      "version": "001",
      "displayName": "Embedding 001",
      "description": "Obtain a distributed representation of a text.",
      "inputTokenLimit": 2048,
      "outputTokenLimit": 1,
      "supportedGenerationMethods": [
        "embedContent"
      ]
    },
    {
      "name": "models/text-embedding-004",
      "version": "004",
      "displayName": "Text Embedding 004",
      "description": "Obtain a distributed representation of a text.",
      "inputTokenLimit": 2048,
      "outputTokenLimit": 1,
      "supportedGenerationMethods": [
        "embedContent"
      ]
    }
  ]
}

```

--- FILE: package-lock.json ---

```json
{
  "name": "synapse-core",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "synapse-core",
      "version": "1.0.0",
      "license": "ISC",
      "devDependencies": {
        "@cloudflare/workers-types": "^4.20230419.0",
        "typescript": "^5.0.4",
        "wrangler": "^3.0.0"
      }
    },
    "node_modules/@cloudflare/kv-asset-handler": {
      "version": "0.3.4",
      "resolved": "https://registry.npmjs.org/@cloudflare/kv-asset-handler/-/kv-asset-handler-0.3.4.tgz",
      "integrity": "sha512-YLPHc8yASwjNkmcDMQMY35yiWjoKAKnhUbPRszBRS0YgH+IXtsMp61j+yTcnCE3oO2DgP0U3iejLC8FTtKDC8Q==",
      "dev": true,
      "license": "MIT OR Apache-2.0",
      "dependencies": {
        "mime": "^3.0.0"
      },
      "engines": {
        "node": ">=16.13"
      }
    },
    "node_modules/@cloudflare/unenv-preset": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/@cloudflare/unenv-preset/-/unenv-preset-2.0.2.tgz",
      "integrity": "sha512-nyzYnlZjjV5xT3LizahG1Iu6mnrCaxglJ04rZLpDwlDVDZ7v46lNsfxhV3A/xtfgQuSHmLnc6SVI+KwBpc3Lwg==",
      "dev": true,
      "license": "MIT OR Apache-2.0",
      "peerDependencies": {
        "unenv": "2.0.0-rc.14",
        "workerd": "^1.20250124.0"
      },
      "peerDependenciesMeta": {
        "workerd": {
          "optional": true
        }
      }
    },
    "node_modules/@cloudflare/workerd-darwin-64": {
      "version": "1.20250718.0",
      "resolved": "https://registry.npmjs.org/@cloudflare/workerd-darwin-64/-/workerd-darwin-64-1.20250718.0.tgz",
      "integrity": "sha512-FHf4t7zbVN8yyXgQ/r/GqLPaYZSGUVzeR7RnL28Mwj2djyw2ZergvytVc7fdGcczl6PQh+VKGfZCfUqpJlbi9g==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=16"
      }
    },
    "node_modules/@cloudflare/workerd-darwin-arm64": {
      "version": "1.20250718.0",
      "resolved": "https://registry.npmjs.org/@cloudflare/workerd-darwin-arm64/-/workerd-darwin-arm64-1.20250718.0.tgz",
      "integrity": "sha512-fUiyUJYyqqp4NqJ0YgGtp4WJh/II/YZsUnEb6vVy5Oeas8lUOxnN+ZOJ8N/6/5LQCVAtYCChRiIrBbfhTn5Z8Q==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=16"
      }
    },
    "node_modules/@cloudflare/workerd-linux-64": {
      "version": "1.20250718.0",
      "resolved": "https://registry.npmjs.org/@cloudflare/workerd-linux-64/-/workerd-linux-64-1.20250718.0.tgz",
      "integrity": "sha512-5+eb3rtJMiEwp08Kryqzzu8d1rUcK+gdE442auo5eniMpT170Dz0QxBrqkg2Z48SFUPYbj+6uknuA5tzdRSUSg==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=16"
      }
    },
    "node_modules/@cloudflare/workerd-linux-arm64": {
      "version": "1.20250718.0",
      "resolved": "https://registry.npmjs.org/@cloudflare/workerd-linux-arm64/-/workerd-linux-arm64-1.20250718.0.tgz",
      "integrity": "sha512-Aa2M/DVBEBQDdATMbn217zCSFKE+ud/teS+fFS+OQqKABLn0azO2qq6ANAHYOIE6Q3Sq4CxDIQr8lGdaJHwUog==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=16"
      }
    },
    "node_modules/@cloudflare/workerd-windows-64": {
      "version": "1.20250718.0",
      "resolved": "https://registry.npmjs.org/@cloudflare/workerd-windows-64/-/workerd-windows-64-1.20250718.0.tgz",
      "integrity": "sha512-dY16RXKffmugnc67LTbyjdDHZn5NoTF1yHEf2fN4+OaOnoGSp3N1x77QubTDwqZ9zECWxgQfDLjddcH8dWeFhg==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=16"
      }
    },
    "node_modules/@cloudflare/workers-types": {
      "version": "4.20251223.0",
      "resolved": "https://registry.npmjs.org/@cloudflare/workers-types/-/workers-types-4.20251223.0.tgz",
      "integrity": "sha512-r7oxkFjbMcmzhIrzjXaiJlGFDmmeu3+GlwkLlZbUxVWrXHTCkvqu+DrWnNmF6xZEf9j+2/PpuKIS21J522xhJA==",
      "dev": true,
      "license": "MIT OR Apache-2.0",
      "peer": true
    },
    "node_modules/@cspotcode/source-map-support": {
      "version": "0.8.1",
      "resolved": "https://registry.npmjs.org/@cspotcode/source-map-support/-/source-map-support-0.8.1.tgz",
      "integrity": "sha512-IchNf6dN4tHoMFIn/7OE8LWZ19Y6q/67Bmf6vnGREv8RSbBVb9LPJxEcnwrcwX6ixSvaiGoomAUvu4YSxXrVgw==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@jridgewell/trace-mapping": "0.3.9"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@emnapi/runtime": {
      "version": "1.7.1",
      "resolved": "https://registry.npmjs.org/@emnapi/runtime/-/runtime-1.7.1.tgz",
      "integrity": "sha512-PVtJr5CmLwYAU9PZDMITZoR5iAOShYREoR45EyyLrbntV50mdePTgUn4AmOw90Ifcj+x2kRjdzr1HP3RrNiHGA==",
      "dev": true,
      "license": "MIT",
      "optional": true,
      "dependencies": {
        "tslib": "^2.4.0"
      }
    },
    "node_modules/@esbuild-plugins/node-globals-polyfill": {
      "version": "0.2.3",
      "resolved": "https://registry.npmjs.org/@esbuild-plugins/node-globals-polyfill/-/node-globals-polyfill-0.2.3.tgz",
      "integrity": "sha512-r3MIryXDeXDOZh7ih1l/yE9ZLORCd5e8vWg02azWRGj5SPTuoh69A2AIyn0Z31V/kHBfZ4HgWJ+OK3GTTwLmnw==",
      "dev": true,
      "license": "ISC",
      "peerDependencies": {
        "esbuild": "*"
      }
    },
    "node_modules/@esbuild-plugins/node-modules-polyfill": {
      "version": "0.2.2",
      "resolved": "https://registry.npmjs.org/@esbuild-plugins/node-modules-polyfill/-/node-modules-polyfill-0.2.2.tgz",
      "integrity": "sha512-LXV7QsWJxRuMYvKbiznh+U1ilIop3g2TeKRzUxOG5X3YITc8JyyTa90BmLwqqv0YnX4v32CSlG+vsziZp9dMvA==",
      "dev": true,
      "license": "ISC",
      "dependencies": {
        "escape-string-regexp": "^4.0.0",
        "rollup-plugin-node-polyfills": "^0.2.1"
      },
      "peerDependencies": {
        "esbuild": "*"
      }
    },
    "node_modules/@esbuild/android-arm": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm/-/android-arm-0.17.19.tgz",
      "integrity": "sha512-rIKddzqhmav7MSmoFCmDIb6e2W57geRsM94gV2l38fzhXMwq7hZoClug9USI2pFRGL06f4IOPHHpFNOkWieR8A==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/android-arm64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm64/-/android-arm64-0.17.19.tgz",
      "integrity": "sha512-KBMWvEZooR7+kzY0BtbTQn0OAYY7CsiydT63pVEaPtVYF0hXbUaOyZog37DKxK7NF3XacBJOpYT4adIJh+avxA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/android-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/android-x64/-/android-x64-0.17.19.tgz",
      "integrity": "sha512-uUTTc4xGNDT7YSArp/zbtmbhO0uEEK9/ETW29Wk1thYUJBz3IVnvgEiEwEa9IeLyvnpKrWK64Utw2bgUmDveww==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/darwin-arm64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.17.19.tgz",
      "integrity": "sha512-80wEoCfF/hFKM6WE1FyBHc9SfUblloAWx6FJkFWTWiCoht9Mc0ARGEM47e67W9rI09YoUxJL68WHfDRYEAvOhg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/darwin-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-x64/-/darwin-x64-0.17.19.tgz",
      "integrity": "sha512-IJM4JJsLhRYr9xdtLytPLSH9k/oxR3boaUIYiHkAawtwNOXKE8KoU8tMvryogdcT8AU+Bflmh81Xn6Q0vTZbQw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/freebsd-arm64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-arm64/-/freebsd-arm64-0.17.19.tgz",
      "integrity": "sha512-pBwbc7DufluUeGdjSU5Si+P3SoMF5DQ/F/UmTSb8HXO80ZEAJmrykPyzo1IfNbAoaqw48YRpv8shwd1NoI0jcQ==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/freebsd-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-x64/-/freebsd-x64-0.17.19.tgz",
      "integrity": "sha512-4lu+n8Wk0XlajEhbEffdy2xy53dpR06SlzvhGByyg36qJw6Kpfk7cp45DR/62aPH9mtJRmIyrXAS5UWBrJT6TQ==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-arm": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm/-/linux-arm-0.17.19.tgz",
      "integrity": "sha512-cdmT3KxjlOQ/gZ2cjfrQOtmhG4HJs6hhvm3mWSRDPtZ/lP5oe8FWceS10JaSJC13GBd4eH/haHnqf7hhGNLerA==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-arm64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm64/-/linux-arm64-0.17.19.tgz",
      "integrity": "sha512-ct1Tg3WGwd3P+oZYqic+YZF4snNl2bsnMKRkb3ozHmnM0dGWuxcPTTntAF6bOP0Sp4x0PjSF+4uHQ1xvxfRKqg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-ia32": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ia32/-/linux-ia32-0.17.19.tgz",
      "integrity": "sha512-w4IRhSy1VbsNxHRQpeGCHEmibqdTUx61Vc38APcsRbuVgK0OPEnQ0YD39Brymn96mOx48Y2laBQGqgZ0j9w6SQ==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-loong64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-loong64/-/linux-loong64-0.17.19.tgz",
      "integrity": "sha512-2iAngUbBPMq439a+z//gE+9WBldoMp1s5GWsUSgqHLzLJ9WoZLZhpwWuym0u0u/4XmZ3gpHmzV84PonE+9IIdQ==",
      "cpu": [
        "loong64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-mips64el": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-mips64el/-/linux-mips64el-0.17.19.tgz",
      "integrity": "sha512-LKJltc4LVdMKHsrFe4MGNPp0hqDFA1Wpt3jE1gEyM3nKUvOiO//9PheZZHfYRfYl6AwdTH4aTcXSqBerX0ml4A==",
      "cpu": [
        "mips64el"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-ppc64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ppc64/-/linux-ppc64-0.17.19.tgz",
      "integrity": "sha512-/c/DGybs95WXNS8y3Ti/ytqETiW7EU44MEKuCAcpPto3YjQbyK3IQVKfF6nbghD7EcLUGl0NbiL5Rt5DMhn5tg==",
      "cpu": [
        "ppc64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-riscv64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-riscv64/-/linux-riscv64-0.17.19.tgz",
      "integrity": "sha512-FC3nUAWhvFoutlhAkgHf8f5HwFWUL6bYdvLc/TTuxKlvLi3+pPzdZiFKSWz/PF30TB1K19SuCxDTI5KcqASJqA==",
      "cpu": [
        "riscv64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-s390x": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-s390x/-/linux-s390x-0.17.19.tgz",
      "integrity": "sha512-IbFsFbxMWLuKEbH+7sTkKzL6NJmG2vRyy6K7JJo55w+8xDk7RElYn6xvXtDW8HCfoKBFK69f3pgBJSUSQPr+4Q==",
      "cpu": [
        "s390x"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/linux-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.17.19.tgz",
      "integrity": "sha512-68ngA9lg2H6zkZcyp22tsVt38mlhWde8l3eJLWkyLrp4HwMUr3c1s/M2t7+kHIhvMjglIBrFpncX1SzMckomGw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/netbsd-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/netbsd-x64/-/netbsd-x64-0.17.19.tgz",
      "integrity": "sha512-CwFq42rXCR8TYIjIfpXCbRX0rp1jo6cPIUPSaWwzbVI4aOfX96OXY8M6KNmtPcg7QjYeDmN+DD0Wp3LaBOLf4Q==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "netbsd"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/openbsd-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/openbsd-x64/-/openbsd-x64-0.17.19.tgz",
      "integrity": "sha512-cnq5brJYrSZ2CF6c35eCmviIN3k3RczmHz8eYaVlNasVqsNY+JKohZU5MKmaOI+KkllCdzOKKdPs762VCPC20g==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "openbsd"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/sunos-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/sunos-x64/-/sunos-x64-0.17.19.tgz",
      "integrity": "sha512-vCRT7yP3zX+bKWFeP/zdS6SqdWB8OIpaRq/mbXQxTGHnIxspRtigpkUcDMlSCOejlHowLqII7K2JKevwyRP2rg==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "sunos"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/win32-arm64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-arm64/-/win32-arm64-0.17.19.tgz",
      "integrity": "sha512-yYx+8jwowUstVdorcMdNlzklLYhPxjniHWFKgRqH7IFlUEa0Umu3KuYplf1HUZZ422e3NU9F4LGb+4O0Kdcaag==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/win32-ia32": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-ia32/-/win32-ia32-0.17.19.tgz",
      "integrity": "sha512-eggDKanJszUtCdlVs0RB+h35wNlb5v4TWEkq4vZcmVt5u/HiDZrTXe2bWFQUez3RgNHwx/x4sk5++4NSSicKkw==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@esbuild/win32-x64": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-x64/-/win32-x64-0.17.19.tgz",
      "integrity": "sha512-lAhycmKnVOuRYNtRtatQR1LPQf2oYCkRGkSFnseDAKPl8lu5SOsK/e1sXe5a0Pc5kHIHe6P2I/ilntNv2xf3cA==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/@fastify/busboy": {
      "version": "2.1.1",
      "resolved": "https://registry.npmjs.org/@fastify/busboy/-/busboy-2.1.1.tgz",
      "integrity": "sha512-vBZP4NlzfOlerQTnba4aqZoMhE/a9HY7HRqoOPaETQcSQuWEIyZMHGfVu6w9wGtGK5fED5qRs2DteVCjOH60sA==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=14"
      }
    },
    "node_modules/@img/sharp-darwin-arm64": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-darwin-arm64/-/sharp-darwin-arm64-0.33.5.tgz",
      "integrity": "sha512-UT4p+iz/2H4twwAoLCqfA9UH5pI6DggwKEGuaPy7nCVQ8ZsiY5PIcrRvD1DzuY3qYL07NtIQcWnBSY/heikIFQ==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-darwin-arm64": "1.0.4"
      }
    },
    "node_modules/@img/sharp-darwin-x64": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-darwin-x64/-/sharp-darwin-x64-0.33.5.tgz",
      "integrity": "sha512-fyHac4jIc1ANYGRDxtiqelIbdWkIuQaI84Mv45KvGRRxSAa7o7d1ZKAOBaYbnepLC1WqxfpimdeWfvqqSGwR2Q==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-darwin-x64": "1.0.4"
      }
    },
    "node_modules/@img/sharp-libvips-darwin-arm64": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-darwin-arm64/-/sharp-libvips-darwin-arm64-1.0.4.tgz",
      "integrity": "sha512-XblONe153h0O2zuFfTAbQYAX2JhYmDHeWikp1LM9Hul9gVPjFY427k6dFEcOL72O01QxQsWi761svJ/ev9xEDg==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "darwin"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-libvips-darwin-x64": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-darwin-x64/-/sharp-libvips-darwin-x64-1.0.4.tgz",
      "integrity": "sha512-xnGR8YuZYfJGmWPvmlunFaWJsb9T/AO2ykoP3Fz/0X5XV2aoYBPkX6xqCQvUTKKiLddarLaxpzNe+b1hjeWHAQ==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "darwin"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-libvips-linux-arm": {
      "version": "1.0.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-linux-arm/-/sharp-libvips-linux-arm-1.0.5.tgz",
      "integrity": "sha512-gvcC4ACAOPRNATg/ov8/MnbxFDJqf/pDePbBnuBDcjsI8PssmjoKMAz4LtLaVi+OnSb5FK/yIOamqDwGmXW32g==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "linux"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-libvips-linux-arm64": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-linux-arm64/-/sharp-libvips-linux-arm64-1.0.4.tgz",
      "integrity": "sha512-9B+taZ8DlyyqzZQnoeIvDVR/2F4EbMepXMc/NdVbkzsJbzkUjhXv/70GQJ7tdLA4YJgNP25zukcxpX2/SueNrA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "linux"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-libvips-linux-s390x": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-linux-s390x/-/sharp-libvips-linux-s390x-1.0.4.tgz",
      "integrity": "sha512-u7Wz6ntiSSgGSGcjZ55im6uvTrOxSIS8/dgoVMoiGE9I6JAfU50yH5BoDlYA1tcuGS7g/QNtetJnxA6QEsCVTA==",
      "cpu": [
        "s390x"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "linux"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-libvips-linux-x64": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-linux-x64/-/sharp-libvips-linux-x64-1.0.4.tgz",
      "integrity": "sha512-MmWmQ3iPFZr0Iev+BAgVMb3ZyC4KeFc3jFxnNbEPas60e1cIfevbtuyf9nDGIzOaW9PdnDciJm+wFFaTlj5xYw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "linux"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-libvips-linuxmusl-arm64": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-linuxmusl-arm64/-/sharp-libvips-linuxmusl-arm64-1.0.4.tgz",
      "integrity": "sha512-9Ti+BbTYDcsbp4wfYib8Ctm1ilkugkA/uscUn6UXK1ldpC1JjiXbLfFZtRlBhjPZ5o1NCLiDbg8fhUPKStHoTA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "linux"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-libvips-linuxmusl-x64": {
      "version": "1.0.4",
      "resolved": "https://registry.npmjs.org/@img/sharp-libvips-linuxmusl-x64/-/sharp-libvips-linuxmusl-x64-1.0.4.tgz",
      "integrity": "sha512-viYN1KX9m+/hGkJtvYYp+CCLgnJXwiQB39damAO7WMdKWlIhmYTfHjwSbQeUK/20vY154mwezd9HflVFM1wVSw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "linux"
      ],
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-linux-arm": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-linux-arm/-/sharp-linux-arm-0.33.5.tgz",
      "integrity": "sha512-JTS1eldqZbJxjvKaAkxhZmBqPRGmxgu+qFKSInv8moZ2AmT5Yib3EQ1c6gp493HvrvV8QgdOXdyaIBrhvFhBMQ==",
      "cpu": [
        "arm"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-linux-arm": "1.0.5"
      }
    },
    "node_modules/@img/sharp-linux-arm64": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-linux-arm64/-/sharp-linux-arm64-0.33.5.tgz",
      "integrity": "sha512-JMVv+AMRyGOHtO1RFBiJy/MBsgz0x4AWrT6QoEVVTyh1E39TrCUpTRI7mx9VksGX4awWASxqCYLCV4wBZHAYxA==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-linux-arm64": "1.0.4"
      }
    },
    "node_modules/@img/sharp-linux-s390x": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-linux-s390x/-/sharp-linux-s390x-0.33.5.tgz",
      "integrity": "sha512-y/5PCd+mP4CA/sPDKl2961b+C9d+vPAveS33s6Z3zfASk2j5upL6fXVPZi7ztePZ5CuH+1kW8JtvxgbuXHRa4Q==",
      "cpu": [
        "s390x"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-linux-s390x": "1.0.4"
      }
    },
    "node_modules/@img/sharp-linux-x64": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-linux-x64/-/sharp-linux-x64-0.33.5.tgz",
      "integrity": "sha512-opC+Ok5pRNAzuvq1AG0ar+1owsu842/Ab+4qvU879ippJBHvyY5n2mxF1izXqkPYlGuP/M556uh53jRLJmzTWA==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-linux-x64": "1.0.4"
      }
    },
    "node_modules/@img/sharp-linuxmusl-arm64": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-linuxmusl-arm64/-/sharp-linuxmusl-arm64-0.33.5.tgz",
      "integrity": "sha512-XrHMZwGQGvJg2V/oRSUfSAfjfPxO+4DkiRh6p2AFjLQztWUuY/o8Mq0eMQVIY7HJ1CDQUJlxGGZRw1a5bqmd1g==",
      "cpu": [
        "arm64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-linuxmusl-arm64": "1.0.4"
      }
    },
    "node_modules/@img/sharp-linuxmusl-x64": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-linuxmusl-x64/-/sharp-linuxmusl-x64-0.33.5.tgz",
      "integrity": "sha512-WT+d/cgqKkkKySYmqoZ8y3pxx7lx9vVejxW/W4DOFMYVSkErR+w7mf2u8m/y4+xHe7yY9DAXQMWQhpnMuFfScw==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-libvips-linuxmusl-x64": "1.0.4"
      }
    },
    "node_modules/@img/sharp-wasm32": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-wasm32/-/sharp-wasm32-0.33.5.tgz",
      "integrity": "sha512-ykUW4LVGaMcU9lu9thv85CbRMAwfeadCJHRsg2GmeRa/cJxsVY9Rbd57JcMxBkKHag5U/x7TSBpScF4U8ElVzg==",
      "cpu": [
        "wasm32"
      ],
      "dev": true,
      "license": "Apache-2.0 AND LGPL-3.0-or-later AND MIT",
      "optional": true,
      "dependencies": {
        "@emnapi/runtime": "^1.2.0"
      },
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-win32-ia32": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-win32-ia32/-/sharp-win32-ia32-0.33.5.tgz",
      "integrity": "sha512-T36PblLaTwuVJ/zw/LaH0PdZkRz5rd3SmMHX8GSmR7vtNSP5Z6bQkExdSK7xGWyxLw4sUknBuugTelgw2faBbQ==",
      "cpu": [
        "ia32"
      ],
      "dev": true,
      "license": "Apache-2.0 AND LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@img/sharp-win32-x64": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/@img/sharp-win32-x64/-/sharp-win32-x64-0.33.5.tgz",
      "integrity": "sha512-MpY/o8/8kj+EcnxwvrP4aTJSWw/aZ7JIGR4aBeZkZw5B7/Jn+tY9/VNwtcoGmdT7GfggGIU4kygOMSbYnOrAbg==",
      "cpu": [
        "x64"
      ],
      "dev": true,
      "license": "Apache-2.0 AND LGPL-3.0-or-later",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      }
    },
    "node_modules/@jridgewell/resolve-uri": {
      "version": "3.1.2",
      "resolved": "https://registry.npmjs.org/@jridgewell/resolve-uri/-/resolve-uri-3.1.2.tgz",
      "integrity": "sha512-bRISgCIjP20/tbWSPWMEi54QVPRZExkuD9lJL+UIxUKtwVJA8wW1Trb1jMs1RFXo1CBTNZ/5hpC9QvmKWdopKw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6.0.0"
      }
    },
    "node_modules/@jridgewell/sourcemap-codec": {
      "version": "1.5.5",
      "resolved": "https://registry.npmjs.org/@jridgewell/sourcemap-codec/-/sourcemap-codec-1.5.5.tgz",
      "integrity": "sha512-cYQ9310grqxueWbl+WuIUIaiUaDcj7WOq5fVhEljNVgRfOUhY9fy2zTvfoqWsnebh8Sl70VScFbICvJnLKB0Og==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/@jridgewell/trace-mapping": {
      "version": "0.3.9",
      "resolved": "https://registry.npmjs.org/@jridgewell/trace-mapping/-/trace-mapping-0.3.9.tgz",
      "integrity": "sha512-3Belt6tdc8bPgAtbcmdtNJlirVoTmEb5e2gC94PnkwEW9jI6CAHUeoG85tjWP5WquqfavoMtMwiG4P926ZKKuQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@jridgewell/resolve-uri": "^3.0.3",
        "@jridgewell/sourcemap-codec": "^1.4.10"
      }
    },
    "node_modules/acorn": {
      "version": "8.14.0",
      "resolved": "https://registry.npmjs.org/acorn/-/acorn-8.14.0.tgz",
      "integrity": "sha512-cl669nCJTZBsL97OF4kUQm5g5hC2uihk0NxY3WENAC0TYdILVkAyHymAntgxGkl7K+t0cXIrH5siy5S4XkFycA==",
      "dev": true,
      "license": "MIT",
      "bin": {
        "acorn": "bin/acorn"
      },
      "engines": {
        "node": ">=0.4.0"
      }
    },
    "node_modules/acorn-walk": {
      "version": "8.3.2",
      "resolved": "https://registry.npmjs.org/acorn-walk/-/acorn-walk-8.3.2.tgz",
      "integrity": "sha512-cjkyv4OtNCIeqhHrfS81QWXoCBPExR/J62oyEqepVw8WaQeSqpW2uhuLPh1m9eWhDuOo/jUXVTlifvesOWp/4A==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=0.4.0"
      }
    },
    "node_modules/as-table": {
      "version": "1.0.55",
      "resolved": "https://registry.npmjs.org/as-table/-/as-table-1.0.55.tgz",
      "integrity": "sha512-xvsWESUJn0JN421Xb9MQw6AsMHRCUknCe0Wjlxvjud80mU4E6hQf1A6NzQKcYNmYw62MfzEtXc+badstZP3JpQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "printable-characters": "^1.0.42"
      }
    },
    "node_modules/blake3-wasm": {
      "version": "2.1.5",
      "resolved": "https://registry.npmjs.org/blake3-wasm/-/blake3-wasm-2.1.5.tgz",
      "integrity": "sha512-F1+K8EbfOZE49dtoPtmxUQrpXaBIl3ICvasLh+nJta0xkz+9kF/7uet9fLnwKqhDrmj6g+6K3Tw9yQPUg2ka5g==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/color": {
      "version": "4.2.3",
      "resolved": "https://registry.npmjs.org/color/-/color-4.2.3.tgz",
      "integrity": "sha512-1rXeuUUiGGrykh+CeBdu5Ie7OJwinCgQY0bc7GCRxy5xVHy+moaqkpL/jqQq0MtQOeYcrqEz4abc5f0KtU7W4A==",
      "dev": true,
      "license": "MIT",
      "optional": true,
      "dependencies": {
        "color-convert": "^2.0.1",
        "color-string": "^1.9.0"
      },
      "engines": {
        "node": ">=12.5.0"
      }
    },
    "node_modules/color-convert": {
      "version": "2.0.1",
      "resolved": "https://registry.npmjs.org/color-convert/-/color-convert-2.0.1.tgz",
      "integrity": "sha512-RRECPsj7iu/xb5oKYcsFHSppFNnsj/52OVTRKb4zP5onXwVF3zVmmToNcOfGC+CRDpfK/U584fMg38ZHCaElKQ==",
      "dev": true,
      "license": "MIT",
      "optional": true,
      "dependencies": {
        "color-name": "~1.1.4"
      },
      "engines": {
        "node": ">=7.0.0"
      }
    },
    "node_modules/color-name": {
      "version": "1.1.4",
      "resolved": "https://registry.npmjs.org/color-name/-/color-name-1.1.4.tgz",
      "integrity": "sha512-dOy+3AuW3a2wNbZHIuMZpTcgjGuLU/uBL/ubcZF9OXbDo8ff4O8yVp5Bf0efS8uEoYo5q4Fx7dY9OgQGXgAsQA==",
      "dev": true,
      "license": "MIT",
      "optional": true
    },
    "node_modules/color-string": {
      "version": "1.9.1",
      "resolved": "https://registry.npmjs.org/color-string/-/color-string-1.9.1.tgz",
      "integrity": "sha512-shrVawQFojnZv6xM40anx4CkoDP+fZsw/ZerEMsW/pyzsRbElpsL/DBVW7q3ExxwusdNXI3lXpuhEZkzs8p5Eg==",
      "dev": true,
      "license": "MIT",
      "optional": true,
      "dependencies": {
        "color-name": "^1.0.0",
        "simple-swizzle": "^0.2.2"
      }
    },
    "node_modules/cookie": {
      "version": "0.7.2",
      "resolved": "https://registry.npmjs.org/cookie/-/cookie-0.7.2.tgz",
      "integrity": "sha512-yki5XnKuf750l50uGTllt6kKILY4nQ1eNIQatoXEByZ5dWgnKqbnqmTrBE5B4N7lrMJKQ2ytWMiTO2o0v6Ew/w==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/data-uri-to-buffer": {
      "version": "2.0.2",
      "resolved": "https://registry.npmjs.org/data-uri-to-buffer/-/data-uri-to-buffer-2.0.2.tgz",
      "integrity": "sha512-ND9qDTLc6diwj+Xe5cdAgVTbLVdXbtxTJRXRhli8Mowuaan+0EJOtdqJ0QCHNSSPyoXGx9HX2/VMnKeC34AChA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/defu": {
      "version": "6.1.4",
      "resolved": "https://registry.npmjs.org/defu/-/defu-6.1.4.tgz",
      "integrity": "sha512-mEQCMmwJu317oSz8CwdIOdwf3xMif1ttiM8LTufzc3g6kR+9Pe236twL8j3IYT1F7GfRgGcW6MWxzZjLIkuHIg==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/detect-libc": {
      "version": "2.1.2",
      "resolved": "https://registry.npmjs.org/detect-libc/-/detect-libc-2.1.2.tgz",
      "integrity": "sha512-Btj2BOOO83o3WyH59e8MgXsxEQVcarkUOpEYrubB0urwnN10yQ364rsiByU11nZlqWYZm05i/of7io4mzihBtQ==",
      "dev": true,
      "license": "Apache-2.0",
      "optional": true,
      "engines": {
        "node": ">=8"
      }
    },
    "node_modules/esbuild": {
      "version": "0.17.19",
      "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.17.19.tgz",
      "integrity": "sha512-XQ0jAPFkK/u3LcVRcvVHQcTIqD6E2H1fvZMA5dQPSOWb3suUbWbfbRf94pjc0bNzRYLfIrDRQXr7X+LHIm5oHw==",
      "dev": true,
      "hasInstallScript": true,
      "license": "MIT",
      "peer": true,
      "bin": {
        "esbuild": "bin/esbuild"
      },
      "engines": {
        "node": ">=12"
      },
      "optionalDependencies": {
        "@esbuild/android-arm": "0.17.19",
        "@esbuild/android-arm64": "0.17.19",
        "@esbuild/android-x64": "0.17.19",
        "@esbuild/darwin-arm64": "0.17.19",
        "@esbuild/darwin-x64": "0.17.19",
        "@esbuild/freebsd-arm64": "0.17.19",
        "@esbuild/freebsd-x64": "0.17.19",
        "@esbuild/linux-arm": "0.17.19",
        "@esbuild/linux-arm64": "0.17.19",
        "@esbuild/linux-ia32": "0.17.19",
        "@esbuild/linux-loong64": "0.17.19",
        "@esbuild/linux-mips64el": "0.17.19",
        "@esbuild/linux-ppc64": "0.17.19",
        "@esbuild/linux-riscv64": "0.17.19",
        "@esbuild/linux-s390x": "0.17.19",
        "@esbuild/linux-x64": "0.17.19",
        "@esbuild/netbsd-x64": "0.17.19",
        "@esbuild/openbsd-x64": "0.17.19",
        "@esbuild/sunos-x64": "0.17.19",
        "@esbuild/win32-arm64": "0.17.19",
        "@esbuild/win32-ia32": "0.17.19",
        "@esbuild/win32-x64": "0.17.19"
      }
    },
    "node_modules/escape-string-regexp": {
      "version": "4.0.0",
      "resolved": "https://registry.npmjs.org/escape-string-regexp/-/escape-string-regexp-4.0.0.tgz",
      "integrity": "sha512-TtpcNJ3XAzx3Gq8sWRzJaVajRs0uVxA2YAkdb1jm2YkPz4G6egUFAyA3n5vtEIZefPk5Wa4UXbKuS5fKkJWdgA==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=10"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/estree-walker": {
      "version": "0.6.1",
      "resolved": "https://registry.npmjs.org/estree-walker/-/estree-walker-0.6.1.tgz",
      "integrity": "sha512-SqmZANLWS0mnatqbSfRP5g8OXZC12Fgg1IwNtLsyHDzJizORW4khDfjPqJZsemPWBB2uqykUah5YpQ6epsqC/w==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/exit-hook": {
      "version": "2.2.1",
      "resolved": "https://registry.npmjs.org/exit-hook/-/exit-hook-2.2.1.tgz",
      "integrity": "sha512-eNTPlAD67BmP31LDINZ3U7HSF8l57TxOY2PmBJ1shpCvpnxBF93mWCE8YHBnXs8qiUZJc9WDcWIeC3a2HIAMfw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=6"
      },
      "funding": {
        "url": "https://github.com/sponsors/sindresorhus"
      }
    },
    "node_modules/exsolve": {
      "version": "1.0.8",
      "resolved": "https://registry.npmjs.org/exsolve/-/exsolve-1.0.8.tgz",
      "integrity": "sha512-LmDxfWXwcTArk8fUEnOfSZpHOJ6zOMUJKOtFLFqJLoKJetuQG874Uc7/Kki7zFLzYybmZhp1M7+98pfMqeX8yA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/fsevents": {
      "version": "2.3.3",
      "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
      "integrity": "sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw==",
      "dev": true,
      "hasInstallScript": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": "^8.16.0 || ^10.6.0 || >=11.0.0"
      }
    },
    "node_modules/get-source": {
      "version": "2.0.12",
      "resolved": "https://registry.npmjs.org/get-source/-/get-source-2.0.12.tgz",
      "integrity": "sha512-X5+4+iD+HoSeEED+uwrQ07BOQr0kEDFMVqqpBuI+RaZBpBpHCuXxo70bjar6f0b0u/DQJsJ7ssurpP0V60Az+w==",
      "dev": true,
      "license": "Unlicense",
      "dependencies": {
        "data-uri-to-buffer": "^2.0.0",
        "source-map": "^0.6.1"
      }
    },
    "node_modules/glob-to-regexp": {
      "version": "0.4.1",
      "resolved": "https://registry.npmjs.org/glob-to-regexp/-/glob-to-regexp-0.4.1.tgz",
      "integrity": "sha512-lkX1HJXwyMcprw/5YUZc2s7DrpAiHB21/V+E1rHUrVNokkvB6bqMzT0VfV6/86ZNabt1k14YOIaT7nDvOX3Iiw==",
      "dev": true,
      "license": "BSD-2-Clause"
    },
    "node_modules/is-arrayish": {
      "version": "0.3.4",
      "resolved": "https://registry.npmjs.org/is-arrayish/-/is-arrayish-0.3.4.tgz",
      "integrity": "sha512-m6UrgzFVUYawGBh1dUsWR5M2Clqic9RVXC/9f8ceNlv2IcO9j9J/z8UoCLPqtsPBFNzEpfR3xftohbfqDx8EQA==",
      "dev": true,
      "license": "MIT",
      "optional": true
    },
    "node_modules/magic-string": {
      "version": "0.25.9",
      "resolved": "https://registry.npmjs.org/magic-string/-/magic-string-0.25.9.tgz",
      "integrity": "sha512-RmF0AsMzgt25qzqqLc1+MbHmhdx0ojF2Fvs4XnOqz2ZOBXzzkEwc/dJQZCYHAn7v1jbVOjAZfK8msRn4BxO4VQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "sourcemap-codec": "^1.4.8"
      }
    },
    "node_modules/mime": {
      "version": "3.0.0",
      "resolved": "https://registry.npmjs.org/mime/-/mime-3.0.0.tgz",
      "integrity": "sha512-jSCU7/VB1loIWBZe14aEYHU/+1UMEHoaO7qxCOVJOw9GgH72VAWppxNcjU+x9a2k3GSIBXNKxXQFqRvvZ7vr3A==",
      "dev": true,
      "license": "MIT",
      "bin": {
        "mime": "cli.js"
      },
      "engines": {
        "node": ">=10.0.0"
      }
    },
    "node_modules/miniflare": {
      "version": "3.20250718.3",
      "resolved": "https://registry.npmjs.org/miniflare/-/miniflare-3.20250718.3.tgz",
      "integrity": "sha512-JuPrDJhwLrNLEJiNLWO7ZzJrv/Vv9kZuwMYCfv0LskQDM6Eonw4OvywO3CH/wCGjgHzha/qyjUh8JQ068TjDgQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@cspotcode/source-map-support": "0.8.1",
        "acorn": "8.14.0",
        "acorn-walk": "8.3.2",
        "exit-hook": "2.2.1",
        "glob-to-regexp": "0.4.1",
        "stoppable": "1.1.0",
        "undici": "^5.28.5",
        "workerd": "1.20250718.0",
        "ws": "8.18.0",
        "youch": "3.3.4",
        "zod": "3.22.3"
      },
      "bin": {
        "miniflare": "bootstrap.js"
      },
      "engines": {
        "node": ">=16.13"
      }
    },
    "node_modules/mustache": {
      "version": "4.2.0",
      "resolved": "https://registry.npmjs.org/mustache/-/mustache-4.2.0.tgz",
      "integrity": "sha512-71ippSywq5Yb7/tVYyGbkBggbU8H3u5Rz56fH60jGFgr8uHwxs+aSKeqmluIVzM0m0kB7xQjKS6qPfd0b2ZoqQ==",
      "dev": true,
      "license": "MIT",
      "bin": {
        "mustache": "bin/mustache"
      }
    },
    "node_modules/ohash": {
      "version": "2.0.11",
      "resolved": "https://registry.npmjs.org/ohash/-/ohash-2.0.11.tgz",
      "integrity": "sha512-RdR9FQrFwNBNXAr4GixM8YaRZRJ5PUWbKYbE5eOsrwAjJW0q2REGcf79oYPsLyskQCZG1PLN+S/K1V00joZAoQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/path-to-regexp": {
      "version": "6.3.0",
      "resolved": "https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-6.3.0.tgz",
      "integrity": "sha512-Yhpw4T9C6hPpgPeA28us07OJeqZ5EzQTkbfwuhsUg0c237RomFoETJgmp2sa3F/41gfLE6G5cqcYwznmeEeOlQ==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/pathe": {
      "version": "2.0.3",
      "resolved": "https://registry.npmjs.org/pathe/-/pathe-2.0.3.tgz",
      "integrity": "sha512-WUjGcAqP1gQacoQe+OBJsFA7Ld4DyXuUIjZ5cc75cLHvJ7dtNsTugphxIADwspS+AraAUePCKrSVtPLFj/F88w==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/printable-characters": {
      "version": "1.0.42",
      "resolved": "https://registry.npmjs.org/printable-characters/-/printable-characters-1.0.42.tgz",
      "integrity": "sha512-dKp+C4iXWK4vVYZmYSd0KBH5F/h1HoZRsbJ82AVKRO3PEo8L4lBS/vLwhVtpwwuYcoIsVY+1JYKR268yn480uQ==",
      "dev": true,
      "license": "Unlicense"
    },
    "node_modules/rollup-plugin-inject": {
      "version": "3.0.2",
      "resolved": "https://registry.npmjs.org/rollup-plugin-inject/-/rollup-plugin-inject-3.0.2.tgz",
      "integrity": "sha512-ptg9PQwzs3orn4jkgXJ74bfs5vYz1NCZlSQMBUA0wKcGp5i5pA1AO3fOUEte8enhGUC+iapTCzEWw2jEFFUO/w==",
      "deprecated": "This package has been deprecated and is no longer maintained. Please use @rollup/plugin-inject.",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "estree-walker": "^0.6.1",
        "magic-string": "^0.25.3",
        "rollup-pluginutils": "^2.8.1"
      }
    },
    "node_modules/rollup-plugin-node-polyfills": {
      "version": "0.2.1",
      "resolved": "https://registry.npmjs.org/rollup-plugin-node-polyfills/-/rollup-plugin-node-polyfills-0.2.1.tgz",
      "integrity": "sha512-4kCrKPTJ6sK4/gLL/U5QzVT8cxJcofO0OU74tnB19F40cmuAKSzH5/siithxlofFEjwvw1YAhPmbvGNA6jEroA==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "rollup-plugin-inject": "^3.0.0"
      }
    },
    "node_modules/rollup-pluginutils": {
      "version": "2.8.2",
      "resolved": "https://registry.npmjs.org/rollup-pluginutils/-/rollup-pluginutils-2.8.2.tgz",
      "integrity": "sha512-EEp9NhnUkwY8aif6bxgovPHMoMoNr2FulJziTndpt5H9RdwC47GSGuII9XxpSdzVGM0GWrNPHV6ie1LTNJPaLQ==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "estree-walker": "^0.6.1"
      }
    },
    "node_modules/semver": {
      "version": "7.7.3",
      "resolved": "https://registry.npmjs.org/semver/-/semver-7.7.3.tgz",
      "integrity": "sha512-SdsKMrI9TdgjdweUSR9MweHA4EJ8YxHn8DFaDisvhVlUOe4BF1tLD7GAj0lIqWVl+dPb/rExr0Btby5loQm20Q==",
      "dev": true,
      "license": "ISC",
      "optional": true,
      "bin": {
        "semver": "bin/semver.js"
      },
      "engines": {
        "node": ">=10"
      }
    },
    "node_modules/sharp": {
      "version": "0.33.5",
      "resolved": "https://registry.npmjs.org/sharp/-/sharp-0.33.5.tgz",
      "integrity": "sha512-haPVm1EkS9pgvHrQ/F3Xy+hgcuMV0Wm9vfIBSiwZ05k+xgb0PkBQpGsAA/oWdDobNaZTH5ppvHtzCFbnSEwHVw==",
      "dev": true,
      "hasInstallScript": true,
      "license": "Apache-2.0",
      "optional": true,
      "dependencies": {
        "color": "^4.2.3",
        "detect-libc": "^2.0.3",
        "semver": "^7.6.3"
      },
      "engines": {
        "node": "^18.17.0 || ^20.3.0 || >=21.0.0"
      },
      "funding": {
        "url": "https://opencollective.com/libvips"
      },
      "optionalDependencies": {
        "@img/sharp-darwin-arm64": "0.33.5",
        "@img/sharp-darwin-x64": "0.33.5",
        "@img/sharp-libvips-darwin-arm64": "1.0.4",
        "@img/sharp-libvips-darwin-x64": "1.0.4",
        "@img/sharp-libvips-linux-arm": "1.0.5",
        "@img/sharp-libvips-linux-arm64": "1.0.4",
        "@img/sharp-libvips-linux-s390x": "1.0.4",
        "@img/sharp-libvips-linux-x64": "1.0.4",
        "@img/sharp-libvips-linuxmusl-arm64": "1.0.4",
        "@img/sharp-libvips-linuxmusl-x64": "1.0.4",
        "@img/sharp-linux-arm": "0.33.5",
        "@img/sharp-linux-arm64": "0.33.5",
        "@img/sharp-linux-s390x": "0.33.5",
        "@img/sharp-linux-x64": "0.33.5",
        "@img/sharp-linuxmusl-arm64": "0.33.5",
        "@img/sharp-linuxmusl-x64": "0.33.5",
        "@img/sharp-wasm32": "0.33.5",
        "@img/sharp-win32-ia32": "0.33.5",
        "@img/sharp-win32-x64": "0.33.5"
      }
    },
    "node_modules/simple-swizzle": {
      "version": "0.2.4",
      "resolved": "https://registry.npmjs.org/simple-swizzle/-/simple-swizzle-0.2.4.tgz",
      "integrity": "sha512-nAu1WFPQSMNr2Zn9PGSZK9AGn4t/y97lEm+MXTtUDwfP0ksAIX4nO+6ruD9Jwut4C49SB1Ws+fbXsm/yScWOHw==",
      "dev": true,
      "license": "MIT",
      "optional": true,
      "dependencies": {
        "is-arrayish": "^0.3.1"
      }
    },
    "node_modules/source-map": {
      "version": "0.6.1",
      "resolved": "https://registry.npmjs.org/source-map/-/source-map-0.6.1.tgz",
      "integrity": "sha512-UjgapumWlbMhkBgzT7Ykc5YXUT46F0iKu8SGXq0bcwP5dz/h0Plj6enJqjz1Zbq2l5WaqYnrVbwWOWMyF3F47g==",
      "dev": true,
      "license": "BSD-3-Clause",
      "engines": {
        "node": ">=0.10.0"
      }
    },
    "node_modules/sourcemap-codec": {
      "version": "1.4.8",
      "resolved": "https://registry.npmjs.org/sourcemap-codec/-/sourcemap-codec-1.4.8.tgz",
      "integrity": "sha512-9NykojV5Uih4lgo5So5dtw+f0JgJX30KCNI8gwhz2J9A15wD0Ml6tjHKwf6fTSa6fAdVBdZeNOs9eJ71qCk8vA==",
      "deprecated": "Please use @jridgewell/sourcemap-codec instead",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/stacktracey": {
      "version": "2.1.8",
      "resolved": "https://registry.npmjs.org/stacktracey/-/stacktracey-2.1.8.tgz",
      "integrity": "sha512-Kpij9riA+UNg7TnphqjH7/CzctQ/owJGNbFkfEeve4Z4uxT5+JapVLFXcsurIfN34gnTWZNJ/f7NMG0E8JDzTw==",
      "dev": true,
      "license": "Unlicense",
      "dependencies": {
        "as-table": "^1.0.36",
        "get-source": "^2.0.12"
      }
    },
    "node_modules/stoppable": {
      "version": "1.1.0",
      "resolved": "https://registry.npmjs.org/stoppable/-/stoppable-1.1.0.tgz",
      "integrity": "sha512-KXDYZ9dszj6bzvnEMRYvxgeTHU74QBFL54XKtP3nyMuJ81CFYtABZ3bAzL2EdFUaEwJOBOgENyFj3R7oTzDyyw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=4",
        "npm": ">=6"
      }
    },
    "node_modules/tslib": {
      "version": "2.8.1",
      "resolved": "https://registry.npmjs.org/tslib/-/tslib-2.8.1.tgz",
      "integrity": "sha512-oJFu94HQb+KVduSUQL7wnpmqnfmLsOA/nAh6b6EH0wCEoK0/mPeXU6c3wKDV83MkOuHPRHtSXKKU99IBazS/2w==",
      "dev": true,
      "license": "0BSD",
      "optional": true
    },
    "node_modules/typescript": {
      "version": "5.9.3",
      "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz",
      "integrity": "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==",
      "dev": true,
      "license": "Apache-2.0",
      "bin": {
        "tsc": "bin/tsc",
        "tsserver": "bin/tsserver"
      },
      "engines": {
        "node": ">=14.17"
      }
    },
    "node_modules/ufo": {
      "version": "1.6.1",
      "resolved": "https://registry.npmjs.org/ufo/-/ufo-1.6.1.tgz",
      "integrity": "sha512-9a4/uxlTWJ4+a5i0ooc1rU7C7YOw3wT+UGqdeNNHWnOF9qcMBgLRS+4IYUqbczewFx4mLEig6gawh7X6mFlEkA==",
      "dev": true,
      "license": "MIT"
    },
    "node_modules/undici": {
      "version": "5.29.0",
      "resolved": "https://registry.npmjs.org/undici/-/undici-5.29.0.tgz",
      "integrity": "sha512-raqeBD6NQK4SkWhQzeYKd1KmIG6dllBOTt55Rmkt4HtI9mwdWtJljnrXjAFUBLTSN67HWrOIZ3EPF4kjUw80Bg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "@fastify/busboy": "^2.0.0"
      },
      "engines": {
        "node": ">=14.0"
      }
    },
    "node_modules/unenv": {
      "version": "2.0.0-rc.14",
      "resolved": "https://registry.npmjs.org/unenv/-/unenv-2.0.0-rc.14.tgz",
      "integrity": "sha512-od496pShMen7nOy5VmVJCnq8rptd45vh6Nx/r2iPbrba6pa6p+tS2ywuIHRZ/OBvSbQZB0kWvpO9XBNVFXHD3Q==",
      "dev": true,
      "license": "MIT",
      "peer": true,
      "dependencies": {
        "defu": "^6.1.4",
        "exsolve": "^1.0.1",
        "ohash": "^2.0.10",
        "pathe": "^2.0.3",
        "ufo": "^1.5.4"
      }
    },
    "node_modules/workerd": {
      "version": "1.20250718.0",
      "resolved": "https://registry.npmjs.org/workerd/-/workerd-1.20250718.0.tgz",
      "integrity": "sha512-kqkIJP/eOfDlUyBzU7joBg+tl8aB25gEAGqDap+nFWb+WHhnooxjGHgxPBy3ipw2hnShPFNOQt5lFRxbwALirg==",
      "dev": true,
      "hasInstallScript": true,
      "license": "Apache-2.0",
      "peer": true,
      "bin": {
        "workerd": "bin/workerd"
      },
      "engines": {
        "node": ">=16"
      },
      "optionalDependencies": {
        "@cloudflare/workerd-darwin-64": "1.20250718.0",
        "@cloudflare/workerd-darwin-arm64": "1.20250718.0",
        "@cloudflare/workerd-linux-64": "1.20250718.0",
        "@cloudflare/workerd-linux-arm64": "1.20250718.0",
        "@cloudflare/workerd-windows-64": "1.20250718.0"
      }
    },
    "node_modules/wrangler": {
      "version": "3.114.16",
      "resolved": "https://registry.npmjs.org/wrangler/-/wrangler-3.114.16.tgz",
      "integrity": "sha512-ve/ULRjrquu5BHNJ+1T0ipJJlJ6pD7qLmhwRkk0BsUIxatNe4HP4odX/R4Mq/RHG6LOnVAFs7SMeSHlz/1mNlQ==",
      "dev": true,
      "license": "MIT OR Apache-2.0",
      "dependencies": {
        "@cloudflare/kv-asset-handler": "0.3.4",
        "@cloudflare/unenv-preset": "2.0.2",
        "@esbuild-plugins/node-globals-polyfill": "0.2.3",
        "@esbuild-plugins/node-modules-polyfill": "0.2.2",
        "blake3-wasm": "2.1.5",
        "esbuild": "0.17.19",
        "miniflare": "3.20250718.3",
        "path-to-regexp": "6.3.0",
        "unenv": "2.0.0-rc.14",
        "workerd": "1.20250718.0"
      },
      "bin": {
        "wrangler": "bin/wrangler.js",
        "wrangler2": "bin/wrangler.js"
      },
      "engines": {
        "node": ">=16.17.0"
      },
      "optionalDependencies": {
        "fsevents": "~2.3.2",
        "sharp": "^0.33.5"
      },
      "peerDependencies": {
        "@cloudflare/workers-types": "^4.20250408.0"
      },
      "peerDependenciesMeta": {
        "@cloudflare/workers-types": {
          "optional": true
        }
      }
    },
    "node_modules/ws": {
      "version": "8.18.0",
      "resolved": "https://registry.npmjs.org/ws/-/ws-8.18.0.tgz",
      "integrity": "sha512-8VbfWfHLbbwu3+N6OKsOMpBdT4kXPDDB9cJk2bJ6mh9ucxdlnNvH1e+roYkKmN9Nxw2yjz7VzeO9oOz2zJ04Pw==",
      "dev": true,
      "license": "MIT",
      "engines": {
        "node": ">=10.0.0"
      },
      "peerDependencies": {
        "bufferutil": "^4.0.1",
        "utf-8-validate": ">=5.0.2"
      },
      "peerDependenciesMeta": {
        "bufferutil": {
          "optional": true
        },
        "utf-8-validate": {
          "optional": true
        }
      }
    },
    "node_modules/youch": {
      "version": "3.3.4",
      "resolved": "https://registry.npmjs.org/youch/-/youch-3.3.4.tgz",
      "integrity": "sha512-UeVBXie8cA35DS6+nBkls68xaBBXCye0CNznrhszZjTbRVnJKQuNsyLKBTTL4ln1o1rh2PKtv35twV7irj5SEg==",
      "dev": true,
      "license": "MIT",
      "dependencies": {
        "cookie": "^0.7.1",
        "mustache": "^4.2.0",
        "stacktracey": "^2.1.8"
      }
    },
    "node_modules/zod": {
      "version": "3.22.3",
      "resolved": "https://registry.npmjs.org/zod/-/zod-3.22.3.tgz",
      "integrity": "sha512-EjIevzuJRiRPbVH4mGc8nApb/lVLKVpmUhAaR5R5doKGfAnGJ6Gr3CViAVjP+4FWSxCsybeWQdcgCtbX+7oZug==",
      "dev": true,
      "license": "MIT",
      "funding": {
        "url": "https://github.com/sponsors/colinhacks"
      }
    }
  }
}

```

--- FILE: package.json ---

```json
{
  "name": "synapse-core",
  "version": "1.0.0",
  "description": "Synapse Core Cloudflare Worker",
  "main": "src/index.ts",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "deploy": "wrangler deploy"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "devDependencies": {
    "@cloudflare/workers-types": "^4.20230419.0",
    "typescript": "^5.0.4",
    "wrangler": "^3.0.0"
  }
}

```

--- FILE: payload.json ---

```json
{
    "message": {
        "chat": {
            "id": 123456789
        },
        "text": "Hello Gemini, verify model 2.5"
    }
}
```

--- FILE: schema.sql ---

```sql
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

```

--- FILE: src\index.ts ---

```typescript

export interface Env {
	TELEGRAM_TOKEN: string;
	GEMINI_API_KEY: string;
	DB: D1Database;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (request.method === "POST") {
			try {
				const update: any = await request.json();
				if (update.message && update.message.text) {
					const chatId = update.message.chat.id;
					const userText = update.message.text;

					console.log(`Received message: ${userText} from chat: ${chatId}`);

					// --- Step 1: Fetch Context History ---
					const history = await env.DB.prepare(
						"SELECT role, content FROM messages WHERE chat_id = ? ORDER BY created_at ASC LIMIT 10"
					).bind(chatId).all();

					const contents = [];
					if (history.results && history.results.length > 0) {
						for (const msg of history.results) {
							contents.push({
								role: msg.role === 'user' ? 'user' : 'model',
								parts: [{ text: msg.content as string }]
							});
						}
					}

					// Add current user message
					contents.push({
						role: "user",
						parts: [{ text: userText }]
					});

					const geminiUrl = `https://generativelanguage.googleapis.com/v1/models/gemini-2.5-flash:generateContent?key=${env.GEMINI_API_KEY}`;
					const payload = { contents: contents };

					console.log("Sending payload to Gemini with history:", JSON.stringify(payload));

					const geminiResponse = await fetch(geminiUrl, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify(payload)
					});

					const responseText = await geminiResponse.text();
					console.log(`Gemini raw response status: ${geminiResponse.status}`);
					console.log("Gemini raw response body:", responseText);

					let replyText = "Error communicating with Gemini.";

					if (geminiResponse.ok) {
						try {
							const data = JSON.parse(responseText);
							if (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts && data.candidates[0].content.parts[0]) {
								replyText = data.candidates[0].content.parts[0].text;
							} else {
								replyText = "Gemini returned an unexpected structure.";
								console.error("Unexpected structure:", data);
							}
						} catch (parseError) {
							console.error("Error parsing Gemini JSON:", parseError);
							replyText = "Error parsing Gemini response.";
						}
					} else {
						replyText = `Gemini API Error: ${geminiResponse.status} - ${responseText}`;
					}

					// --- Step 2: Save Messages to DB ---
					// Verify result is OK before saving to avoid polluting DB with error messages?
					// For now, saving everything as requested.

					// Save User Message
					await env.DB.prepare(
						"INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)"
					).bind(chatId, 'user', userText).run();

					// Save Model Response
					// Only save if we got a real reply, or even if error? User asked to save "AI's response".
					// Let's save the replyText.
					await env.DB.prepare(
						"INSERT INTO messages (chat_id, role, content) VALUES (?, ?, ?)"
					).bind(chatId, 'model', replyText).run();


					const telegramUrl = `https://api.telegram.org/bot${env.TELEGRAM_TOKEN}/sendMessage`;
					await fetch(telegramUrl, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({
							chat_id: chatId,
							text: replyText
						})
					});
				}
			} catch (e) {
				console.error("Error in worker:", e);
			}
		}
		return new Response("OK");
	},
};

```

--- FILE: wrangler.toml ---

```
name = "my-gemini-bot"
main = "src/index.ts"
compatibility_date = "2023-12-01"

[[d1_databases]]
binding = "DB"
database_name = "synapse_db"
database_id = "7eaed018-787b-463b-b1da-164fab56f586"

```