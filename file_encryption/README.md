# File encryption and decryption

## Encrypt
Cryptographically safe salt and iv are generated. A key is derived from the provided password, and the generated key and salt. The file content encryption is done with AES-256 using the key. A temp file is created and then renamed to the original name when the original file is deleted.

## Decrypt
Salt and iv are read from the file. Key is derived from the provided password and salt from file. Data is read from the file and decrypted with the key. A temp file is created and then renamed to the original name when the original file is deleted.

Running:
1. `g++ encrypt.cpp -o encrypt -lssl -lcrypto`
2. `./encrypt`
