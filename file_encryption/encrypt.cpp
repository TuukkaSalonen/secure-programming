#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cstdio>

#define SALT_SIZE 16
#define IV_SIZE 16 // Initialization vector size
#define KEY_SIZE 32
#define ITERATIONS 1000

using namespace std;

// Running:
// g++ task4.cpp -o task4 -lssl -lcrypto
// ./task4

// Function to generate random salt with OpenSSL RAND_bytes (https://docs.openssl.org/1.1.1/man3/RAND_bytes/)
bool generateSalt(vector<unsigned char>& salt) {
    return RAND_bytes(salt.data(), SALT_SIZE);
}

// Derives key from password and salt using PBKDF2 with SHA256 (https://docs.openssl.org/3.0/man3/PKCS5_PBKDF2_HMAC/)
bool deriveKey(const string& password, const vector<unsigned char>& salt, vector<unsigned char>& key) {
    return PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), ITERATIONS, EVP_sha256(), KEY_SIZE, key.data());
}

// Encrypt file and overwrite original file
bool encryptFile(const string& inputFile, const string& password) {
    ifstream in(inputFile, ios::binary); // Binary mode
    string tempFile = inputFile + ".enc"; // Temp file
    ofstream out(tempFile, ios::binary); // Binary mode

    if (!in || !out) return false;

    // Generate salt and IV
    vector<unsigned char> salt(SALT_SIZE);
    if (!generateSalt(salt)) return false;
    out.write(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);

    // Random value used to ensure that same plaintext will encrypt to be different
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) return false;
    out.write(reinterpret_cast<const char*>(iv), IV_SIZE);

    // Derive key from given password and generated salt
    vector<unsigned char> key(KEY_SIZE);
    if (!deriveKey(password, salt, key)) return false;

    // Initialize encryption context (https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv);

    vector<unsigned char> buffer(1024);
    vector<unsigned char> cipherBuffer(1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int cipherLen = 0;

    // Encrypt file
    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()); // Read data from file
        int bytesRead = in.gcount();
        if (bytesRead > 0) {
            EVP_EncryptUpdate(ctx, cipherBuffer.data(), &cipherLen, buffer.data(), bytesRead); // Encrypt data
            out.write(reinterpret_cast<const char*>(cipherBuffer.data()), cipherLen); // Write to file
        }
    }

    EVP_EncryptFinal_ex(ctx, cipherBuffer.data(), &cipherLen); // Finalize encryption
    out.write(reinterpret_cast<const char*>(cipherBuffer.data()), cipherLen); // Write to file

    // Free encryption context
    EVP_CIPHER_CTX_free(ctx);

    // Close streams
    out.flush();
    out.close();
    in.close();

    // Remove original file
    if (remove(inputFile.c_str()) != 0) {
        cerr << "Error deleting original file.\n";
        return false;
    }

    // Rename temporary encrypted file to original file
    if (rename(tempFile.c_str(), inputFile.c_str()) != 0) {
        cerr << "Error renaming encrypted file.\n";
        return false;
    }

    return true;
}

// Decrypt file and overwrite original file
bool decryptFile(const string& inputFile, const string& password) {
    ifstream in(inputFile, ios::binary);
    string tempFile = inputFile + ".dec";  // Temp file
    ofstream out(tempFile, ios::binary);

    if (!in || !out) {
        return false;
    }

    // Read salt and IV from file
    vector<unsigned char> salt(SALT_SIZE);
    in.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);

    unsigned char iv[IV_SIZE];
    in.read(reinterpret_cast<char*>(iv), IV_SIZE);

    // Derive key from given password and read salt
    vector<unsigned char> key(KEY_SIZE);
    if (!deriveKey(password, salt, key)){
        return false;
    }

    // Initialize decryption context (https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv);

    vector<unsigned char> buffer(1024);
    vector<unsigned char> plainBuffer(1024 + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int plainLen = 0;

    // Decrypt file
    while (in) {
        in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()); // Read data from file
        int bytesRead = in.gcount();
        if (bytesRead > 0) {
            EVP_DecryptUpdate(ctx, plainBuffer.data(), &plainLen, buffer.data(), bytesRead); // Decrypt data
            out.write(reinterpret_cast<const char*>(plainBuffer.data()), plainLen); // Write to file
        }
    }

    // Finalize decryption
    if (!EVP_DecryptFinal_ex(ctx, plainBuffer.data(), &plainLen)) {
        EVP_CIPHER_CTX_free(ctx); // Free decryption context
        return false;
    }
    out.write(reinterpret_cast<const char*>(plainBuffer.data()), plainLen); // Write to file

    // Free decryption context
    EVP_CIPHER_CTX_free(ctx);

    // Close streams
    out.flush();
    out.close();
    in.close();

    // Remove original file
    if (remove(inputFile.c_str()) != 0) {
        cerr << "Error deleting original file.\n";
        return false;
    }

    // Rename temp file to original file
    if (rename(tempFile.c_str(), inputFile.c_str()) != 0) {
        cerr << "Error renaming decrypted file.\n";
        return false;
    }

    return true;
}

int main() {
    cout << "Choose action (1: Encrypt, 2: Decrypt): ";
    int selection;
    cin >> selection;

    cin.ignore();
    string inputFile, password;

    cout << "Enter file name: ";
    getline(cin, inputFile);
    cout << "Enter password: ";
    getline(cin, password);

    if (selection == 1) {
        if (encryptFile(inputFile, password)) {
            cout << "File encrypted successfully" << endl;
        } else {
            cerr << "Encryption failed\n";
        }
    } else if (selection == 2) {
        if (decryptFile(inputFile, password)) {
            cout << "File decrypted successfully" << endl;
        } else {
            cerr << "Decryption failed" << endl;
        }
    } else {
        cerr << "Invalid choice" << endl;
    }

    return 0;
}
