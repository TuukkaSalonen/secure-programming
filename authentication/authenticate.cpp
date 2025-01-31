#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <fstream>

// Define constants
#define SALT_SIZE 16
#define HASH_SIZE 32
#define ITERATIONS 1000
#define FILE_NAME "users.txt"

using namespace std;

// Running:
// g++ task3.cpp -o task3 -lssl -lcrypto
// ./task3

// Function to generate random salt with OpenSSL RAND_bytes (https://docs.openssl.org/1.1.1/man3/RAND_bytes/)
bool generateRandomSalt(vector<unsigned char>& salt) {
    return RAND_bytes(salt.data(), SALT_SIZE); // 1 if successful 0 if error
}

// Derivation function to hash a password using PBKDF2 with SHA256 (https://docs.openssl.org/3.0/man3/PKCS5_PBKDF2_HMAC/)
bool hashPassword(const string& password, const vector<unsigned char>& salt, vector<unsigned char>& hash) {
    return PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), ITERATIONS, EVP_sha256(), HASH_SIZE, hash.data()) != 0;
} // 1 if successful 0 if error

// Function to convert binary to a hex string just for readability
string toHexString(const unsigned char* data, size_t length) {
    stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        // Convert each byte to a 2-digit hex string with leading 0 padding
        ss << setw(2) << setfill('0') << hex << static_cast<int>(data[i]);
    }
    return ss.str();
}

// Function to check if the username already exists
bool isUsernameTaken(const string& username) {
    ifstream inFile(FILE_NAME);
    if (!inFile) {
        return false;  // File doesn't exist, so no existing users
    }

    string storedUsername;
    string storedSaltHex;
    string storedHashHex;
    string line;

    while (getline(inFile, line)) {
        istringstream iss(line);
        if (getline(iss, storedUsername, ':') &&
            getline(iss, storedSaltHex, ':') &&
            getline(iss, storedHashHex)) {

            if (storedUsername == username) {
                return true;  // Username already exists
            }
        }
    }
    return false;  // Username not found
}

// Function to register a new user
void registerUser(const string& username, const string& password) {
    // Check if username is already taken
    if (isUsernameTaken(username)) {
        cerr << "Error: Username already taken" << endl;
        return;
    }

    // Generate random salt
    vector<unsigned char> salt(SALT_SIZE);
    if (!generateRandomSalt(salt)) {
        cerr << "Error generating random salt" << endl;
        exit(EXIT_FAILURE);
    }

    // Hash password with salt
    vector<unsigned char> hash(HASH_SIZE);
    if (!hashPassword(password, salt, hash)) {
        cerr << "Error hashing password" << endl;
        exit(EXIT_FAILURE);
    }

    // Convert salt and hash to hex strings for readability (in this example)
    string saltHex = toHexString(salt.data(), salt.size());
    string hashHex = toHexString(hash.data(), hash.size());

    // Write username, salt, and hash to file
    ofstream outFile(FILE_NAME, ios::app); // Append
    if (!outFile) {
        cerr << "Failed to open file" << endl;
        exit(EXIT_FAILURE);
    }

    outFile << username << ":" << saltHex << ":" << hashHex << endl;
    outFile.close();

    cout << "User registered successfully" << endl;
}

// Function to authenticate a user
bool authenticateUser(const string& username, const string& password) {
    ifstream inFile(FILE_NAME);
    if (!inFile) {
        cerr << "No user file (register first)" << endl;
        exit(EXIT_FAILURE);
    }

    string storedUsername;
    string storedSaltHex;
    string storedHashHex;
    string line;

    while (getline(inFile, line)) {
        istringstream iss(line);
        if (getline(iss, storedUsername, ':') &&
            getline(iss, storedSaltHex, ':') &&
            getline(iss, storedHashHex)) {

            if (storedUsername == username) {
                // Convert stored hex salt and hash back to binary
                vector<unsigned char> storedSalt(SALT_SIZE);
                vector<unsigned char> storedHash(HASH_SIZE);
                
                // Take 2-character substring from hex, convert to integer and store it in the salt and hash
                for (size_t i = 0; i < SALT_SIZE; ++i) {
                    storedSalt[i] = stoi(storedSaltHex.substr(i * 2, 2), nullptr, 16);
                }

                for (size_t i = 0; i < HASH_SIZE; ++i) {
                    storedHash[i] = stoi(storedHashHex.substr(i * 2, 2), nullptr, 16);
                }

                // Hash given password with salt
                vector<unsigned char> computedHash(HASH_SIZE);
                if (!hashPassword(password, storedSalt, computedHash)) {
                    cerr << "Error hashing password" << endl;
                    exit(EXIT_FAILURE);
                }

                // Compare the stored hash with the new hash
                return computedHash == storedHash;
            }
        }
    }

    return false; // User not found
}

int main() {
    int selection;
    string username, password;

    cout << "***********************\n";
    cout << "* User Authentication *\n";
    cout << "***********************\n";

    cout << "1 to register\n2 to log in\nEnter your choice: ";
    cin >> selection;

    cin.ignore();  // Clear the newline
    
    cout << "Enter username: ";
    getline(cin, username);
    cout << "Enter password: ";
    getline(cin, password);

    if (selection == 1) {
        registerUser(username, password);
    } else if (selection == 2) {
        if (authenticateUser(username, password)) {
            cout << "Authentication successful" << endl;
        } else {
            cout << "Invalid credentials" << endl;
        }
    } else {
        cerr << "Invalid choice" << endl;
    }

    return 0;
}
