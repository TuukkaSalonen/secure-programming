#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>

// Running:
// g++ task2.cpp -o task2 -lssl -lcrypto
// ./task2 text or ./task2 binary

using namespace std;

// Function to convert binary data to hexadecimal string
string toHexString(const unsigned char* data, size_t length) {
    stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        // Convert each byte to a 2-digit hex string with leading 0 padding
        ss << setw(2) << setfill('0') << hex << static_cast<int>(data[i]);
    }
    return ss.str();
}

int main(int argc, char* argv[]) {
    const int DATA_SIZE = 256;
    unsigned char data[DATA_SIZE];
    bool text;
    
    if (argc > 1) {
        string arg = argv[1];
        if (arg == "binary") {
            text = false;
        } else if (arg == "text") {
            text = true;
        } else {
            cerr << "Invalid argument. Use 'text' or 'binary'." << endl;
            return 1;
        }
    }

    // Generate a random data with OpenSSL RAND_bytes (https://docs.openssl.org/1.1.1/man3/RAND_bytes/)
    if (RAND_bytes(data, DATA_SIZE) != 1) { // 1 if successful 0 if error
        cerr << "Error generating random data using OpenSSL" << endl;
        return 1;
    }

    // If text format convert random data to hex string
    if (text) {
        string hexString = toHexString(data, DATA_SIZE);

        // Write to a file
        ofstream outfile("random_data.txt");
        if (!outfile) {
            cerr << "Error opening file for writing" << endl;
            return 1;
        }
        outfile << hexString;
        outfile.close();

        cout << "Data written to random_data.txt" << endl;
    } else {
        // Write to a file
        ofstream outfile("random_data.bin", ios::binary);
        if (!outfile) {
            cerr << "Error opening file for writing" << endl;
            return 1;
        }
        outfile.write(reinterpret_cast<char*>(data), DATA_SIZE);
        outfile.close();

        cout << "Data written to random_data.bin" << endl;
    }

    return 0;
}
