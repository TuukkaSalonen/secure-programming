# Authentication
## Register
Cryptographically safe salt is generated and password is hashed with it. Username, salt, and hashed password are saved in file.
## Login
Provided username is checked, and if found provided password is hashed with the corresponding salt in file. If the provided hash password is the same as the one in the file, authentication is successful.

Running:
1. `g++ authenticate.cpp -o authenticate -lssl -lcrypto`
2. `./authenticate`
