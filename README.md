# Capstone Project - DoorBell System



## Requirement:

1. python3.5

2. pip

3. pycrypto - a RSA encryption/decryption module in PyPI

The program will automatically check the required modules when it begins to execute. If some modules are missing, the program will prompt user to install it. 



## Usage:

1. To run the server of doorbell system, go to Capstone Project/Server, and use following command:

   <python3 ServerStart.py secret port1,port2,port3…>
    
   Example: python3 ServerStart.py apple 10000,20000,30000,40000

2. The server's public key which is used for RSA encryption is saved in the "Server/Keys/PublicKey.pem"

3. Distribute the PublicKey.pem to the client and the client should put the key in the "Client/Keys/PublicKey.pem"

4. To run the client tool to enable SSH service in server, go to Capstone Project/Client and use following command:
    
   <python3 ClientStart.py serverIP secret port1,port2,port3…>
   
   Example: python3 ClientStart.py 192.168.1.1 apple 10000,20000,30000,40000
