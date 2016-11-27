# Capstone Project - DoorBell System

Requirement:

python3.5

pip

pycrypto - a RSA encryption/decryption module

Usage:
1. To run the server of DoorBell system, go to Capstone Project/Server, and use following command:
    
   python3 ServerStart.py secret port1,port2,por3…
    
   Example: python3 ServerStart.py apple 10000,20000,30000,40000

2. The server public key which is used for RSA encryption is saved in Server/Keys/PublicKey.pem

3. Distribute the PublicKey.pem to the client who wants to enable SSH service of the server, and 
   the put the key in Client/Keys/PublicKey.pem

4. To run the client tool, go to Capstone Project/Client and use following command:
    
   python3 ClientStart.py serverIP secret port1,port2,por3…
   
   Example: python3 ClientStart.py 192.168.1.1 apple 10000,20000,30000,40000
