import socket
import multiprocessing
import platform
import threading
import time
import sys
import os


#Check the required RSA library, if not exist, install it by pip from Python Package Index
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
except ImportError:
    print("->\"pycrypto\" need to be installed via pip (Python Package Index), [Y/N]?", end=" ");
    
    UserInput=input().upper();
    if(UserInput=="YES" or UserInput=="Y"):
        try:
            import pip
        except ImportError:
            OS=platform.system();
            if(OS=="Linux"):
                print("\n->No pip module, preparing to install pip");
                t=threading.Thread(target=os.system,args=("sudo apt-get install python3-pip",));
                t.start();
                t.join();
            else:
                print("\n->Please manually install pip and gcc");
                sys.exit();
            
        pip.main(["install","pycrypto"]);
        print("\n->Successfully, please restart the program!");
        sys.exit();
    else:
        print("->Exit!");
        sys.exit();


#Read a string or byte string, return encrypted bytes
def encription(plainText, PublicKey):
        
    if(type(plainText)==str):
        plainText=plainText.encode();
            
    cipher = PKCS1_OAEP.new(PublicKey);
    cipherText = cipher.encrypt(plainText);
    
    return cipherText;
    
    
#Read encrypted bytes, return a string
def decryption(cipherText, ClientRSAKey):
    
    cipher = PKCS1_OAEP.new(ClientRSAKey);
    plainText=cipher.decrypt(cipherText).decode();
    
    return plainText;


def getPublicKey(RSAKey):
    
    return RSAKey.publickey().exportKey();


def getLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    s.connect(("gmail.com",80));
    ip=s.getsockname()[0];
    s.close();
    return ip;


def main():
    
    ServerKeyPath=os.getcwd()+"/Keys/PublicKey.pem";
    #ServerKeyPath=os.path.dirname(os.getcwd())+"/Server/Keys/PublicKey.pem"
    
    
    if(len(sys.argv)!=4):
        print("ERROR: The argument number is not correct!");
        return;
    else:
        ServerIP=sys.argv[1];
        Secret=sys.argv[2];
        PortList=sys.argv[3].split(",");
    
    try:
        for i in range(len(PortList)):
            PortList[i]=int(PortList[i]);
    except ValueError:
        print("ERROR: The port is not correct!");
        print("Example: python3 ClientStart.py 192.168.1.1 secret 10000,20000,30000");
        return;
    
    
    LocalIP=getLocalIP();
    
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);
        sock.bind((LocalIP,25549));
    except OSError:
        print("ERROR: Address or port is already in use!");
        return;
    
    
    print("->Loading the server public key.");
    try:
        f = open(ServerKeyPath,'rb');
    except FileNotFoundError:
        print("ERROR: The public key is not found!");
        return;
  
    ServerPublicKey = RSA.importKey(f.read());
    f.close();
    
    print("->Generating 1024-bit RSA key.");
    ClientRSAKey=RSA.generate(1024);
        
    
    '''
    Message1 Format: Secret@@@ClientPublicKey
    '''
    ClientPublicKey=getPublicKey(ClientRSAKey);
    Message1=encription(Secret,ServerPublicKey)+b"@@@"+ClientPublicKey;
    
    
    #Send the Message1s to the server
    for i in range(len(PortList)-1):
        print("->Sending the Message1 to the server port",PortList[i]);
        sock.sendto(Message1,(ServerIP,PortList[i]));
        time.sleep(0.1);
    
    
    #Receive the HashValue from the server
    (data,addr)=sock.recvfrom(65535);
    print("->The Message2(HashValue) is received from the server");
    HashValue=decryption(data,ClientRSAKey);
    
    
    #Send the Message3(HashValue) to the server
    Message3=encription(HashValue,ServerPublicKey);
    print("->Sending the Message3(HashValue) to the server port",PortList[-1]);
    sock.sendto(Message3,(ServerIP,PortList[-1]));
    
    
    #Receive the SSH_Port and TTL from the server
    (data,addr)=sock.recvfrom(65535);
    data=decryption(data,ClientRSAKey);
    data=data.split("@@@");
    print("SSH port: "+data[0]+", open for "+data[1]+" s.");
    
    
    return;






if __name__ == '__main__':
    
    counter=0;
    while(counter<2):
        p = multiprocessing.Process(target=main);
        p.start();
        p.join(6);
        
        if(p.is_alive()==True):
            p.terminate();
            counter+=1;
            if(counter==2):
                print("ERROR: The program is timeout for 2 times, please check the parameters!");
            else:
                print("\n->Timeout, retrying...\n");  
        else:
            break;
    
    
    
        
    
    
    
        
