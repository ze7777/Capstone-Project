
import os
import sys
import time
import random
import socket
import platform
import threading


#Check the OS and user privilege
OS=platform.system();

if(OS!="Linux"):
    print("->Please run this program on Linux!");
    sys.exit();
        
if(os.getuid()!=0):
        print("->Please run this program with sudo");
        sys.exit();


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
            print("\n->No pip module, preparing to install pip\n");
            t=threading.Thread(target=os.system,args=("sudo apt-get install python3-pip",));
            t.start();
            t.join();
            
        pip.main(["install","pycrypto"]);
        print("\n->Successfully, please restart the program!");
        sys.exit();
    else:
        print("->Exit!");
        sys.exit();

    


class doorbell():
    
    def __init__(self,secret,portlist):
        
        print("->Initializing...");
        self.SSH_Port=22; 
        self.VerificationTTL=3;
        self.SSH_TTL=60;
        
        
        self.SSH_TurnOn="service ssh start";
        self.SSH_TurnOff="service ssh stop";
        
        
        self.Secret=secret;
        self.IP=os.popen("hostname -I").read().split()[0];
        

        print("->Closing SSH Service...");
        self.DisableSSH();
        

        print("->Generating 1024-bit RSA key...");
        self.ServerRSAKey=RSA.generate(1024);
        self.SaveServerPublicKey();
        

        #Database Entry: addr->[ClientKey,Event,ArrivedPacks]
        self.Database={};
        

        self.PortList=portlist;
        self.SocketList=[];
        
        try:
            for port in self.PortList:
                sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);
                sock.bind((self.IP,port));
                self.SocketList.append(sock);
        except OSError:
            print("ERROR: Address or port is already in use!");
            sys.exit();
        

        return;
    

    #Read a plain text, encrypt the text by RSA key and return encrypted bytes
    def Encription(self, PlainText, PublicKey):
        
        if(type(PlainText)!=bytes):
            PlainText=PlainText.encode();
            
        cipher = PKCS1_OAEP.new(PublicKey);
        CipherText = cipher.encrypt(PlainText);
    
        return CipherText;


    #Read encrypted bytes, decrypt the cipher by RSA key and return a plain text
    def decryption(self, CipherText):
        
        cipher = PKCS1_OAEP.new(self.ServerRSAKey);
        PlainText=cipher.decrypt(CipherText).decode();
        
        return PlainText;


    #Enable SSH service
    def EnableSSH(self):
        print("->Enable SSH service & TTL="+str(self.SSH_TTL)+"s");
        os.system(self.SSH_TurnOn)
        
        return;


    #Disable SSH service
    def DisableSSH(self):
        print("->Close SSH service");
        os.system(self.SSH_TurnOff);
        
        return;
    
    
    #Save the server public key to local disk=/Server/Keys/PublicKey.pem
    def SaveServerPublicKey(self):
        
        f=open(os.getcwd()+"/Keys/PublicKey.pem","wb");
        ServerPublicKey=self.ServerRSAKey.publickey().exportKey();
        f.write(ServerPublicKey);
        f.close();
        
        return;
    

    #Add the packet info to the database, such as arriving port & time
    def AddEntry(self,addr,Port):
        
        if(self.Database.get(addr)==None):
            ClientKey=None;
            Event=None;
            ArrivedPacks={};
            self.Database[addr]=[ClientKey,Event,ArrivedPacks];
        
        
        ArriveTime=time.time();
        ArrivedPacks=self.Database[addr][2];
        ArrivedPacks.update({Port:ArriveTime}); #Port->ArriveTime
        
        return;     
    
    
    #Check the arriving order of Message1s, if out-of-order, return false
    def CheckArrivingOrder(self,addr):
        
        ArrivedPacks=self.Database[addr][2];
        for i in range(len(self.PortList)-2):
            Port1=self.PortList[i];
            ArriveTime1=ArrivedPacks[Port1];
            Port2=self.PortList[i+1];
            ArriveTime2=ArrivedPacks[Port2];
            if(ArriveTime1>ArriveTime2):
                return False;
        
        return True;
    
    
    '''
    The verification function initiated by receiving a Message#1 at port A. 
    In this function, the system uses a one-time hash to verify the identification 
    of the client once more. If client is identified, the doorbell system will enable SSH service.
    '''
    def Verification(self,addr):
        
        #The EVENT will block the function until the server receives the required number of Message1s
        EVENT=self.Database[addr][1];
        
        RecvAllPacks=EVENT.wait(self.VerificationTTL); #This is a Timer
        if(RecvAllPacks==False):
            print("ATTENTION: The Verification process for",addr[0],"is timeout!\n");
            self.Database.pop(addr);
            return;
        
        else:
            #Check the arriving order of Message1s, if out-of-order, exit Verification
            if(self.CheckArrivingOrder(addr)==True):
                
                #Send the Message2(HashValue) to the client at PortList[-2]
                seed=str(random.random()).encode();
                HashValue=SHA256.new(seed).hexdigest();
                ClientKey=self.Database[addr][0];
                Message2=self.Encription(HashValue,ClientKey);
                print("->Sending the Message2(HashValue) to the client:",addr[0]);
                self.SocketList[-2].sendto(Message2,addr);
                
                #Receive the Message3(HashValue) at PortList[-1]
                self.SocketList[-1].settimeout(2);
                while(True):
                    try:
                        (data,addr)=self.SocketList[-1].recvfrom(65535);
                        Message3=self.decryption(data);
                        break;
                    except socket.timeout:
                        print("ATTENTION: Receiving the Message3(HashValue) from",addr[0],"is timeout!\n");
                        self.Database.pop(addr);
                        return;
                    except ValueError:
                        print("ATTENTION: Unable to decrypt the Message3(HashValue) received from",addr[0],"\n");
                        self.Database.pop(addr);
                        return;    
               
                #Check the equality of two HashValues, if correct, enable SSH service
                if(Message3==HashValue):
                    print("->The Message3(HashValue) is received from",addr[0],"at Port:",self.PortList[-1]);
                    
                    #Enable SSH service
                    self.EnableSSH();
                    
                    #Enable a Timer, after TTL, close the SSH service
                    threading.Timer(self.SSH_TTL, self.DisableSSH).start();
                    
                    #Send the SSH_Port and TTL to the client
                    text=str(self.SSH_Port)+"@@@"+str(self.SSH_TTL);
                    Message4=self.Encription(text,ClientKey);
                    print("->Sending the Message4(SSH_Port) to the client:",addr[0],"\n");
                    self.SocketList[-1].sendto(Message4,addr);
                    
                    #Clear the database cache
                    self.Database.pop(addr); 
                else:
                    print("ATTENTION: The incorrect Message3(HashValue) is received from",addr[0],"\n");
                    self.Database.pop(addr);
                    return;
                    
            else:
                print("ATTENTION: Message1s received from",addr[0],"are out-of-order!\n");
                self.Database.pop(addr);
                return;

        return;
    
    #The Monitoring function contains a UDP listening port which is used to receive Message#1s sent from client.
    def Monitering(self,sock):
        
        IncomingPort=sock.getsockname()[1];
        
        while(True):
            (data,addr)=sock.recvfrom(65535);
            try:
                data=data.split(b"@@@");
                secret=self.decryption(data[0])
                key=data[1];
            except IndexError:
                print("ATTENTION: The invalid Message1 is received from",addr[0],"at Port:",IncomingPort);
                continue;
            except ValueError:
                print("ATTENTION: Unable to decrypt the Message1 received from",addr[0],"at Port:",IncomingPort);
                continue;
    
            if(secret==self.Secret):
                print("->The secret is received from",addr[0],"at Port:",IncomingPort);
                self.AddEntry(addr,IncomingPort);
                
                if(IncomingPort==self.PortList[0]):
                    '''
                    If at Port A, save the client key,
                    and initiate Verification process in a new thread.
                    '''
                    ClientKey=RSA.importKey(key);
                    EVENT=threading.Event();
                    
                    self.Database[addr][0]=ClientKey;
                    self.Database[addr][1]=EVENT;
                    
                    print("->Starting the Verification process for",addr[0]);
                    threading.Thread(target=self.Verification,args=(addr,)).start();
                
                else:
                    '''
                    If the packet arrives at other ports, the server checks the
                    number of arrived packets. If the NumOfArrived equals the required
                    number, it will release the EVENT in the Verification();
                    '''
                    ArrivedPacks=self.Database[addr][2];
                    Required=len(self.PortList)-1;
                    
                    if(len(ArrivedPacks)==Required):
                        event=self.Database[addr][1];
                        event.set();
                    
            else:
                print("ATTENTION: The incorrect secret is received from",addr[0],"at Port:",IncomingPort);
                #keep silent
            
        return;
           
        
    
    #Start the DoorBell system
    def SystemStart(self):
        '''
        MultiThreading is used in the server, to concurrently handle requests
        received at port A,B,C,D...
        Port A,B,C,D..n-2 are used for receiving secret,
        Port n-1 is used for sending hash to client,
        Port n is used for receiving the hash from client and sending SSH port to client.
        '''
        print("->DoorBell System is running on",self.IP);
        
        ThreadPool=[];
        
        for i in range(len(self.SocketList)-1):
            t=threading.Thread(target=self.Monitering,args=(self.SocketList[i],));
            ThreadPool.append(t);
            
            
        for i in range(len(ThreadPool)):
            if(i==len(ThreadPool)-1):
                print("->Port#"+str(i+1)+": "+str(self.PortList[i])+" is up.(Use for Sending Hash)");
            else:
                print("->Port#"+str(i+1)+": "+str(self.PortList[i])+" is up.");
            
            ThreadPool[i].setDaemon(True);
            ThreadPool[i].start();
        
        i=len(self.SocketList)-1;
        print("->Port#"+str(i+1)+": "+str(self.PortList[i])+" is up.(Use for Sending SSH Port)\n");
        
        for t in ThreadPool:
            t.join();
        
        return;
    
    
    
