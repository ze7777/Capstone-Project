
import sys
import signal
import DoorBellSystem


def sigint_handler(signum, frame):
    print("->Exit");
    sys.exit();
        

def main():
    
    signal.signal(signal.SIGINT, sigint_handler);
    
    if(len(sys.argv)!=3):
        print("ERROR: The argument number is not correct!");
        print("Example: python3 ServerStart.py secret 10000,20000,30000");
        return;
    else:
        secret=sys.argv[1];
        PortList=sys.argv[2].split(",");
    
    try:
        for i in range(len(PortList)):
            PortList[i]=int(PortList[i]);
    except ValueError:
        print("ERROR: The port is not correct!");
        return;
    
        
    MyDoorBell=DoorBellSystem.doorbell(secret,PortList);
    MyDoorBell.SystemStart();
    
    return;

  

    


if __name__=="__main__":

    main();
    
