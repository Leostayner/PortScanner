import sys
import socket
import time
import argparse
import nmap

def help():
    parser = argparse.ArgumentParser(description='scanner.py - Replicates limited nmap functionality in python')
    parser.add_argument('-ss', '--tcpscan', action  ='store_true', help = 'Enable this for TCP scans')
    parser.add_argument('-su', '--udpscan', action  ='store_true', help = 'Enable this for UDP scans')
    parser.add_argument('-p' , '--ports'  , default ='1-65534'   , help = 'The ports you want to scan')
    parser.add_argument('-t' , '--targets',                        help = 'The target(s) you want to scan')
    
    if len(sys.argv) == 1: 
        parser.print_help() 
        sys.exit(0)
        
    return parser.parse_args()


def pePro(args):
    tcp    = args.tcpscan
    udp    = args.udpscan
    ports  = args.ports

    if("," in ports):
        ports = [int(x) for x in ports.split(",")]

    elif("-" in ports ):
        tmp   = [int(x) for x in ports.split("-")]
        ports = [x for x in range(tmp[0], tmp[1] + 1)]

    targets = args.targets

    return tcp, udp, ports, targets


def tcp_scanner(ip_target, ports):
    time_start = time.time() 

    print("TCP Port Scanner")
    print("Target: {0}".format(ip_target) )
    print("PORT    STATE    SERVICE")
        
    for port in ports:  
        try:
    
            sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('0.0.0.0', 1444))
            sock.settimeout(0.01)
            
            result = sock.connect_ex((ip_target, port))

            if (not result):
                st = str(port) + (5 - len(str(port)) ) * " "
                
                try   : service = socket.getservbyport(port)
                except: service = "Unknown"

                print ("{0}   OPEN     {1}".format(st, service))
                    
        except Exception as err:
            pass
        
        sock.close()
            
    
    print("Scanned in {0:.2f} seconds \n".format(time.time() - time_start))


def udp_scanner(ip_target, ports):
    time_start = time.time() 

    print("TCP Port Scanner From Target: ", ip_target)
    print("PORT    STATE    SERVICE")
        
    for port in ports:  
        try:
            sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', 1444))
            sock.settimeout(0.01)
            
            sock.connect((ip_target, port))
            results = sock.recv(4096)
            print(port)

        except Exception as err:
            pass
        
        sock.close()
            
    
    print("Scanned in {0:.2f} seconds \n".format(time.time() - time_start))



def host_scanner(ports):
    print("Host Scanner")
    nm = nmap.PortScanner()
    nm.scan("192.168.51.0/24")
    print("IP ADDRES" + (" " * 7) + "HOST NAME")
        
    for host in nm.all_hosts():
        try:
            st1 = host + (15 - len(host) ) * " " 
            print(st1, socket.gethostbyaddr(host)[0])
        except Exception as err:
            pass

def host_Portscanner(ports):
    nm = nmap.PortScanner()
    nm.scan("192.168.51.0/24")
    for host in nm.all_hosts():
        tcp_scanner(host, ports)
            

def network_scanner():
    print("Network Scanner")


def main(): 
    args = help()
    tcp, udp, ports, targets =  pePro(args)
    print()

    try:
        if(targets is None):
            
            raise Exception("Error: No targer specifier ")

        if(tcp):
            tcp_scanner(targets, ports)

        elif(udp):
            udp_scanner(targets, ports)


    except Exception as err:
        print(err)


if __name__ == "__main__":
    main()