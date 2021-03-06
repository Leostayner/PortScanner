import sys
import time
import nmap

def menu():
    st = ("\nFunctions:\n"  
          "(0) : Host TCP Port Scanner\n"
          "(1) : Host UDP Port Scanner\n"
          "(2) : Network - List Hosts \n"    
          "(3) : Network - Hosts Port Scanner\n"    
          "(4) : Exit \n"
          "\nSelect a Function: ")    
    try:
        value = int(input(st))
    
    except :
        raise Exception("Error: Invalud Function")
    
    print()
    return value


def _exit():
    sys.exit()


def pePro(ports_str):
    try:
        if("," in ports_str):
            ports_str = ports_str.replace(" ", "")
            ports_list = [int(x) for x in ports_str.split(",")]
        
        elif(" " in ports_str):
            ports_str = ports_str.replace(" ", ",")
            ports_list = [int(x) for x in ports_str.split(",")]
        
        elif("-" in ports_str ):
            tmp   = [int(x) for x in ports_str.split("-")]
            ports_list = [x for x in range(tmp[0], tmp[1] + 1)]
        
        elif(ports_str.isdigit()):
            ports_list = [int(ports_str)]

        elif(ports_str == ""):
            ports_str = "1-65534"
            ports_list = [x for x in range (1, 65534)]

        else:
            raise Exception("Error: Invalid input format\n"
                            "Ex. input: 80, 81 or 80 81 or 1-100")

    except Exception as err:
        raise Exception("Error: Invalid input format\n"
                        "Ex. input: 80, 81 or 80 81 or 1-100")

    return ports_str, ports_list


def tcp_scanner(target, ports_str, ports_list):
    time_start = time.time() 
    nm = nmap.PortScanner()
    
    print("TCP Port Scanner")
    
    nm.scan(target, ports_str)
    
    for target in nm.all_hosts():
        print("Target: {0}".format(target) )
        print("PORT    STATE    SERVICE")

        for port in ports_list:
            try:
                lport = nm[target]['tcp'][port]
                st1 = str(port) + (7 - len( str(port) ) ) * " "
                st2 = lport["state"] + (8 - len(lport["state"]) ) * " "
                st3 = lport["name"]

                print(st1, st2, st3)
                            
            except Exception as err:
                pass
        
        print("\nScanned in {0:.2f} seconds \n".format(time.time() - time_start))


def udp_scanner(target, ports_str, ports_list):
    time_start = time.time() 
    nm = nmap.PortScanner()
    
    print("UDP Port Scanner")
    
    nm.scan(target, ports_str)
    
    for target in nm.all_hosts():
        print("Target: {0}".format(target) )
        print("PORT    STATE    SERVICE")

        for port in ports_list:
            try:
                lport = nm[target]['udp'][port]
                st1 = str(port) + (7 - len( str(port) ) ) * " "
                st2 = lport["state"] + (8 - len(lport["state"]) ) * " "
                st3 = lport["name"]

                print(st1, st2, st3)
                            
            except Exception as err:
                pass
        
        print("\nScanned in {0:.2f} seconds \n".format(time.time() - time_start))


def network_scanner():
    print("Network Scanner")
    
    nm = nmap.PortScanner()
    nm.scan(input("Network IP: "))
    print()
    
    print("IP ADDRES" + (" " * 7) + "HOST NAME")
     
    time_start = time.time() 
   
    for host in nm.all_hosts():
        try:
            st1  = host + (15 - len(host) ) * " " 
            name = nm[host].hostname()

            if (len(name) == 0):
                name = "Unknow"

            print(st1, name)
        
        except Exception as err:
            print(err)
    
    print("\nScanned in {0:.2f} seconds \n".format(time.time() - time_start))
        

def network_Portscanner():
    print("Network Port Scanner")
    nm = nmap.PortScanner()
    nm.scan(input("Network IP: "))

    ports  = input("Port(s) (default: 1-65534): ")
    ports_str, ports_list  = pePro(ports)
    print()
    

    for host in nm.all_hosts():
        tcp_scanner(host, ports_str, ports_list)
            

def main(): 
    while True:
        list_functions     = [network_scanner, network_Portscanner, _exit]
        list_functions_2ag = [tcp_scanner, udp_scanner]
        
        try:
            value = menu()
            
            if value in range(2):
                target = input("Target IP or Host Name: ")
                ports  = input("Port(s) (default: 1-65534): ")
                print()

                ports_str, ports_list = pePro(ports)

                list_functions_2ag[value](target, ports_str, ports_list)
            
            if value in range(2, 6):
                list_functions[value - 2]()

        except Exception as err:
            print(err)

if __name__ == "__main__":
    main()