#!/usr/bin/python
import gspread
import sys
from time import sleep
import logging
from random import randint


# Google Docs Account Credentials
GD_ACCT = '<user>@gmail.com'
GD_PASS = '<Password>'
GD_DOC_NAME = '<spreadsheetname>'
GD_SHEET_NAME = '<sheet/pagename>'

#Debug Logger Handle
# Debug Logging Object and Handle
# Will log to file if exe
DEBUG = False

docLogger = logging.getLogger('__docBUFFER__')
if not DEBUG:
    docLogger.setLevel(logging.ERROR)
else:
    docLogger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
if not DEBUG:
    ch.setLevel(logging.ERROR)
else:
    ch.setLevel(logging.NOTSET)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
docLogger.addHandler(ch)



### PARENT docBUFFER CLASS ### 
# Base for client and server classes
class gdocParentBuffer:
    def __init__(self):
        ## CONSTANTS ##
        self.SERVER_WRITE_COL = 'd'
        self.SERVER_READ_COL  = 'a'
    
        self.CLIENT_WRITE_COL = 'a'
        self.CLIENT_READ_COL  = 'd'
    
        self.BUFFER_RANGE_MIN = 2
        self.BUFFER_RANGE_MAX = 20
    
        self.SERVER_WRITE_INDEX_CORD = 'e2'
        self.CLIENT_WRITE_INDEX_CORD = 'b2'
    
        ## MUTABLE VARS ##
        #CellIndexCords
        self.lastReadCell = self.BUFFER_RANGE_MIN
        self.lastWriteCell = self.BUFFER_RANGE_MIN
        
        #Bad Crypto
        self.aesKey = ''     
        self.hmacKey = ''
        
        ## GSPREAD VARS ##
        #Auth Vars
        self.GD_ACCT = GD_ACCT
        self.GD_PASS = GD_PASS
        self.GD_DOC_NAME = GD_DOC_NAME
        self.GD_SHEET_NAME = GD_SHEET_NAME
        
        #Gdocs SpeadSheet Object
        #Instantiate && return bufferSheet object
        self.bufferSheet = self.init_gs(self.GD_SHEET_NAME)
        
    
    def __del__(self):
    #TODO: use this to clear buffer
        pass    
       
    #Create and return Gspread Buffer object
    def init_gs(self, GD_SHEET_NAME):    #TODO: check why are we passing sheet name and not self. reference?
        """ Sets which WorkSheet to use within a Document
            this feature can be used for sessions or threads """
        #auth to google
        try:
            gc = gspread.login(self.GD_ACCT, self.GD_PASS)
            docLogger.debug('init_gs(): Success Authenticating to Google Acc')        
        except gspread.AuthenticationError:
            raise Exception('init_gs(): could not auth, check creds')
        #open buffer && return handle to object
        try:
            baseDOC = gc.open(self.GD_DOC_NAME) #original
            bufferSheet = baseDOC.worksheet(GD_SHEET_NAME) #added
            return bufferSheet         
        except:
            raise Exception('init_gs(): could not open "%s", check sheet name' % GD_SHEET_NAME)
        
    ### BUFFER INIT ###
    # Null out either chosen buffer
    def buffer_init(self, whichBuffer, BufferData = "<NULL>"):
        """ Valid whichBuffer "client" or "server"
        Valid BufferData "<NULL>" or "!sync" """
        self.lastReadCell = self.BUFFER_RANGE_MIN
        self.lastWriteCell = self.BUFFER_RANGE_MAX       
        if whichBuffer.lower() == "server":
            #Set ClientWriteIndex to beginning of buffer
            self.set_cell(self.CLIENT_WRITE_INDEX_CORD, self.BUFFER_RANGE_MIN)
            #Set to SERVER Buffer Range
            cellMinCord = self.SERVER_WRITE_COL + str(self.BUFFER_RANGE_MIN)
            cellMaxCord = self.SERVER_WRITE_COL + str(self.BUFFER_RANGE_MAX)
        elif whichBuffer.lower() == "client":
            #Set ServerWriteIndex to beginning of buffer
            self.set_cell(self.SERVER_WRITE_INDEX_CORD, self.BUFFER_RANGE_MIN)
            #Set to CLIENT Buffer Range
            cellMinCord = self.CLIENT_WRITE_COL + str(self.BUFFER_RANGE_MIN)
            cellMaxCord = self.CLIENT_WRITE_COL + str(self.BUFFER_RANGE_MAX)
        else:
            raise Exception('VALUE ERROR: invalid var whichBuffer, use: "server" or  "client"')
        #Create the cellList and initialize with BufferData
        if (BufferData == "<NULL>") or (BufferData == "!sync"):
            cell_listC = self.bufferSheet.range(cellMinCord + ':' + cellMaxCord)                            
            for cell in cell_listC:
                cell.value = BufferData
            self.bufferSheet.update_cells(cell_listC)
        else:
            raise Exception('VALUE ERROR - invalid var BufferData, use: "<NULL>" or "!sync"')
    
    # TODO: STILL UNWRITTEN, may not be needed
    # Reauth after a timeout
    def check_auth(self):
        #could just use a timer inside client instead
        #used if someone leave client open for too long
        #Should call init an create a new buffersheet object
        #and assign to self.buffersheet     
        pass
                
    ### INDEX UPDATERS ###
    #update lastReadCell var
    def last_read_update(self, readCell):
        self.lastReadCell = readCell
          
    #lastWriteCell Updater
    #update lastWriteCell var
    def write_update(self, writtenTo):
        self.lastWriteCell = writtenTo
        
    ### Cell GETTERS and SETTERS ###
    #Set cell based by cellCord
    def set_cell(self, cellCord, data):
        try:
            #data = crypt(data, encrypt) encrypt data before posting
            self.bufferSheet.update_acell(cellCord, data)              
        except:
            return 'ERROR: write failed'
    
    #Get data by cellCord as str  
    def get_cell_data(self, cellCord):
        try:
            cellData = self.bufferSheet.acell(cellCord).value
            return cellData
        except:
            return 'ERROR: read failed'
    
    #Return cell toWrite next
    def get_to_write(self):
        if self.lastWriteCell == self.BUFFER_RANGE_MAX:
            return self.BUFFER_RANGE_MIN
        else:
            return self.lastWriteCell + 1
        # Reset lastReadCell, lastWriteCell and indices
        
    ### CRYPTO OR ENCODING ### 
    #Encrypt/Decrypt Inbound & OutBound Data
    def crypt(self, textBlock, direction):
        if direction == "decrypt":
            #base64 decode
            #aes decrypt
            #return clearText as string
            pass
        elif direction == "encrypt":
            #aes encrypt
            #base64 encode
            #return cipherText as  string
            pass
        else:
            docLogger.debug('Invalid call to crypt() ' + "Text: " + textBlock + "  Direction: " + direction)
                   
    #Negotiate AES Key For Session        
    def gen_key(self, cipherText, direction):
        #crypto ignored on !sync string should never be crypted
        #sync reset to base keys
        #request <rekey>
        #gen rsa pair on client
        #encrypt public using base share aes key and send
        #server generate new passphrase 
        #crypt with client pub key
        #return rsa(<newkey>)
        #derive aes and hmac keys from passphrase
        #AES-CBC-HMAC for session
        pass


### DOC CLIENT CLASS ###
class gdocClientBuffer(gdocParentBuffer):
    ### INDEX TRACKERS ###
    #update value of ClientWriteIndex 
    #I.E. set last cell into which client wrote data
    def set_write_index(self, cellWritten):
        self.set_cell(self.CLIENT_WRITE_INDEX_CORD, cellWritten)
          
    #return value of ServerWriteIndex
    #I.E. get last cell into which Server wrote data
    def getServerIndex(self):
        serverIndex = int(self.get_cell_data(self.SERVER_WRITE_INDEX_CORD))
        return serverIndex
    
    #Return cell toRead next
    def get_to_read(self):
        serverWriteIndex = self.getServerIndex()
        if serverWriteIndex == self.lastReadCell:
            return self.lastReadCell    
        elif serverWriteIndex != self.lastReadCell:
            if self.lastReadCell == self.BUFFER_RANGE_MAX:
                return self.BUFFER_RANGE_MIN
            else:
                return self.lastReadCell + 1
    
    ### PRIMARY READ AND SEND METHODS ###
    #post data to client buffer
    def send_data(self, data):
        toWrite = self.get_to_write()
        writeCellCord = self.CLIENT_WRITE_COL + str(toWrite)
        self.set_cell(writeCellCord, data)
        self.write_update(toWrite)
        self.set_write_index(toWrite)

    # Read remote output from sever buffer
    def read_data(self):
        """ Use as primary Read Data Function
            retries relative to buffer length  """
        queryTries = 1 
        serverData = "<NULL>"     
        while (serverData == "<NULL>") or (serverData == "<READ>"):
            toRead = self.get_to_read()
            readCellCord = self.CLIENT_READ_COL + str(toRead)
            serverData = self.get_cell_data(readCellCord)
            if type(serverData) != str:
                self.set_cell(readCellCord, "<READ>")
                self.last_read_update(toRead)
                return "non-string type returned."
            elif ((serverData != "<NULL>") and (serverData != "<READ>")):
                self.set_cell(readCellCord, "<READ>")
                self.last_read_update(toRead)
                return serverData
            else:
                print ". ",
                sys.stdout.flush()
                queryTries = queryTries + 1
                if queryTries >= ( 2 * ( (self.BUFFER_RANGE_MAX + 1) - self.BUFFER_RANGE_MIN ) ):
                    raise Exception('READ ERROR: Connection timed out.')
                sleep(.5)
                                       
    # Read data with no sleep or repeat
    # Used with port forward methods
    def readData_Unsafe(self):
        toRead = self.get_to_read()
        readCellCord = self.CLIENT_READ_COL + str(toRead)
        serverData = self.get_cell_data(readCellCord)
        if ( (serverData != "<NULL>") and (serverData != "<READ>") ):
            self.set_cell(readCellCord, "<READ>")
            self.last_read_update(toRead)
            return serverData
        else:
            return ''

    #synchronize buffers, initiate connection
    #can be used to resync a session 
    # returns Bool
    def sync_up(self):
        try:
            self.buffer_init("server")
            self.buffer_init("client", "!sync")
            serverData = self.read_data()
            if serverData == "<SYNCEDUP>":
                return True
            else:
                return False
        except:
            return False
            
###  DOC SERVER CLASS ###
class gdocServerBuffer(gdocParentBuffer):
    ### INDEX TRACKERS ### 
    #update value of ServerWriteIndex 
    #I.E. set last cell into which client wrote data
    def set_write_index(self, cellWritten):
        self.set_cell(self.SERVER_WRITE_INDEX_CORD, cellWritten)
          
    #return value of ClientWriteIndex
    #I.E. get last cell into which Server wrote data
    def get_client_index(self):
        clientIndex = int(self.get_cell_data(self.CLIENT_WRITE_INDEX_CORD))
        return clientIndex
  
    #Return cell toRead next
    def get_to_read(self):
        clientWriteIndex = self.get_client_index()
        if clientWriteIndex == self.lastReadCell:
            return self.lastReadCell    
        elif clientWriteIndex != self.lastReadCell:
            if self.lastReadCell == self.BUFFER_RANGE_MAX:
                return self.BUFFER_RANGE_MIN
            else:
                return self.lastReadCell + 1
    
    ### PRIMARY READ AND SEND METHODS ###    
    #post data to client buffer
    def send_data(self, data):
        toWrite = self.get_to_write()
        writeCellCord = self.SERVER_WRITE_COL + str(toWrite)
        self.set_cell(writeCellCord, data)
        self.write_update(toWrite)
        self.set_write_index(toWrite)
                
    # Read remote output from sever buffer
    def read_data(self):
        """ Use as primary Read Data Function
            retries relative to buffer length  """
        queryTries = 1     
        clientData = "<NULL>"         
        while (clientData == "<NULL>") or (clientData == "<READ>"):
            toRead = self.get_to_read()        
            readCellCord = self.SERVER_READ_COL + str(toRead)
            clientData = self.get_cell_data(readCellCord)
            if (clientData != "<NULL>") and (clientData != "<READ>"):
                self.set_cell(readCellCord, "<READ>")
                self.last_read_update(toRead)
                return clientData
            else:
                queryTries = queryTries + 1
                if queryTries >= ( 2 * ( (self.BUFFER_RANGE_MAX + 1) - self.BUFFER_RANGE_MIN ) ):
                    return "ERROR: read timed out."
                sleep(.5)                                               
                     
    #Reinitialize Buffer on !sync command
    def sync_up(self): 
        self.buffer_init("client")
        return "<SYNCEDUP>"
