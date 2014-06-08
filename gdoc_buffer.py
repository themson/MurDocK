#!/usr/bin/python
import gspread
import sys
from time import sleep
import logging
from random import randint

# Google Drive Account Credentials
GD_ACCT = '<user>@gmail.com'
GD_PASS = '<Password>'
GD_DOC_NAME = '<spreadsheetname>'
GD_SHEET_NAME = '<sheet/pagename>'
Google Docs Account Credentials

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


class gdocParentBuffer:
    """PARENT gdocBUFFER CLASS"""
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
       
    def init_gs(self, GD_SHEET_NAME): # TODO: check why are we passing sheet name and not self. reference?
        """Create and return Gspread Buffer object
        
        Sets which WorkSheet to use within a Document
        this feature can be used for sessions or threads
        """
        try: # Auth to google
            gc = gspread.login(self.GD_ACCT, self.GD_PASS)
            docLogger.debug('init_gs(): Success Authenticating to Google Acc')        
        except gspread.AuthenticationError:
            raise Exception('init_gs(): could not auth, check creds')
        try: # Open buffer && return object handle
            baseDOC = gc.open(self.GD_DOC_NAME) #original
            bufferSheet = baseDOC.worksheet(GD_SHEET_NAME) #added
            return bufferSheet         
        except:
            raise Exception('init_gs(): could not open "%s", check sheet name' % GD_SHEET_NAME)

    def buffer_init(self, whichBuffer, BufferData = "<NULL>"):
        """Null out chosen buffer
        
        Valid whichBuffer "client" or "server"
        Valid BufferData "<NULL>" or "!sync" 
        """
        self.lastReadCell = self.BUFFER_RANGE_MIN
        self.lastWriteCell = self.BUFFER_RANGE_MAX       
        if whichBuffer.lower() == "server":
            self.set_cell(self.CLIENT_WRITE_INDEX_CORD, self.BUFFER_RANGE_MIN) # Set ClientWriteIndex to beginning of buffer
            cellMinCord = self.SERVER_WRITE_COL + str(self.BUFFER_RANGE_MIN) # Set to SERVER Buffer Range
            cellMaxCord = self.SERVER_WRITE_COL + str(self.BUFFER_RANGE_MAX)
        elif whichBuffer.lower() == "client":
            self.set_cell(self.SERVER_WRITE_INDEX_CORD, self.BUFFER_RANGE_MIN) # Set ServerWriteIndex to beginning of buffer
            cellMinCord = self.CLIENT_WRITE_COL + str(self.BUFFER_RANGE_MIN) # Set to CLIENT Buffer Range
            cellMaxCord = self.CLIENT_WRITE_COL + str(self.BUFFER_RANGE_MAX)
        else:
            raise Exception('VALUE ERROR: invalid var whichBuffer, use: "server" or  "client"')
        
        if (BufferData == "<NULL>") or (BufferData == "!sync"): # Create cellList and initialize with BufferData
            cell_listC = self.bufferSheet.range(cellMinCord + ':' + cellMaxCord)                            
            for cell in cell_listC:
                cell.value = BufferData
            self.bufferSheet.update_cells(cell_listC)
        else:
            raise Exception('VALUE ERROR - invalid var BufferData, use: "<NULL>" or "!sync"')
    
    def check_auth(self): # TODO: STILL UNWRITTEN, may not be needed
        """Reauth after a timeout
        
        used if someone leaves client open for too long
        Should call init to create new buffersheet object,
        and assign to self.buffersheet.
        could use a timer inside client instead
        """   
        pass
                
    ### INDEX UPDATERS ###
    def last_read_update(self, readCell):
        """Update lastReadCell var."""
        self.lastReadCell = readCell
    
    def write_update(self, writtenTo):
        """update lastWriteCell var"""
        self.lastWriteCell = writtenTo
        
    ### Cell GETTERS and SETTERS ###
    def set_cell(self, cellCord, data):
        """Set cell based by cellCord"""
        try:
            #data = crypt(data, encrypt) encrypt data before posting
            self.bufferSheet.update_acell(cellCord, data)              
        except:
            return 'ERROR: write failed'
         
    def get_cell_data(self, cellCord):
        """Get data by cellCord as str"""
        try:
            cellData = self.bufferSheet.acell(cellCord).value
            return cellData
        except:
            return 'ERROR: read failed'
    
    def get_to_write(self):
        """Return cell toWrite next"""
        if self.lastWriteCell == self.BUFFER_RANGE_MAX:
            return self.BUFFER_RANGE_MIN
        else:
            return self.lastWriteCell + 1
        # Reset lastReadCell, lastWriteCell and indices <-- what is this, can remove?
        
    ### CRYPTO ###
    def crypt(self, textBlock, direction):
        """Encrypt/Decrypt Inbound & OutBound Data"""
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
       
    def gen_key(self, cipherText, direction):
        """Negotiate AES Key For Session"""
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


class gdocClientBuffer(gdocParentBuffer):
    
    ### INDEX TRACKERS ###
    def set_write_index(self, cellWritten):
        """"Update last cell into which client wrote data."""
        self.set_cell(self.CLIENT_WRITE_INDEX_CORD, cellWritten)

    def getServerIndex(self):
        """Return last cell into which Server wrote data."""
        serverIndex = int(self.get_cell_data(self.SERVER_WRITE_INDEX_CORD))
        return serverIndex
    
    def get_to_read(self):
        """Return cell to read next."""
        serverWriteIndex = self.getServerIndex()
        if serverWriteIndex == self.lastReadCell:
            return self.lastReadCell    
        elif serverWriteIndex != self.lastReadCell:
            if self.lastReadCell == self.BUFFER_RANGE_MAX:
                return self.BUFFER_RANGE_MIN
            else:
                return self.lastReadCell + 1
    
    ### PRIMARY READ AND SEND METHODS ###
    def send_data(self, data):
        """ Post data to client buffer."""
        toWrite = self.get_to_write()
        writeCellCord = self.CLIENT_WRITE_COL + str(toWrite)
        self.set_cell(writeCellCord, data)
        self.write_update(toWrite)
        self.set_write_index(toWrite)

    def read_data(self):
        """Read remote output from sever buffer
        
        Use as primary read, retries relative to buffer length  
        """
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
                                       
    def readData_Unsafe(self):
        """Read data with no sleep or repeat. Used in port forwarding"""
        toRead = self.get_to_read()
        readCellCord = self.CLIENT_READ_COL + str(toRead)
        serverData = self.get_cell_data(readCellCord)
        if ( (serverData != "<NULL>") and (serverData != "<READ>") ):
            self.set_cell(readCellCord, "<READ>")
            self.last_read_update(toRead)
            return serverData
        else:
            return ''

    def sync_up(self):
        """Returns sync success Bool
        
        initiate connection
        synchronize buffers, 
        can be used to resync a session
        """
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
            

class gdocServerBuffer(gdocParentBuffer):
    ### INDEX TRACKERS ### 
    def set_write_index(self, cellWritten):
        """Set last cell into which client wrote data."""
        self.set_cell(self.SERVER_WRITE_INDEX_CORD, cellWritten)

    def get_client_index(self):
        """Get last cell into which Server wrote data."""
        clientIndex = int(self.get_cell_data(self.CLIENT_WRITE_INDEX_CORD))
        return clientIndex

    def get_to_read(self):
        """Return cell to read next."""
        clientWriteIndex = self.get_client_index()
        if clientWriteIndex == self.lastReadCell:
            return self.lastReadCell    
        elif clientWriteIndex != self.lastReadCell:
            if self.lastReadCell == self.BUFFER_RANGE_MAX:
                return self.BUFFER_RANGE_MIN
            else:
                return self.lastReadCell + 1
    
    ### PRIMARY READ AND SEND METHODS ###    
    def send_data(self, data):
        """Post data to client buffer."""
        toWrite = self.get_to_write()
        writeCellCord = self.SERVER_WRITE_COL + str(toWrite)
        self.set_cell(writeCellCord, data)
        self.write_update(toWrite)
        self.set_write_index(toWrite)

    def read_data(self):
        """Read remote output from sever buffer
        
        Use as primary Read Data Function
        Retries relative to buffer length 
        """
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

    def sync_up(self):
        """Reinitialize Buffer on !sync command"""
        self.buffer_init("client")
        return "<SYNCEDUP>"
