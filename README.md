MurDocK
=======

Mutable. Universal. Relay. Document. Kit.  
*_:: MurDock is an extension of the "falo" framework ::_*
 
 
~ MurDock v1.0 beta ~  
Author:   [Themson Mester](https://twitter.com/ThemsonMester)  
Version:  1.0 beta  
Release:  Public  
License:  [MIT](https://github.com/themson/MurDocK/blob/master/LICENSE)  
EULA:  Be Excellent to each other  
Help:  !help  


# Overview:

The purpose of this tool is to provide a protocol independent framework that contains a base set of features that
can piggyback on top of any collaborative web platform or service. The base docClient and docServer are meant to
be extended upon with _Buffer_ classes written for individual web services. These buffer classes can be plugged
into the MurDock framework in order to create a unique shell infrastructure that will always contains a base set of features, as well as the ability to tunnel over any web application traffic for which a buffer class has been constructed. The framework can be extended to operate over lower level protocols if desired.
	

 
# Supported Services:

**Adpative to any collaborative web platform via creation of _"buffer"_ class.**
  
  
  
The base toolkit comes with a set of classes that allow for communication over the Google Spreadsheets service. This _Buffer_ class is a wrapper of the [gspread](https://github.com/burnash/gspread) library by, [Anton Burnashev](https://github.com/burnash).

	
__Notice:__ _This is in no way a vulnerability, exploit or misconfiguration in any Google services or systems, it is
simply a demonstration of the application of this framework. The spreadsheet services was chosen due
to the fact that it is one with which a great number of enterprise users are familiar. This tools does
not in any way seek to disrupt services or perform any action with the intent of introducing to Google products
and services any viruses, worms, defects, Trojan horses, malware or any items of a destructive nature. The 
services is solely utilized to store, manipulate and transport data, as intend. This tool is as a proof of
concept, and may only be used between systems on which all controlling parties have agreed to the transport
and manipulation of data. Users are not authorized to leverage this framework in any means that may fall outside
of the bounds of locally applicable law._


 
# Installation:
### Framework Requirements
- python 2.7.*
- ~~Pycrypto > 2.5~~ (Not needed for current public release)

### "Buffer" Class Requirements
- docBuffer
	- [gspread](https://github.com/burnash/gspread)

_Run as python script or create PE|ELF|DMG using the following_
- [cx_Freeze](http://cx-freeze.sourceforge.net/index.html)
- [pyinstaller](http://www.pyinstaller.org/)
- [py2exe](http://www.py2exe.org/)
  


# Usage:

### Components
1. dockSERVER - run on remote host
2. dockCLIENT - run on local host    
3. Atleast one _"Buffer"_ class (on each host)
 
### Help Menu -
           ~ Murdock 1.0 Public ~
           *** commands ***
          !help     - Print this menu
          !clear    - Clear local terminal              
          !cmd      - Execute local command - Usage : !cmd <command string>
          !sysinfo  - Print System info for remote host
          
          !upload   - Usage : !upload <local_file_path> remote_file_path>
          !download - Usage : !download <remote_file_path> <local_file_path>
          
          !egress   - Find egress ports out of remote network - Interactive
          !meterup  - Upgrade to meterpreter shell - Interactive
          !forward  - Forward local socket to remote socket - Interactive (disabled)
          
          !sync     - Synchronize buffers with remote server  
          !shutdown - Shutdown remote docServer. Does not remove binary (SLOPPY)
          !cleanup  - Shutdown remote docServer and remove binary (BEST)
          !exit     - Exit Local docClient   
          
          <:        - Send command to remote server
 
 
 
## Known Bugs:
    
[See Github Issues Tracker:](https://github.com/themson/MurDocK/issues) _https://github.com/themson/MurDocK/issues_
 
 
## Road Map:

