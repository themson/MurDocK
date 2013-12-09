MurDocK
=======

Mutable. Universal. Relay. Document. Kit.

:: MurDock is an extension of the "falo" framework ::
 
 	~ MurDock v1.0 beta ~
 	Author:   Themson Mester
 	Version:  1.0 beta
 	Release:  Public
 	License:  MIT
 	EULA:  Be Excellent to each other
 	Help:  !help
 	

Overview:

	The purpose of this tool is to provide a protocol independent C&C tool that contains a base set of features and
	can piggyback on top of any collaborative web platform or service. The base docClient and docServer are meant to
	be extended upon with BUFFER classes written for individual web services. These buffer classes can be plugged
	into the docDoor tool in order to create a unique C&C infrastructure that will always contains a base set of features,
	as well as the ability to tunnel over any web application traffic for which a buffer class has been constructed. 
	The framework can be extended to operate over lower level protocols if desired.
	

 
Supported Services:

	Adpative to any common collaborative web platform via creation of "buffer" class.
	
	
	The base toolkit comes with a set of classes (buffer parent, inherited client and server) that allow for        
	communication over the Google Spreadsheets service.
	
	Note: This is in no way a vulnerability, exploit or misconfiguration in any Google services or systems, it is
	simply a demonstration of the application of this framework. The spreadsheet services was chosen due
	to the fact that it is one with which a great number of enterprise users are familiar. This tools does
	not in any way seek to disrupt services or perform any action with the intent of introducing to Google products
	and services any viruses, worms, defects, Trojan horses, malware or any items of a destructive nature. The 
	services is solely utilized to store, manipulate and transport data, as intend. This tool is as a proof of
	concept, and may only be used between systems on which all controlling parties have agreed to the transport
	and manipulation of data. Users are not authorized to leverage this framework in any mean that may fall outside
	of the bounds of locally applicable law.

 
Installation:

 
 
Usage:
 
	Components -
 	       dockSERVER runs on infected host
 	       dockCLIENT runs on controlling host
 	
 	Usage -
           ~ Murdock 1.0 Public ~
           *** commands ***
          !help     - Print this menu
          !clear    - Clear local terminal              
          !cmd      - Execute local command - Usage : !cmd <command string>
          !sysinfo  - Print System info for remote host
          
          !upload   - Push file to remote host - Usage : !upload <local_file_path> remote_file_path>
          !download - Pull file from remote host - Usage : !download <remote_file_path> <local_file_path>
          
          !egress   - Find egress ports out of remote network - Interactive
          !meterup  - Upgrade to meterpreter shell - Interactive
          !forward  - Forward local socket to remote socket - Interactive (DISABLED IN PUBLIC RELEASE)
          
          !sync     - Synchronize buffers with remote server  
          !shutdown - Shutdown remote docServer. Does not remove binary (SLOPPY)
          !cleanup  - Shutdown remote docServer and remove binary (BEST)
          !exit     - Exit Local docClient   
          
          <:        - Send command to remote server
 
 
 
Known Bugs:
    
	Time out on none returning subprocess communicate calls 
		-being addressed with timer
	
	Execesive overhead in creation of initializaion buffer object 
		-to be addressed
 
 
Road Map:

