iocOut
=====

Takes a .txt input file of indicators and outputs an IOC file which can then be edited with Mandiant's IOC Editor.

Usage
-----
    python iocOut.py [-h] [-f INPUT] [-o OUTPUT] [-n "name"] [-a "author"] [-d "description"]

    Mandatory Arguments:
		-f,    		File with indicators to use to generate an IOC file. Currently only .txt files are supported.
    
	Optional Arguments:
		-h, --help	show this message and exit
		-o,    		Name of the output file. If not used, the file will be output as <input filename>.ioc.
		-n, 		Populate the "Name" field in IOC Editor. String must be wrapped in quotes.
		-a,			Populate the "Author" field in IOC Editor. String must be wrapped in quotes.
		-d, 		Populate the "Description" field in IOC Editor. String must be wrapped in quotes.

Requirements
------------
	Tested with Python 2.7

Known issues
------------
	Currently supports IPs, MD5s and domains. Assumes all non-IP/MD5 indicators are domains.

Todo
------------
	Add CSV support
	Add ability to nest items from csv
	If csv, support logical operators
	Add detection/support for multiple ioc types
	
Change Log
------------
2/12/14: Added optional arguments to populate name, author and description fields.
1/30/14: Added support for MD5 indicators.