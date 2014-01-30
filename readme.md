iocOut
=====

Takes a .txt input file of indicators and outputs an IOC file which can then be edited with Mandiant's IOC Editor.

Usage
-----
    python iocOut.py [OPTIONS]

    OPTION LIST:

	parser.add_option('-f', dest='indicatorFile', type='string', help='indicators to create new IOC file')
	parser.add_option('-o', dest='outputFileName', type='string', default=None, help='name of the output file')
	
	-f    File with indicators to use to generate an IOC file. Currently only .txt files are supported.
    -o    Optional option to name the output file. If not used, the file will be output as <input filename>.ioc.


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
1/30/14: Added support for MD5 indicators.