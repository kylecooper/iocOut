'''
Takes a .txt input file of indicators and outputs an IOC file.
Todo: Add CSV support
	  Add ability to nest items from csv
	  If csv, support logical operators
	  Add detection/support for multiple ioc types
Known issues: Assumes all non-ips are domains
'''
import optparse
import datetime
import time
import sys
import os
import re
    
def turnToIOC(iFile, oFile):
	#create file to write
	print "[+]Writing indicators from " + iFile + " to " + oFile
	
	#we have to fill the last-modified and authored_date fields or the ioc will not load
	#get the current time and modify it to the expected format
	longDate = str(datetime.datetime.now())
	splitDate = longDate.split(' ')
	HMS = splitDate[1].split('.')
	formattedDate = splitDate[0] + "T" + HMS[0]
	
	#create file to write, open file to read indicators
	output = open(oFile, 'w')
	indicators = open(iFile, 'r')
	
	#write the xml header
	output.write("<?xml version=\"1.0\" encoding=\"us-ascii\"?>\n")
	output.write("<ioc xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" id=\"\" last-modified=\"")
	output.write(formattedDate + "\" xmlns=\"http://schemas.mandiant.com/2010/ioc\">\n")
	output.write("  <short_description></short_description>\n")
	output.write("  <authored_date>" + formattedDate + "</authored_date>\n")
	output.write("  <links />\n")
	output.write("  <definition>\n")
	output.write( "    <Indicator operator=\"OR\" id=\"\">\n")
	
	#regex to check if indicators are IP addresses
	testIfIP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
	#iterate through indicators
	for indicator in indicators.readlines():
		indicator = indicator.strip('\n')
		#logic to determine type of indicator (IP or domain currently)
		isIP = testIfIP.match(indicator)
		if isIP:
			#write the IP to file using the IP type
			output.write("      <IndicatorItem id=\"\" condition=\"is\">\n")
			output.write("        <Context document=\"PortItem\" search=\"PortItem/remoteIP\" type=\"mir\" />\n")
			output.write("        <Content type=\"IP\">" + indicator + "</Content>\n")
			output.write("      </IndicatorItem>\n")
		else: #assumes domain if not IP, supporting more ioc types is on the todo
			#write the domain to the file using the domain type
			output.write("      <IndicatorItem id=\"\" condition=\"is\">\n")
			output.write("        <Context document=\"Network\" search=\"Network/DNS\" type=\"mir\" />\n")
			output.write("        <Content type=\"string\">" + indicator + "</Content>\n")
			output.write("      </IndicatorItem>\n")
	
	#write the xml footer
	output.write("    </Indicator>\n")
	output.write("  </definition>\n")
	output.write("</ioc>")
	#close files
	indicators.close()
	output.close()
	exit(0)

def main():
	parser = optparse.OptionParser("usage: python iocOut.py -f <input file> -o <optional output name>")
	parser.add_option('-f', dest='indicatorFile', type='string', help='indicators to create new IOC file')
	parser.add_option('-o', dest='outputFileName', type='string', default=None, help='name of the output file')
	(options, args) = parser.parse_args()
	
	indicatorFile = options.indicatorFile
	outputFileName = options.outputFileName
	
	#make sure the input file exists
	if ((os.path.isfile(options.indicatorFile)) == False):
		print "[*]Input file doesn't exist"
		exit(0)
	#check to see if outFileName was included
	#if not, set outFileName to (indicatorFile) + .ioc
	elif outputFileName == None:
		outputFileName = os.path.splitext(indicatorFile)[0] + '.ioc'
	else:
		pass
	#exit if the output file already exists
	if ((os.path.isfile(outputFileName)) == True):
		print "[*]Output file already exists"
		exit(0)
	else:
		pass

	turnToIOC(indicatorFile, outputFileName)

if __name__ == '__main__':
	main()