# See project page @ https://github.com/kylecooper/iocOut for updates, todo, known issues, etc.
import optparse
import datetime
import time
import sys
import os
import re
    
def turnToIOC(iFile, oFile, name, author, desc):
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
	output.write("  <short_description>")
	if name == None:
		pass
	else:
		output.write(name)
	output.write("</short_description>\n")
	output.write("  <description>")
	if desc == None:
		pass
	else:
		output.write(desc)
	output.write("</description>\n")
	output.write("  <authored_by>")
	if author == None:
		pass
	else:
		output.write(author)
	output.write("</authored_by>\n")
	output.write("  <authored_date>" + formattedDate + "</authored_date>\n")
	output.write("  <links />\n")
	output.write("  <definition>\n")
	output.write( "    <Indicator operator=\"OR\" id=\"\">\n")
	
	#regex to check if indicators are IP addresses
	testIfIP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
	testIfMD5 = re.compile(r"([a-fA-F\d]{32})")
	#iterate through indicators
	for indicator in indicators.readlines():
		indicator = indicator.strip('\n')

		if testIfIP.match(indicator):
			#write the indicator to file using the IP type
			output.write("      <IndicatorItem id=\"\" condition=\"is\">\n")
			output.write("        <Context document=\"PortItem\" search=\"PortItem/remoteIP\" type=\"mir\" />\n")
			output.write("        <Content type=\"IP\">" + indicator + "</Content>\n")
			output.write("      </IndicatorItem>\n")
		elif testIfMD5.match(indicator):
			#write the indicator to file using the md5 type
			output.write("      <IndicatorItem id=\"\" condition=\"is\">\n")
			output.write("        <Context document=\"FileItem\" search=\"FileItem/Md5sum\" type=\"mir\" />\n")
			output.write("        <Content type=\"md5\">" + indicator + "</Content>\n")
			output.write("      </IndicatorItem>\n")
		else: #assumes domain if not IP or md5, supporting more ioc types is on the todo
			#write the indicator to the file using the domain type
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
	parser = optparse.OptionParser("usage: python iocOut.py [-h] [-f INPUT] [-o OUTPUT] [-n \"name\"] [-a \"author\"] [-d \"description\"]")
	parser.add_option('-f', dest='indicatorFile', type='string', help='File with indicators to use to generate an IOC file. Currently only .txt files are supported.')
	parser.add_option('-o', dest='outputFileName', type='string', default=None, help='Name of the output file. If not used, the file will be output as <input filename>.ioc.')
	parser.add_option('-n', dest='inputName', type='string', default=None, help='Populate the "Name" field in IOC Editor. String must be wrapped in quotes.')
	parser.add_option('-a', dest='inputAuthor', type='string', default=None, help='Populate the "Author" field in IOC Editor. String must be wrapped in quotes.')
	parser.add_option('-d', dest='inputDesc', type='string', default=None, help='Populate the "Description" field in IOC Editor. String must be wrapped in quotes.')
	(options, args) = parser.parse_args()
	
	indicatorFile = options.indicatorFile
	outputFileName = options.outputFileName
	inputName = options.inputName
	inputAuthor = options.inputAuthor
	inputDesc = options.inputDesc
	
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

	turnToIOC(indicatorFile, outputFileName, inputName, inputAuthor, inputDesc)

if __name__ == '__main__':
	main()