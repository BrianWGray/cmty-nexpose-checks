#!/usr/bin/env ruby

## BrianWGray
## Carnegie Mellon University
## Initial Creation date: 10.05.2016

## = Description:
## == The script performs the following:
# 1. load fingerprint file
# 2. Apply the fingerprint file to a provided uri
# 3. Return data as filtered by the finger print.
# 
# 	 Examples:
# 		- "ruby debug_fp.rb xpath_webapps.xml http://baseurl/" 

## TODO: 
# 	1. Write it?
# 	2. Add appropriate exception handlers etc. A lot of them

require 'rubygems'
require 'net/http'
gem 'nokogiri'
require 'nokogiri'
require 'pp'

if ARGV.length < 2
	# for now if no argument is passed evaluate the current cwd
	puts "No file name or base url provided: Exiting..."
	puts "If this isn't what you intended try #{__FILE__} xpath_webapps.xml http://baseurl/"
else
	# accept fingerprint file name
	fpXmlFile = ARGV[0] # => "xpath_webapps.xml"
	url = URI.parse(ARGV[1])

	# Broken out in this fasion to help me remember values
	# fpUri = URI("#{url.scheme}://#{url.host}#{url.path}#{url.query}#{url.fragment}") 

end


## provide path locations to rapid7 schema files
## default location to find the schema files - console:/opt/rapid7/nexpose/plugins/xsd/
xsdPath = "xsd/"
xmlXsdPath = "#{xsdPath}xml.xsd"


# Define Validation via Nokogiri
def validate(document_path, schema_path, root_element)
	@document_path, @schema_path, @root_element = document_path, schema_path, root_element

	begin
  		schema = Nokogiri::XML::Schema(File.open(@schema_path))
  		document = Nokogiri::XML(File.read(@document_path))
  		# schema.validate(document.xpath("//#{root_element}").to_s)
  		schema.validate(document)

  	rescue => error
  		puts error
 	end


end

# Apply XML Validations against the finger print file.
def fpCheck(fpXmlFile="./xpath_webapps.xml",xmlXsdPath)
	@fpXmlFile = fpXmlFile
	@xmlXsdPath = xmlXsdPath

	if File.exists?(@fpXmlFile)

				begin
					validate(@fpXmlFile, @xmlXsdPath, 'container').each do |error|
			  			puts error.message
					end
				end
			else
				puts "\n**	The #{@fpXmlFile} file is missing and the finger print description may not be validated\n\n"
			end
end

## Support HTTP Calls for fingerprint checks

# Make HTTP Connection and GET URI data to be evaluated
def getHttp(fpUri)
	res = Net::HTTP.get_response(fpUri)
	
	# Headers
	res['Set-Cookie']            # => String
	res.get_fields('set-cookie') # => Array
	res.to_hash['set-cookie']    # => Array

	return res
end

# Make HTTPS Connection and GET URI data to be evaluated
def getHttps(fpUri)
	http = Net::HTTP.new(fpUri.host, fpUri.port)
	
	http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE # For signature checks it doesn't matter if a valid certificate is present.

	# Headers
	res['Set-Cookie']            # => String
	res.get_fields('set-cookie') # => Array
	res.to_hash['set-cookie']    # => Array

	return res
end

def parseConfigs(fpXmlFile="./xpath_webapps.xml")
	

	if File.exists?(fpXmlFile)


		begin
			# Load fingerprint xml 
			@fpXml = Nokogiri::XML(File.open(fpXmlFile)) do |config|
				config.options = Nokogiri::XML::ParseOptions::NONET # Disable Network Connections during parsing
			end
		end
	else
		puts "\n**	The #{@fpXml} file is missing and the finger print configurations may not be imported\n\n"
		exit(1)
	end

	return @fpXml
end

def parseBody(fpUri,fpXpath,fpRegex)
	@fpUri = fpUri
	@fpXpath = fpXpath
	@fpRegex = fpRegex
	@queryInfo = getHttp(@fpUri)
	@value = Nokogiri::HTML.parse(@queryInfo.body)

	xpathReturn = @value.xpath("#{@fpXpath}")
	regexReturn = xpathReturn.to_s.match("#{@fpRegex}")

		puts "\r\nResults:\r\n"
		
		puts "XPath Match: #{xpathReturn}"
		puts "RegEx Match: #{regexReturn}"
		puts "Group 1 (Version) : #{regexReturn[1]}" if !regexReturn.nil?
		puts "\r\n"
	
	returnValue = [regexReturn, xpathReturn]

	return returnValue
end

def evaluateFingerPrints(fpXml,url)

	fpXml.xpath('//fingerprint').each do |fpInfo|
		puts "Finger Print: "
		fpInfo.xpath('example').each do |exampleInfo|
			puts "\r\nProduct  = " + exampleInfo.attributes["product"].to_s
		end
		
		fpInfo.xpath('get').each do |getInfo|
			# Check Path that will be provided from the signature file
			pathVerb = "GET"
			@path = getInfo.attributes["path"].to_s
			puts "\r\n#{pathVerb} #{@path}\r\n"
		
			fpInfo.xpath('test').each do |testInfo|
	 			@fpXpath = testInfo.attributes["xpath"].to_s
	 			@fpRegex = testInfo.attributes["regex"].to_s
	 			puts "\r\nxpath: #{@fpXpath}"
	 			puts "regex: #{@fpRegex}"
			end
		end
	
		fpInfo.xpath('post').each do |postInfo|
			pathVerb = "POST"
			@path = postInfo.attributes["path"].to_s
			puts "\r\n#{pathVerb} #{@path}\r\n"
		end
	  

		@fpUri = URI("#{url.scheme}://#{url.host}#{@path}")

		# Parse a specified URI based on information from the fingerprint.
		parsedReturn = parseBody(@fpUri,@fpXpath,@fpRegex)
		
		#puts "\r\nResults:\r\n"
		
		#puts "XPath Match: #{parsedReturn[1][0]}"
		#puts "RegEx Match: #{parsedReturn[0][0]}"
		#puts "Group 1 (Version) : #{parsedReturn[0][1]}"
		#puts "\r\n"
	
	end

end

# fpCheck(fpXmlFile,xmlXsdPath) # No XSD currently seems to exists to validate finger prints?

# Load fingerprint xml into fpXml
fpXml = parseConfigs(fpXmlFile)

evaluateFingerPrints(fpXml,url)















