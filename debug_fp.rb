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
require 'openssl'
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
	# fpUri = URI("#{url.scheme}://#{url.host}#{url.path}#{url.port}#{url.query}#{url.fragment}") 
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

	if File.exists?(@fpXmlFile) # => @fpXmlFile = true
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
def getHttp(fpUri,fpVerb="GET",fpData="")
	#@fpUserAgent = "CMU/2.2 CFNetwork/672.0.8 Darwin/14.0.0"
	@fpUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0"

	http = Net::HTTP.new(fpUri.host, fpUri.port)

	case fpUri.scheme.upcase
		when "https".upcase
			http.use_ssl = true
		 	# For signature checks it doesn't matter if a valid certificate is present.
		 	http.verify_mode = OpenSSL::SSL::VERIFY_NONE if fpUri.scheme.upcase == "https".upcase
		else
		end

	case fpVerb.upcase
		when "Get".upcase
			# For now forcing encoding to text as some devices being tested have broken compression implemented.
			request = Net::HTTP::Get.new(fpUri,initheader = {'Accept-Encoding' => 'gzip, default, br', 'User-Agent' => @fpUserAgent})  if fpVerb.upcase == "Get".upcase
			# request = Net::HTTP::Get.new(fpUri)  if fpVerb.upcase == "Get".upcase # Default Header
			
			puts "GET #{fpUri}"

		when "Post".upcase
			request = Net::HTTP::Post.new(fpUri.request_uri)  if fpVerb.upcase == "Post".upcase
			request.set_form_data(fpData)  if fpVerb.upcase == "Post".upcase
		
		else
			requestFail = true
		end

	response = http.request(request) if !requestFail
	return response
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

def parseBody(fpUri,fpVerb,fpData,fpXpath,fpRegex)
	@fpUri = fpUri
	@fpXpath = fpXpath
	@fpRegex = fpRegex
	@queryInfo = getHttp(@fpUri,fpVerb,)
	@value = Nokogiri::HTML.parse(@queryInfo.body)

	xpathReturn = @value.xpath("#{@fpXpath}")
	regexReturn = xpathReturn.to_s.match("#{@fpRegex}")
	#regexReturn = Array.new
	
	#xpathReturn.each do |item|
    #	regexReturn << item.to_s.match("#{fpRegex}")
  	#end

		puts "\r\nResults:\r\n"
	
		puts "XPath Match: #{xpathReturn}"
		puts "RegEx Match: #{regexReturn}"
		puts "Group 1 (Version) : #{regexReturn[1]}" if !regexReturn.nil?
		puts "Group 2 (SubVersion) : #{regexReturn[2]}" if !regexReturn.nil?
		puts "\r\n"
	
	returnValue = [regexReturn, xpathReturn]

	return returnValue
end

def evaluateFingerPrints(fpXml,fpUrl)
	@fpVerb = "GET" # Default Verb for requests

	fpXml.xpath('//fingerprint').each do |fpInfo|
		fpInfo.xpath('example').each do |exampleInfo|
			puts "\r\n----------------------------- Finger Print: #{exampleInfo.attributes["product"].to_s} -----------------------------\r\n"
		end
		
		fpInfo.xpath('get').each do |getInfo|
			# Check Path that will be provided from the signature file
			@fpVerb = "GET"
			@path = getInfo.attributes["path"].to_s
			puts "\r\nRequest will #{@fpVerb} #{@path}\r\n"
		
			fpInfo.xpath('test').each do |testInfo|
	 			@fpXpath = testInfo.attributes["xpath"].to_s
	 			@fpRegex = testInfo.attributes["regex"].to_s
	 			puts "\r\nxpath: #{@fpXpath}"
	 			puts "regex: #{@fpRegex}"
			end
		end
	
		fpInfo.xpath('post').each do |postInfo|
			@fpVerb = "POST"
			@fpData = "" # What should be posted to the URI?
			@path = postInfo.attributes["path"].to_s
			puts "\r\n#{pathVerb} #{@path}\r\n"
		end
	  
		@fpUri = URI("#{fpUrl.scheme}://#{fpUrl.host}:#{fpUrl.port}#{@path}")

		# Parse a specified URI based on information from the fingerprint.
		parsedReturn = parseBody(@fpUri,@fpVerb,@fpData,@fpXpath,@fpRegex)
		
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




