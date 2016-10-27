#!/usr/bin/env ruby

## BrianWGray
## Carnegie Mellon University
## Initial Creation date: 08.17.2016

## = Description:
## == The script performs the following:
# 1. load vck schema and descriptor xml schema
# 2. use the vulnerability checkName to run schema validation of the check
# 3. use dir.glob to specify one check or any checks matching partial check name or directory location.
# 	 Examples:
# 		- "ruby validate_nexpose_check.rb cmty-"  will validate all checks in the current directory starting with cmty-
# 		- "ruby validate_nexpose_check.rb cmty-ssh-default-account-"  will validate all ssh account checks in the current directory
# 		- "ruby validate_nexpose_check.rb cmty-ssh-default-account-pi-password-raspberry"  will validate the cmty-ssh-default-account-pi-password-raspberry vck and xml pair

## TODO: add appropriate exception handlers etc.

require 'rubygems'
gem 'nokogiri'
require 'nokogiri'

if ARGV.length < 1
	# for now if no argument is passed evaluate the current cwd
	puts "No check name provided: defaulting to checking .vck files in ./"
	puts "If this isn't what you intended try #{__FILE__} cmty-checkname"
else
	# accept check name and strip file extentions if they are provided
	checkName = ARGV[0].gsub(/.vck|.xml/i,"") # => "cmty-ssh-default-account-admin-password-admin123"
end


## provide path locations to rapid7 schema files
## default location to find the schema files - console:/opt/rapid7/nexpose/plugins/xsd/
xsdPath = "xsd/"
vckXsdPath = "#{xsdPath}vulnerability-check.xsd"
xmlXsdPath = "#{xsdPath}vulnerability-descriptor.xsd"

def directory_check(directoryPath="./",vckXsdPath,xmlXsdPath)
	@directoryPath = directoryPath
	Dir.glob("#{@directoryPath}*.vck").each do|f| 

		begin

			@vckXsdPath,@xmlXsdPath = vckXsdPath,xmlXsdPath
			## record check names
			@checkVck = f
			
			# # Validate vck
			puts "\n\n\e[36mValidating #{@checkVck} against #{@vckXsdPath}\n\e[0m"
			
			if File.exists?(@checkVck)
				begin
					validate(@checkVck, @vckXsdPath, 'container').each do |error|
			  			puts "\e[31]m[WARNING]\e[0m - #{error.message}"
					end
					@checkSolName = solution_exists(@checkVck, '//VulnerabilityCheck/@id')
					@checkXml = "#{@checkSolName}.xml"
				end

			else 
				puts "\n\n\n\e[31m[WARNING]\n\e[0m - The #{@checkVck} file is missing and the check may not be validated\n\n"
			end
			
			# Validate descriptor xml
			puts "\n\n\e[36mValidating #{@checkXml} from #{@checkVck} against #{@xmlXsdPath}\n\e[0m"
			
			if File.exists?(@checkXml)

				begin
					validate(@checkXml, @xmlXsdPath, 'container').each do |error|
			  			puts error.message
					end

					@solName = solution_exists(@checkXml, '//Vulnerability/@id')
					@solFileName = @checkXml.gsub(/.xml/i,"") 
					puts "\n\e[31m[WARNING]\e[0m - Solution ID \e[35m#{@solName}\e[0m and File name \e[35m#{@solFileName}\e[0m.xml do not match\n\e[31m[WARNING]\e[0m - Review the Vulnerability ID within the solution file." if @solName .to_s.chomp != @solFileName.to_s.chomp

				end
			else
				puts "\n\e[31m[WARNING]\e[0m - #{@checkXml} file could not be found\n\e[31m[WARNING]\e[0m - This may indicate a typo, an invalid vulnerability ID being referenced in \e[33m#{@checkVck}\e[0m, or a missing file\n\n"
				puts "If a check specifies <VulnerabilityCheck id=\"#{@solName}\"... then the name must match the vulnerability definition base filename and id that the check points to.\n\n"
			end

		rescue => error
  			puts error.message
  			next
		end
	end
end

def parse_xml(xmlFile)
	if File.exists?(xmlFile)
		begin
			# Load xml file
			@xml = Nokogiri::XML(File.open(xmlFile)) do |config|
				config.options = Nokogiri::XML::ParseOptions::NONET # Disable Network Connections during parsing
			end
		end
	else
		puts "\n\e[31m[WARNING]\e[0m -	The file: #{@xml} is was not found.\n\n"
		exit(1)
	end
	
	return @xml
end

def solution_exists(documentPath, solXpath)
	@directoryPath = documentPath
	@solAvailable = false 

	@xml = parse_xml(documentPath)

	@solName = @xml.xpath(solXpath)

	puts @directoryPath
	puts "extracted solution id: #{@solName}"

	return @solName
end


def validate(documentPath, schemaPath, rootElement)
	@documentPath, @schemaPath, @rootElement = documentPath, schemaPath, rootElement
	begin
  		schema = Nokogiri::XML::Schema(File.open(@schemaPath))
  		document = Nokogiri::XML(File.read(@documentPath))
  		# schema.validate(document.xpath("//#{root_element}").to_s)
  		schema.validate(document)

  	rescue => error
  		puts error
 	end


end

# Run
directory_check(checkName,vckXsdPath,xmlXsdPath)

