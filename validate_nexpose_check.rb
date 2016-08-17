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
	# for now exit if no arguments are passed
	puts "No check name provided"
	puts "Try #{__FILE__} cmty-checkname"
	exit
else
	# accept check name and strip file extentions if they are provided
	checkName = ARGV[0].gsub(/.vck|.xml/i,"") # => "cmty-ssh-default-account-admin-password-admin123"
end


## provide path locations to rapid7 schema files
## default location to find the schema files - console:/opt/rapid7/nexpose/plugins/xsd/
xsdPath = "xsd/"
vckXsdPath = "#{xsdPath}vulnerability-check.xsd"
xmlXsdPath = "#{xsdPath}vulnerability-descriptor.xsd"

def directoryCheck(directoryPath="./",vckXsdPath,xmlXsdPath)
	@directoryPath = directoryPath
	Dir.glob("#{@directoryPath}*.vck").each do|f| 
		
		@vckXsdPath,@xmlXsdPath = vckXsdPath,xmlXsdPath
		## record check names
		@checkVck = f
		@checkXml = f.gsub(/.vck/i,'.xml')
		# # Validate vck
		puts "Validating #{@checkVck} against #{@vckXsdPath}"
		
		begin
			validate(@checkVck, @vckXsdPath, 'container').each do |error|
		  		puts error.message
			end
		end
		
		# Validate descriptor xml
		puts "Validating #{@checkXml} against #{@xmlXsdPath}"
		
		begin
			validate(@checkXml, @xmlXsdPath, 'container').each do |error|
		  		puts error.message
			end
		end
	end
end


def validate(document_path, schema_path, root_element)
	@document_path, @schema_path, @root_element = document_path, schema_path, root_element

  schema = Nokogiri::XML::Schema(File.open(@schema_path))
  document = Nokogiri::XML(File.read(@document_path))
  # schema.validate(document.xpath("//#{root_element}").to_s)
  schema.validate(document)
end

directoryCheck(checkName,vckXsdPath,xmlXsdPath)

