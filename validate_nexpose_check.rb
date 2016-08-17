#!/usr/bin/env ruby

## BrianWGray
## Carnegie Mellon University
## Initial Creation date: 08.17.2016

## = Description:
## == The script performs the following:
# 1. load vck schema and descriptor xml schema
# 2. use the vulnerability checkName to run schema validation of the check
# 3. 
# TODO provide an option for performing mass validation of all checks in a directory.

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

## record check names
checkVck = "#{checkName}.vck"
checkXml = "#{checkName}.xml"

## provide path locations to rapid7 schema files
## default location to find the schema files - console:/opt/rapid7/nexpose/plugins/xsd/
xsdPath = "../checkscheme/xsd/"
vckXsdPath = "#{xsdPath}vulnerability-check.xsd"
xmlXsdPath = "#{xsdPath}vulnerability-descriptor.xsd"

def validate(document_path, schema_path, root_element)
	@document_path, @schema_path, @root_element = document_path, schema_path, root_element

  schema = Nokogiri::XML::Schema(File.open(@schema_path))
  document = Nokogiri::XML(File.read(@document_path))
  # schema.validate(document.xpath("//#{root_element}").to_s)
  schema.validate(document)
end

# # Validate vck
puts "Validating #{checkVck} against #{vckXsdPath}"

begin
	validate(checkVck, vckXsdPath, 'container').each do |error|
  		puts error.message
	end
end

# Validate descriptor xml
puts "Validating #{checkXml} against #{xmlXsdPath}"

begin
	validate(checkXml, xmlXsdPath, 'container').each do |error|
  		puts error.message
	end
end
