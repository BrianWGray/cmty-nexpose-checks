#!/usr/bin/env ruby

## BrianWGray
## Carnegie Mellon University
## Initial Creation date: 08.17.2016

## = Description:
## == The script performs the following:
# 1. load sol schema
# 2. use the solution name to run schema validation of the solution
# 3. use dir.glob to specify one solution or any solutions matching partial solution name or directory location.
# 	 Examples:
# 		- "ruby validate_solution.rb cmty-"  will validate all solutions in the current directory starting with cmty-
# 		- "ruby validate_solution.rb cmty-ssh-disable-account-"  will validate all ssh account solutions in the current directory

## TODO: add appropriate exception handlers etc.

require 'rubygems'
gem 'nokogiri'
require 'nokogiri'

if ARGV.length < 1
	# for now if no argument is passed evaluate the current cwd
	puts "No solution name provided: defaulting to checking .sol files in ./"
	puts "If this isn't what you intended try #{__FILE__} cmty-solutionname"
else
	# accept solution name and strip file extentions if they are provided
	solutionName = ARGV[0].gsub(/.sol/i,"") # => "cmty-ssh-disable-account-admin"
end


## provide path locations to rapid7 schema files
## default location to find the schema files - console:/opt/rapid7/nexpose/plugins/xsd/
xsdPath = "xsd/"
solXsdPath = "#{xsdPath}vulnerability-solution.xsd"

def directory_check(directoryPath="./",solXsdPath)
	@directoryPath = directoryPath
	Dir.glob("#{@directoryPath}*.sol").each do|f| 

		begin

			@solXsdPath = solXsdPath
			## record solution names
			@solutionName = f
			
			# # Validate vck
			puts "\n\n\e[36mValidating #{@solutionName} against #{@solXsdPath}\n\e[0m"
			
			if File.exists?(@solutionName)
				begin
					validate(@solutionName, @solXsdPath, 'container').each do |error|
			  			puts "\e[31]m[WARNING]\e[0m - #{error.message}"
					end
				end

			else 
				puts "\n\n\n\e[31m[WARNING]\n\e[0m - The #{@solutionName} file is missing and the solution may not be validated\n\n"
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
directory_check(solutionName,solXsdPath)

