#!/usr/bin/env ruby
#
# BrianWGray
# Carnegie Mellon University
# Initial Creation Date: 08.16.2016

# 10.12.2018 added simple check for HTTP Basic auth - BrianWGray

## Script Description
# Generate checks using nexpose check templates.

# TODO: everything
## 1.) re-implement weak_creds.pl provided by Rapid7 in Ruby
## 2.) ...

require 'Time' # => Import Time for inserting generation dates in the description file
require 'base64' # => Import base64 to encode HTTP Basic Auth values

timeInfo = Time.now
checkType = "ssh" # For now force service type to SSH

## Collect interactive information
# TODO: make this an optional collection type and also provide various arg entry options.
puts "Enter Check Type: (SSH, Telnet, HTTP, basicauth)"
checkType = gets.chomp

puts "Enter user account:"
username = gets.chomp

puts "Enter user password:"
password = gets.chomp


def gen_content(username, password, checkType, vck, xml) 
  @username, @password, @checkType, @vck, @xml = username, password, checkType, vck, xml
  File.write("cmty-#{@checkType.downcase}-default-account-#{username}-password-#{password}.vck", @vck)
  File.write("cmty-#{@checkType.downcase}-default-account-#{username}-password-#{password}.xml", @xml)
end

## Load File Templates
# TODO: Move templates out of this file and use something like gsub to replace var locations?

def vck_file_content(username, password, checkType)
  @username, @password, @checkType = username, password, checkType
  case @checkType.downcase 
      when "ssh"
        vckFileContent =  "<VulnerabilityCheck id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" scope=\"endpoint\">\n"
        vckFileContent += "    <NetworkService type=\"#{@checkType.upcase}\"/>\n"
        vckFileContent += "       <DefaultAccount>\n"
        vckFileContent += "          <uid>#{@username}</uid>\n"
        vckFileContent += "          <password><![CDATA[#{@password}]]></password>\n"
        vckFileContent += "       </DefaultAccount>\n"
        vckFileContent += "</VulnerabilityCheck>\n"
  
      when "telnet"
        vckFileContent =  "<VulnerabilityCheck id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" scope=\"endpoint\">\n"
        vckFileContent += "    <NetworkService type=\"#{@checkType.capitalize}\"/>\n"
        vckFileContent += "       <DefaultAccount>\n"
        vckFileContent += "          <uid>#{@username}</uid>\n"
        vckFileContent += "          <password><![CDATA[#{@password}]]></password>\n"
        vckFileContent += "       </DefaultAccount>\n"
        vckFileContent += "</VulnerabilityCheck>\n"

      when "http"
        vckFileContent =  "<VulnerabilityCheck id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" scope=\"endpoint\">\n"
        vckFileContent += "    <NetworkService type=\"HTTP|HTTPS\"/>\n"
        vckFileContent += "       <DefaultAccount>\n"
        vckFileContent += "          <uid>#{@username}</uid>\n"
        vckFileContent += "          <password><![CDATA[#{@password}]]></password>\n"
        vckFileContent += "       </DefaultAccount>\n"
        vckFileContent += "</VulnerabilityCheck>\n"

      when "basicauth"

        puts "Enter uri path to auth (/):"
        path = gets.chomp
        vckFileContent =  "<VulnerabilityCheck id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" scope=\"endpoint\">\n"
        vckFileContent += "    <NetworkService type=\"HTTP|HTTPS\"/>\n"
        vckFileContent += "       <DefaultAccount>\n"
        vckFileContent += "          <uid>#{@username}</uid>\n"
        vckFileContent += "          <password><![CDATA[#{@password}]]></password>\n"
        vckFileContent += "       </DefaultAccount>\n"
        vckFileContent += "</VulnerabilityCheck>\n"

        basicValue = Base64.encode64("#{@username}:#{@password}").chomp
        vckFileContent  = "<VulnerabilityCheck id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" scope=\"endpoint\">\n"
        vckFileContent += "  <NetworkService type=\"HTTP|HTTPS\"/>\n"
        vckFileContent += "<and>\n"
        vckFileContent += "  <HTTPCheck>\n"
        vckFileContent += "      <HTTPRequest method=\"GET\">\n"
        vckFileContent += "          <URI><![CDATA[#{path}]]></URI>\n"
        vckFileContent += "      </HTTPRequest>\n"
        vckFileContent += "      <HTTPResponse code=\"401\"/>\n"
        vckFileContent += "  </HTTPCheck>\n"
        vckFileContent += "  <HTTPCheck>\n"
        vckFileContent += "      <HTTPRequest method=\"GET\">\n"
        vckFileContent += "          <URI><![CDATA[#{path}]]></URI>\n"
        vckFileContent += "          <HTTPHeader name=\"Authorization\"><value>Basic #{basicValue}</value></HTTPHeader>\n"
        vckFileContent += "      </HTTPRequest>\n"
        vckFileContent += "      <HTTPResponse code=\"200\"></HTTPResponse>\n"
        vckFileContent += "  </HTTPCheck>\n"
        vckFileContent += "</and>\n"
        vckFileContent += "</VulnerabilityCheck>\n"

      else
        raise Invalid, "service type unrecognized"
  end

  return vckFileContent
end

def xml_file_content(username, password, checkType, timeInfo)
  @username, @password, @checkType, @timeInfo = username, password, checkType, timeInfo
  case @checkType.downcase
    when "ssh"
      xmlFileContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      xmlFileContent += "<Vulnerability id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" published=\"#{@timeInfo.strftime("%Y-%m-%d")}\" added=\"#{@timeInfo.strftime("%Y-%m-%d")}\" modified=\"#{@timeInfo.strftime("%Y-%m-%d")}\" version=\"2.0\">\n"
      xmlFileContent += "  <name>Default #{@checkType} account: #{@username} password \"<![CDATA[#{@password}]]>\"</name>\n"
      xmlFileContent += "  <severity>10</severity>\n"
      xmlFileContent += "  <cvss>(AV:N/AC:L/Au:N/C:C/I:C/A:C)</cvss>\n"
      xmlFileContent += "  <Tags>\n"
      xmlFileContent += "    <tag>Default Account</tag>\n"
      xmlFileContent += "    <tag>#{@checkType.upcase}</tag>\n"
      xmlFileContent += "  </Tags>\n"
      xmlFileContent += "  <AlternateIds>\n"
      xmlFileContent += "  </AlternateIds>\n\n"
      xmlFileContent += "  <Description>\n"
      xmlFileContent += "    <p>The #{@username} account uses a password of &quot;<![CDATA[#{@password}]]>&quot;.  This would allow\n"
      xmlFileContent += "      anyone to log into the machine via #{@checkType.upcase} and take complete\n"
      xmlFileContent += "      control.</p>\n"
      xmlFileContent += "  </Description>\n"
      xmlFileContent += "  <Solutions>\n"
      xmlFileContent += "    <Solution id=\"cmty-#{@checkType}-default-account-#{@username}-password-#{@password}\" time=\"15m\">\n"
      xmlFileContent += "      <summary>Fix Default #{@checkType.upcase} account: #{@username} password: <![CDATA[#{@password}]]></summary>\n"
      xmlFileContent += "      <workaround>\n"
      xmlFileContent += "        <p>\n"
      xmlFileContent += "          Change the password to a strong non-default value.\n"
      xmlFileContent += "        </p>\n"
      xmlFileContent += "      </workaround>\n"
      xmlFileContent += "    </Solution>\n"
      xmlFileContent += "  </Solutions>\n"
      xmlFileContent += "</Vulnerability>\n"

    when "telnet"
      xmlFileContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      xmlFileContent += "<Vulnerability id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" published=\"#{@timeInfo.strftime("%Y-%m-%d")}\" added=\"#{@timeInfo.strftime("%Y-%m-%d")}\" modified=\"#{@timeInfo.strftime("%Y-%m-%d")}\" version=\"2.0\">\n"
      xmlFileContent += "  <name>Default #{@checkType.capitalize} account: #{@username} password \"<![CDATA[#{@password}]]>\"</name>\n"
      xmlFileContent += "  <severity>10</severity>\n"
      xmlFileContent += "  <cvss>(AV:N/AC:L/Au:N/C:C/I:C/A:C)</cvss>\n"
      xmlFileContent += "  <Tags>\n"
      xmlFileContent += "    <tag>Default Account</tag>\n"
      xmlFileContent += "    <tag>#{@checkType.capitalize}</tag>\n"
      xmlFileContent += "  </Tags>\n"
      xmlFileContent += "  <AlternateIds>\n"
      xmlFileContent += "  </AlternateIds>\n\n"
      xmlFileContent += "  <Description>\n"
      xmlFileContent += "    <p>The #{@username} account uses a password of &quot;<![CDATA[#{@password}]]>&quot;.  This would allow\n"
      xmlFileContent += "      anyone to log into the machine via #{@checkType.upcase} and take complete\n"
      xmlFileContent += "      control.</p>\n"
      xmlFileContent += "  </Description>\n"
      xmlFileContent += "  <Solutions>\n"
      xmlFileContent += "    <Solution id=\"cmty-#{@checkType}-default-account-#{@username}-password-#{@password}\" time=\"15m\">\n"
      xmlFileContent += "      <summary>Fix Default #{@checkType.upcase} account: #{@username} password: <![CDATA[#{@password}]]></summary>\n"
      xmlFileContent += "      <workaround>\n"
      xmlFileContent += "        <p>\n"
      xmlFileContent += "          Change the password to a strong non-default value.\n"
      xmlFileContent += "        </p>\n"
      xmlFileContent += "      </workaround>\n"
      xmlFileContent += "    </Solution>\n"
      xmlFileContent += "  </Solutions>\n"
      xmlFileContent += "</Vulnerability>\n"

    when "http"
      xmlFileContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      xmlFileContent += "<Vulnerability id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" published=\"#{@timeInfo.strftime("%Y-%m-%d")}\" added=\"#{@timeInfo.strftime("%Y-%m-%d")}\" modified=\"#{@timeInfo.strftime("%Y-%m-%d")}\" version=\"2.0\">\n"
      xmlFileContent += "  <name>Default #{@checkType} account: #{@username} password \"<![CDATA[#{@password}]]>\"</name>\n"
      xmlFileContent += "  <severity>8</severity>\n"
      xmlFileContent += "  <cvss>(AV:N/AC:L/Au:S/C:P/I:C/A:P)</cvss>\n"
      xmlFileContent += "  <Tags>\n"
      xmlFileContent += "    <tag>Default Account</tag>\n"
      xmlFileContent += "    <tag>#{@checkType.upcase}</tag>\n"
      xmlFileContent += "  </Tags>\n"
      xmlFileContent += "  <AlternateIds>\n"
      xmlFileContent += "  </AlternateIds>\n\n"
      xmlFileContent += "  <Description>\n"
      xmlFileContent += "    <p>The #{@username} account uses a password of &quot;<![CDATA[#{@password}]]>&quot;.  This would allow\n"
      xmlFileContent += "      anyone to log into the web application via #{@checkType.upcase} and abuse the application\n"
      xmlFileContent += "      </p>\n"
      xmlFileContent += "  </Description>\n"
      xmlFileContent += "  <Solutions>\n"
      xmlFileContent += "    <Solution id=\"cmty-#{@checkType}-default-account-#{@username}-password-#{@password}\" time=\"15m\">\n"
      xmlFileContent += "      <summary>Fix Default #{@checkType.upcase} account: #{@username} password: <![CDATA[#{@password}]]></summary>\n"
      xmlFileContent += "      <workaround>\n"
      xmlFileContent += "        <p>\n"
      xmlFileContent += "          Change the password to a strong non-default value.\n"
      xmlFileContent += "        </p>\n"
      xmlFileContent += "      </workaround>\n"
      xmlFileContent += "    </Solution>\n"
      xmlFileContent += "  </Solutions>\n"
      xmlFileContent += "</Vulnerability>\n"

    when "basicauth"
      xmlFileContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      xmlFileContent += "<Vulnerability id=\"cmty-#{@checkType.downcase}-default-account-#{@username}-password-#{@password}\" published=\"#{@timeInfo.strftime("%Y-%m-%d")}\" added=\"#{@timeInfo.strftime("%Y-%m-%d")}\" modified=\"#{@timeInfo.strftime("%Y-%m-%d")}\" version=\"2.0\">\n"
      xmlFileContent += "  <name>Default #{@checkType} account: #{@username} password \"<![CDATA[#{@password}]]>\"</name>\n"
      xmlFileContent += "  <severity>8</severity>\n"
      xmlFileContent += "  <cvss>(AV:N/AC:L/Au:S/C:P/I:C/A:P)</cvss>\n"
      xmlFileContent += "  <Tags>\n"
      xmlFileContent += "    <tag>Default Account</tag>\n"
      xmlFileContent += "    <tag>HTTP</tag>\n"
      xmlFileContent += "    <tag>Web</tag>\n"
      xmlFileContent += "  </Tags>\n"
      xmlFileContent += "  <AlternateIds>\n"
      xmlFileContent += "  </AlternateIds>\n\n"
      xmlFileContent += "  <Description>\n"
      xmlFileContent += "    <p>The #{@username} account uses a password of &quot;<![CDATA[#{@password}]]>&quot;. This would allow\n"
      xmlFileContent += "      anyone to log into the web application via #{@checkType.upcase} and abuse the application\n"
      xmlFileContent += "      </p>\n"
      xmlFileContent += "  </Description>\n"
      xmlFileContent += "  <Solutions>\n"
      xmlFileContent += "    <Solution id=\"cmty-#{@checkType}-default-account-#{@username}-password-#{@password}\" time=\"15m\">\n"
      xmlFileContent += "      <summary>Fix Default #{@checkType.upcase} account: #{@username} password: <![CDATA[#{@password}]]></summary>\n"
      xmlFileContent += "      <workaround>\n"
      xmlFileContent += "        <p>\n"
      xmlFileContent += "          Change the password to a strong non-default value.\n"
      xmlFileContent += "        </p>\n"
      xmlFileContent += "      </workaround>\n"
      xmlFileContent += "    </Solution>\n"
      xmlFileContent += "  </Solutions>\n"
      xmlFileContent += "</Vulnerability>\n"

    else
      raise Invalid, "service type unrecognized"
  end

  return xmlFileContent
end

vck = vck_file_content(username, password, checkType)
xml = xml_file_content(username, password, checkType, timeInfo)

gen_content(username,password,checkType,vck,xml)


