#!/usr/bin/perl -w
#
# weak_creds.pl - script to generate vuln checks based on weak/default credentials
#
# Joshua Abraham < jabra@rapid7.com >
#
# Modified for Carnegie Mellon University Use by Brian W. Gray
# 05.04.2016
#

use strict;
use MIME::Base64;
my $service = 'none';
my ( @file1, @file2 );
use DateTime;
my $dt        = DateTime->now;
my $ymd       = $dt->ymd('-');
my @supported = ( 'db2', 'mssql', 'mysql', 'postgres', 'ssh', 'ftp', 'telnet',
    'tomcat' );

sub help {
    print
        "$0: [service] [username_file.txt] [password_file.txt] (realm_file.txt - optional)\n";
    print "\n";
    print "Supported Services include: ";
    print join( ',', @supported );
    print "\n";
    exit;
}

sub vck {
    my ( $username, $password, $realm, $id ) = @_;
    my $vck = "<VulnerabilityCheck id=\"$id\" scope=\"endpoint\">\n";
    if ( $id =~ /^telnet/ ) {
        $vck .= "   <NetworkService type=\"Telnet\"/>\n";
    }
    elsif ( $id =~ /^postgres/ ) {
        $vck .= "   <NetworkService type=\"Postgres\"/>\n";
    }
    elsif ( $id =~ /^mysql/ ) {
        $vck .= "   <NetworkService type=\"MySQL\"/>\n";
    }
    elsif ( $id =~ /^ssh/ ) {
        $vck .= "   <NetworkService type=\"SSH\"/>\n";
    }
    elsif ( $id =~ /^ftp/ ) {
        $vck .= "   <NetworkService type=\"FTP\"/>\n";
    }
    elsif ( $id =~ /^tds/ ) {
        $vck .= "   <NetworkService type=\"TDS|Sybase\"/>\n";
    }
    elsif ( $id =~ /^db2/ ) {
        $vck .= "   <NetworkService type=\"DB2\"/>\n";
    }
    else { }

    $vck .= "   <DefaultAccount>\n";
    $vck .= "       <uid>$username</uid>\n";
    $vck .= "       <password>$password</password>\n";
    if ( $realm eq '*none*' ) {
        if ( $id =~ /^mssql/ or $service =~ /^tds/ ) {
            $vck .= "       <realm>master</realm>\n";
        }
        elsif ( $id =~ /^ssh/ or $id =~ /^ftp/ ) {

        }
        elsif ( $id =~ /^mysql/ ) {
            $vck .= "       <realm>mysql</realm>\n";
        }
        elsif ( $id =~ /^postgres/ ) {
            $vck .= "       <realm>template1</realm>\n";
        }
        elsif ( $id =~ /^db2/ ) {
            $vck .= "       <realm>SAMPLE</realm>\n";
        }
        else {
            $vck .= "       <realm></realm>\n";
        }
    }
    else {
        $vck .= "       <realm>$realm</realm>\n";
    }
    $vck .= "   </DefaultAccount>\n";
    $vck .= "</VulnerabilityCheck>\n";
    return $vck;
}

sub postgres {
    my ( $username, $password, $realm ) = @_;

    my $id;
    if ( $realm eq '*none*' ) {
        $id = "cmty-postgres-default-account-$username-password-$password";
    }
    else {
        $id = "cmty-postgres-default-account-$username-password-$password-$realm";
    }

    my $vck = vck( $username, $password, $realm, $id );
    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        = "<Vulnerability id=\"$id\" published=\"$ymd\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>Postgres access with $username/$password credentials</name>\n";
    $xml .= "   <severity>8</severity>\n";
    $xml .= "   <pci severity=\"3\"/>\n";
    $xml .= "   <cvss>(AV:L/AC:L/Au:N/C:P/I:P/A:P)</cvss>\n";
    $xml .= "   <Tags>\n";
    $xml .= "       <tag>PostgreSQL</tag>\n";
    $xml .= "       <tag>Database</tag>\n";
    $xml .= "       <tag>Default Account</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "   <Description>\n";
    $xml
        .= "Access to the Postgres server was gained using the user account &quot;$username&quot; and password &quot;$password&quot;.\n";
    $xml .= "   </Description>\n";
    $xml .= "   <Solutions>\n";
    $xml .= "       <Solution id=\"secure-postgres-account\" time=\"5m\">\n";
    $xml .= "       <summary>Secure the Postgres account</summary>\n";
    $xml .= "   <workaround>\n";
    $xml
        .= "   Remove or disable the account if it is not critical for the system to function.\n";
    $xml
        .= "   Otherwise, the password should be changed to a non-default value.\n";
    $xml .= "   </workaround>\n";
    $xml .= "   </Solution>\n";
    $xml .= "   </Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

sub mysql {
    my ( $username, $password, $realm ) = @_;

    my $id;
    if ( $realm eq '*none*' ) {
        $id = "cmty-mysql-default-account-$username-password-$password";
    }
    else {
        $id = "cmty-mysql-default-account-$username-password-$password-$realm";
    }

    my $vck = vck( $username, $password, $realm, $id );
    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        = "<Vulnerability id=\"$id\" published=\"$ymd\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>MySQL access with $username/$password credentials</name>\n";
    $xml .= "   <severity>7</severity>\n";
    $xml .= "   <pci severity=\"5\"/>\n";
    $xml .= "   <cvss>(AV:N/AC:L/Au:N/C:P/I:P/A:P)</cvss>\n";
    $xml .= "   <Tags>\n";
    $xml .= "       <tag>MySQL</tag>\n";
    $xml .= "       <tag>Database</tag>\n";
    $xml .= "       <tag>Default Account</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "   <Description>\n";
    $xml
        .= "Access to the MySQL server was gained using the user account &quot;$username&quot; and password &quot;$password&quot;.\n";
    $xml .= "   </Description>\n";
    $xml .= "   <Solutions>\n";
    $xml .= "       <Solution id=\"secure-mysql-account\" time=\"5m\">\n";
    $xml .= "       <summary>Secure the MySQL account</summary>\n";
    $xml .= "   <workaround>\n";
    $xml
        .= "   Remove or disable the account if it is not critical for the system to function.\n";
    $xml
        .= "   Otherwise, the password should be changed to a non-default value.\n";
    $xml .= "   </workaround>\n";
    $xml .= "   </Solution>\n";
    $xml .= "   </Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

sub ftp {
    my ( $username, $password, $realm ) = @_;

    my $id;
    if ( $realm eq '*none*' ) {
        $id = "cmty-ftp-default-account-$username-password-$password";
    }
    else {
        $id = "cmty-ftp-default-account-$username-password-$password-$realm";
    }

    my $vck = vck( $username, $password, $realm, $id );
    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        = "<Vulnerability id=\"$id\" published=\"$ymd\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>FTP access with $username/$password credentials</name>\n";
    $xml .= "   <severity>8</severity>\n";
    $xml .= "   <pci severity=\"5\"/>\n";
    $xml .= "   <cvss>(AV:N/AC:L/Au:N/C:P/I:P/A:P)</cvss>\n";
    $xml .= "   <Tags>\n";
    $xml .= "       <tag>FTP</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "   <Description>\n";
    $xml
        .= "Access to the FTP server was gained using the user account &quot;$username&quot; and password &quot;$password&quot;.\n";
    $xml .= "   </Description>\n";
    $xml .= "   <Solutions>\n";
    $xml .= "       <SolutionRef id=\"secure-ftp-account\"/>\n";
    $xml .= "   </Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

sub db2 {
    my ( $username, $password, $realm ) = @_;

    my $id;
    if ( $realm eq '*none*' ) {
        $id = "cmty-db2-default-account-$username-password-$password";
    }
    else {
        $id = "cmty-db2-default-account-$username-password-$password-$realm";
    }

    my $vck = vck( $username, $password, $realm, $id );
    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        .= "<Vulnerability id=\"$id\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>Default DB2 account $username/$password available</name>\n";
    $xml .= "   <severity>10</severity>\n";
    $xml .= "   <pci severity=\"5\"/>\n";
    $xml .= "   <Tags>\n";
    $xml .= "       <tag>Database</tag>\n";
    $xml .= "       <tag>DB2</tag>\n";
    $xml .= "       <tag>Default Account</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "   <cvss>(AV:N/AC:L/Au:N/C:P/I:P/A:P)</cvss>\n";
    $xml .= "   <AlternateIds>\n";
    $xml .= "   </AlternateIds>\n";
    $xml .= "   <Description>\n";
    $xml
        .= "DB2 creates a default account with the user ID &quot;$username&quot; and password &quot;$password&quot;. This account grants administrator level access to the system.\n";
    $xml .= "   </Description>\n";
    $xml .= "   <Solutions>\n";
    $xml .= "       <SolutionRef id=\"secure-db2-account\"/>\n";
    $xml .= "   </Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

sub telnet {
    my ( $username, $password, $realm ) = @_;

    my $id;
    if ( $realm eq '*none*' ) {
        $id = "cmty-telnet-default-account-$username-password-$password";
    }
    else {
        $id = "cmty-telnet-default-account-$username-password-$password-$realm";
    }

    my $vck = vck( $username, $password, $realm, $id );
    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        .= "<Vulnerability id=\"$id\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>Default Telnet password: $username password &quot;$password&quot;</name>\n";
    $xml .= "   <severity>10</severity>\n";
    $xml .= "   <pci severity=\"5\"/>\n";
    $xml .= "   <Tags>\n";
    $xml .= "       <tag>Default Account</tag>\n";
    $xml .= "       <tag>Telnet</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "   <cvss>(AV:N/AC:L/Au:N/C:C/I:C/A:C)</cvss>\n";
    $xml .= "   <AlternateIds>\n";
    $xml .= "   </AlternateIds>\n";
    $xml .= "   <Description>\n";
    $xml
        .= "   <p>The $username account uses a password of &quot;$password&quot;.\n";
    $xml
        .= "   This would allow anyone to log into the machine via Telnet and take complete control of the system.</p>\n";
    $xml .= "   </Description>\n";
    $xml .= " <Solutions>\n";
    $xml .= "   <Solution id=\"$id\" time=\"15m\">\n";
    $xml
        .= "       <summary>Change the password to a non-default value.</summary>\n";
    $xml .= "       <workaround>\n";
    $xml .= "<p>Change the password to a non-default value.</p>\n";
    $xml .= "       </workaround>\n";
    $xml .= "       </Solution>\n";
    $xml .= "   </Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

sub ssh {
    my ( $username, $password, $realm ) = @_;

    my $id;
    if ( $realm eq '*none*' ) {
        $id = "cmty-ssh-default-account-$username-password-$password";
    }
    else {
        $id = "cmty-ssh-default-account-$username-password-$password-$realm";
    }

    my $vck = vck( $username, $password, $realm, $id );
    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        .= "<Vulnerability id=\"$id\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>Default SSH account: $username password &quot;$password&quot;</name>\n";
    $xml .= "   <severity>10</severity>\n";
    $xml .= "   <pci severity=\"5\"/>\n";
    $xml .= "   <Tags>\n";
    $xml .= "       <tag>Default Account</tag>\n";
    $xml .= "       <tag>SSH</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "   <cvss>(AV:N/AC:L/Au:N/C:C/I:C/A:C)</cvss>\n";
    $xml .= "   <AlternateIds>\n";
    $xml .= "   </AlternateIds>\n";
    $xml .= "   <Description>\n";
    $xml
        .= "   <p>The $username account uses a password of &quot;$password&quot;.\n";
    $xml
        .= "   This would allow anyone to log into the machine via SSH and take complete control of the system.</p>\n";
    $xml .= "   </Description>\n";
    $xml .= " <Solutions>\n";
    $xml .= "   <Solution id=\"$id\" time=\"15m\">\n";
    $xml
        .= "       <summary>Fix Default SSH account: $username password &quot;$password&quot;</summary>\n";
    $xml .= "       <workaround>\n";
    $xml
        .= "<p>Use the &quot;passwd&quot; command to set a more secure login password. A good\n";
    $xml
        .= "   password should consist of a mix of lower- and upper-case characters,\n";
    $xml
        .= "   numbers, and punctuation and should be at least 8 characters long.</p>\n";
    $xml .= "       </workaround>\n";
    $xml .= "       </Solution>\n";
    $xml .= "   </Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

sub mssql {
    my ( $username, $password, $realm ) = @_;

    my $id;
    if ( $realm eq '*none*' ) {
        $id = "cmty-tds-default-account-$username-$password";
    }
    else {
        $id = "cmty-tds-default-account-$username-$password-$realm";
    }

    my $vck = vck( $username, $password, $realm, $id );
    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        .= "<Vulnerability id=\"$id\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>TDS (SQL Server) access with username $username and password $password </name>\n";
    $xml .= "   <severity>10</severity>\n";
    $xml .= "   <pci severity=\"5\"/>\n";
    $xml .= "   <Tags>\n";
    $xml .= "       <tag>Database</tag>\n";
    $xml .= "       <tag>Default Account</tag>\n";
    $xml .= "       <tag>Microsoft SQL Server</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "<cvss>(AV:N/AC:L/Au:N/C:C/I:C/A:C)</cvss>\n";
    $xml .= "<AlternateIds>\n";
    $xml .= "</AlternateIds>\n";
    $xml .= "<Description>\n";
    $xml
        .= "$service was found to have a weak account configuration with the user ID &quot;$username&quot; and password &quot;$password&quot;. This account grants administrator level access to the system.\n";
    $xml .= "  </Description>\n";
    $xml .= "<Solutions>\n";
    $xml .= "   <Solution id=\"fix-$id\" time=\"15m\">\n";
    $xml
        .= "   <summary>Fix TDS (SQL Server) access with $username and password $password</summary>\n";
    $xml .= "   <workaround>\n";
    $xml
        .= "   Remove or disable the account if it is not critical for the system to function. Otherwise, the password should be changed to a non-default value.\n";
    $xml .= "   </workaround>\n";
    $xml .= "   </Solution>\n";
    $xml .= "</Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

sub tomcat {
    my ( $username, $password, $realm ) = @_;

    my $str = "$username:$password";
    chomp($str);
    my $encoded_username_password = encode_base64("$str");
    chomp($encoded_username_password);

    my $id  = "cmty-http-tomcat-manager-$username-$password-password";
    my $vck = "<VulnerabilityCheck id=\"$id\" scope=\"endpoint\">\n";
    $vck .= "   <NetworkService type=\"HTTP|HTTPS\">\n";
    $vck .= "       <Product name=\"Apache Tomcat\"/>\n";
    $vck .= "   </NetworkService>\n";
    $vck .= "   <and>\n";
    $vck .= "       <HTTPCheck>\n";
    $vck .= "           <HTTPRequest method=\"GET\">\n";
    $vck .= "               <URI>/manager/html</URI>\n";
    $vck .= "           </HTTPRequest>\n";
    $vck .= "           <HTTPResponse code=\"401\"/>\n";
    $vck .= "       </HTTPCheck>\n";
    $vck .= "       <HTTPCheck>\n";
    $vck .= "           <HTTPRequest method=\"GET\">\n";
    $vck .= "               <URI>/manager/html</URI>\n";
    $vck
        .= "               <HTTPHeader name=\"Authorization\"><value>Basic $encoded_username_password</value></HTTPHeader>\n";
    $vck .= "           </HTTPRequest>\n";
    $vck
        .= "           <HTTPResponse code=\"200\"><regex>Tomcat</regex></HTTPResponse>\n";
    $vck .= "       </HTTPCheck>\n";
    $vck .= "   </and>\n";
    $vck .= "</VulnerabilityCheck>\n";

    open( VCK, ">$id.vck" ) or die "can't write file\n";
    print VCK $vck;

    my $xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
    $xml
        .= "<Vulnerability id=\"$id\" added=\"$ymd\" modified=\"$ymd\" version=\"2.0\">\n";
    $xml
        .= "   <name>Tomcat Application Manager Default $username / $password Password Vulnerability</name>\n";
    $xml .= "   <severity>10</severity>\n";
    $xml .= "   <pci severity=\"5\"/>\n";
    $xml .= "   <Tags>\n";
    $xml .= "   <tag>Default Account</tag>\n";
    $xml .= "   </Tags>\n";
    $xml .= "   <cvss>(AV:N/AC:L/Au:N/C:P/I:P/A:P)</cvss>\n";
    $xml .= "   <AlternateIds>\n";
    $xml .= "   </AlternateIds>\n";
    $xml .= "   <Description>\n";
    $xml
        .= "   Tomcat Manager was found to have a weak account configuration with the user ID &quot;$username&quot; and password &quot;$password&quot;. This account grants administrator level access to the system.\n";
    $xml .= "   </Description>\n";
    $xml .= "   <Solutions>\n";
    $xml
        .= "       <SolutionRef id=\"tomcat-default-password-workaround\"/>\n";
    $xml .= "   </Solutions>\n";
    $xml .= "</Vulnerability>\n";

    open( XML, ">$id.xml" ) or die "can't write file\n";
    print XML $xml;
}

if (    defined( $ARGV[0] )
    and defined( $ARGV[1] )
    and -r $ARGV[1]
    and defined( $ARGV[2] )
    and -r $ARGV[2] )
{
    my $service = $ARGV[0];
    my $warning = 1;
    foreach (@supported) {
        chomp;
        if ( $service eq $_ ) {
            $warning = 0;
            last;
        }
    }
    help() if ( $warning == 1 );

    open( FIRST, $ARGV[1] ) or die "Can't open username file\n";
    my @usernames = <FIRST>;
    close(FIRST);

    open( SECOND, $ARGV[2] ) or die "Can't open password file\n";
    my @passwords = <SECOND>;
    close(SECOND);

    my @realms;
    if ( defined( $ARGV[3] ) and -r $ARGV[3] ) {
        open( THIRD, $ARGV[3] ) or die "Can't open realm file\n";
        @realms = <THIRD>;
        close(THIRD);
    }
    else {
        push( @realms, '*none*' );
    }

    foreach my $realm (@realms) {
        chomp($realm);
        foreach my $username (@usernames) {
            chomp($username);
            foreach my $password (@passwords) {
                chomp($password);
                if ( $service eq 'tomcat' ) {
                    print "tomcat check generated for: $username/$password\n";
                    tomcat( $username, $password, $realm );
                }
                elsif ( $service eq 'db2' ) {
                    print "db2 check generated for: $username/$password\n";
                    db2( $username, $password, $realm );
                }
                elsif ( $service eq 'mssql' ) {
                    print "mssql check generated for: $username/$password\n";
                    mssql( $username, $password, $realm );
                }
                elsif ( $service eq 'postgres' ) {
                    print
                        "postgres check generated for: $username/$password\n";
                    postgres( $username, $password, $realm );
                }
                elsif ( $service eq 'mysql' ) {
                    print "mysql check generated for: $username/$password\n";
                    mysql( $username, $password, $realm );
                }
                elsif ( $service eq 'ftp' ) {
                    print "ftp check generated for: $username/$password\n";
                    ftp( $username, $password, $realm );
                }
                elsif ( $service eq 'ssh' ) {
                    print "ssh check generated for: $username/$password\n";
                    ssh( $username, $password, $realm );
                }
                elsif ( $service eq 'telnet' ) {
                    print "telnet check generated for: $username/$password\n";
                    telnet( $username, $password, $realm );
                }
                else { }
            }
        }
    }
}
else {
    help();
}