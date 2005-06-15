# $Id: 11-escapedchars.t 319 2005-05-30 17:12:09Z olaf $		 -*-perl-*-

#
#  These tests are called only if Net::DNS::TestNS is available
#

# You should have a couple of IP addresses at your disposal
#  sudo ifconfig lo0 inet 127.53.53.1 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.2 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.3 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.4 netmask 255.255.255.255 alias




use Test::More;
use strict;


use vars qw(
	    @Addresses
	    $TestPort
	    );





BEGIN {
    $TestPort  = 53452;
    @Addresses = qw (
		     127.53.53.1
		     127.53.53.2
		     127.53.53.3
		     127.53.53.4
		     );
    
    if(
       eval {require Net::DNS::TestNS;} &&
       eval {require IO::Socket;}
       ){
	#Try binding to the test addresses .. 
	foreach my $address (@Addresses){
	    diag ("Testing availability of $address");
	    my $s = IO::Socket::INET->new(Proto => 'udp',
					  LocalAddr => $address,
					  LocalPort => $TestPort
					  );

	    

	    unless ($s){
		diag ("This test needs ".join (" ",@Addresses). " to be configured on your system");

		plan skip_all =>  "$address has not been configured";
		exit;
	    }
	    close ($s);


	}
	plan tests => 1;
    }else{

       plan skip_all => 'Some modules required for this test are not available (dont\'t worry about this)';          
       exit;
   }





}	

my $configfile="t/testns.xml";


my $server=Net::DNS::TestNS->new($configfile, {
#    Verbose => 1,
    Validate => 1,
});

is(ref($server),"Net::DNS::TestNS", "Sever instance created");

use_ok("Net::DNS::Resolver");

my $resolver=Net::DNS::Resolver->new(
				     nameservers => \@Addresses,
				     port        => $TestPort,
				     debug => 1,
				     );

$server->run();

print join(" ", $resolver->nameservers());

$resolver->query("bla.foo", 'TXT');


$server->medea();
