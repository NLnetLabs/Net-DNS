# $Id: 11-escapedchars.t 319 2005-05-30 17:12:09Z olaf $		 -*-perl-*-

#
#  These tests are called only if Net::DNS::TestNS is available
#

# You should have a couple of IP addresses at your disposal
#  sudo ifconfig lo0 inet 127.53.53.1 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.2 netmask 255.255.255.255 alias
#  sudo ifconfig lo0 inet 127.53.53.3 netmask 255.255.255.255 alias
# ...
#  sudo ifconfig lo0 inet 127.53.53.11 netmask 255.255.255.255 alias




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
		     127.53.53.5
		     127.53.53.6
		     127.53.53.7
		     127.53.53.8
		     127.53.53.9
		     127.53.53.10
		     127.53.53.11
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

	if ( $Net::DNS::TestNS::VERSION < 368){
	  diag ("You will need a more recent version of Net::DNS::TestNS");
	  diag ("which might not be available from CPAN");
	  diag ("Use subversion to fetch it from");
	  diag (" http://www.net-dns/svn/net-dns-testns/trunk ");
	  plan skip_all => "old Net::DNS::TestNS ($Net::DNS::TestNS::VERSION)";
	  exit;
	}
	plan tests => 56;
    }else{

       plan skip_all => 'Some modules required for this test are not available (dont\'t worry about this)';          
       exit;
   }





}	

my $configfile="t/testns.xml";

my $test_nameservers=Net::DNS::TestNS->new($configfile, {
#    Verbose => 1,
    Validate => 1,
});

is(ref($test_nameservers),"Net::DNS::TestNS", "Sever instance created");

use_ok("Net::DNS::Resolver");

my $resolver=Net::DNS::Resolver->new(
				     nameservers => \@Addresses,
				     port        => $TestPort,
				     debug => 0,
				     );

$test_nameservers->run();


#print join(" ", $resolver->nameservers());
$resolver->query("bla.foo", 'TXT');

use Net::DNS::Resolver::Recurse;

my $res = Net::DNS::Resolver::Recurse->new(
					   port  => $TestPort,
					   debug => 0,
					   );
$res->hints( "127.53.53.1" );


my $packet;


# This is a test for which in the delegation path there is one
# lame server.

# We need to run this test a couple of times
# The chances that the lame server is 1 in 3 so we run the experiment
# 50 times to be reasonably certain of the event having occured at least once.


my $i=0;
while ($i<50){
    $packet = $res->query_dorecursion("lame.test.zone","A");
    ok($packet,"Lame recursion test: Packet received");
    $i++;
}



$resolver->nameserver( qw( 127.53.53.1 ) );
$resolver->tcp_timeout(3);
$resolver->axfr('example.com');
is( $resolver->errorstring,"timeout", "AXFR timed out");


$resolver->nameserver( qw( 127.53.53.2 ) );
$resolver->tcp_timeout(3);
$resolver->axfr('example.com');
is( $resolver->errorstring,"Response code from server: REFUSED", "Got Refused");


#
#  Try to see if TCP connections work.
#
$resolver->nameserver( qw( 127.53.53.3 ) );
$resolver->usevc(1);
$resolver->tcp_timeout(3);
my $ans=$resolver->query("bla.foo", 'TXT');
is( $resolver->errorstring,"NOERROR","TCP request returned without Errors");
is(($ans->answer)[0]->type,"TXT","TXT type returned");



$test_nameservers->medea();
