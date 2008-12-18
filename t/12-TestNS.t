# $Id$		 -*-perl-*-

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
use Net::DNS::Nameserver;

my $debug=0;

use vars qw(
	    @Addresses
	    $TestPort
            $lameloop
            $tcptimeout
	    );





BEGIN {
    $lameloop=2;
    $tcptimeout=6;
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
	plan tests => $lameloop+12;
    }else{

       plan skip_all => 'Some modules required for this test are not available (dont\'t worry about this)';          
       exit;
   }

}	

my $configfile="t/testns.xml";

my $test_nameservers=Net::DNS::TestNS->new($configfile, {
    Verbose => $debug,
    Validate => 1,
});

is(ref($test_nameservers),"Net::DNS::TestNS", "Sever instance created");

use_ok("Net::DNS::Resolver");

my $resolver=Net::DNS::Resolver->new(
				     nameservers => \@Addresses,
				     port        => $TestPort,
				     debug => $debug,
				     );

$test_nameservers->run();


#print join(" ", $resolver->nameservers());
$resolver->query("bla.foo", 'TXT');



# Try to see what happens with some really bogus data
#$resolver->ignqrid(1);
#$resolver->query("rt30316.test", 'A');


use Net::DNS::Resolver::Recurse;

my $res = Net::DNS::Resolver::Recurse->new(
					   port  => $TestPort,
					   debug => $debug,
					   );



$res->hints( "127.53.53.1" );
my $packet;


# This is a test for which in the delegation path there is one
# lame server.

# We need to run this test a couple of times The chances that the lame
# server is 1 in 3 so we run the experiment $lameloop (see BEGIN block
# above) times to be reasonably certain of the event having occured at
# least once.



my $i=0;
while ($i<$lameloop){
    $packet = $res->query_dorecursion("lame.test.zone","A");
    ok($packet,"Lame recursion test: Packet received");
    $i++;
}
$packet = $res->query_dorecursion("deeprecursion.test.zone","A");

$resolver->nameserver( qw( 127.53.53.1 ) );
$resolver->tcp_timeout($tcptimeout);
$resolver->axfr('example.com');
is( $resolver->errorstring,"timeout", "AXFR timed out");


$resolver->nameserver( qw( 127.53.53.2 ) );
$resolver->tcp_timeout($tcptimeout);
$resolver->axfr('example.com');
is( $resolver->errorstring,"Response code from server: REFUSED", "Got Refused");


#
#  Try to see if TCP connections work.
#
$resolver->nameserver( qw( 127.53.53.3 ) );
$resolver->usevc(1);
$resolver->tcp_timeout($tcptimeout);
my $ans=$resolver->query("bla.foo", 'TXT');
is( $resolver->errorstring,"NOERROR","TCP request returned without Errors");
is(($ans->answer)[0]->type,"TXT","TXT type returned");
undef($res);
$res = Net::DNS::Resolver->new(config_file => 't/resolv.conf-testns',
			  debug => 1,
				  port        => $TestPort,
    );

undef($ans);
$ans=$res->query("resolve.test","A");

is( $res->errorstring,"NOERROR","REFUSED TEST: request returned without Errors");
is(($ans->answer)[0]->type,"A","REFUSED TEST: type returned");
is(($ans->answer)[0]->name,"resolve.test","REFUSED TEST: proper owner name returned");
is($res->answerfrom,"127.53.53.10","Refused Test: Answer from proper server");


diag("Performing a test without actually testing on output");
undef($res);
undef($ans);
use Net::DNS::Resolver;
$res = Net::DNS::Resolver->new (
    retry => 1,
    udp_timeout => 1,
    config_file => 't/resolv.conf-testns',
    debug =>$debug,
    port => $TestPort
    );
$res->nameservers("ns.test.zone");
$ans = $res->query( "resolve.test.", "A");
diag($res->errorstring);
is(($ans->answer)[0]->type,"A","Problematic local resolver: type returned");
is(($ans->answer)[0]->name,"www.net-dns.org","Proplematic: proper owner name returned");


$test_nameservers->medea();

