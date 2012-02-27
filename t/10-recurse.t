# $Id$ -*-perl-*-

use Test::More;
use strict;
use t::NonFatal;

BEGIN {
	if (-e 't/online.enabled' && ! -e 't/online.disabled' ) {

	    #
	    # Some people try to run these on private address space."
	    use IO::Socket::INET;
	    my $sock = IO::Socket::INET->new(PeerAddr => '193.0.14.129', # k.root-servers.net.
					  PeerPort => '53',
					  Proto    => 'udp');
	    
	    
	    unless($sock){
		plan skip_all => "Cannot bind to socket:\n\t".$!."\n";
		diag "This is an indication you do have network problems";
		exit;
	    }else{
		my $ip = inet_ntoa($sock->sockaddr);
		if ( $ip =~ /^(10|172\.(1[6-9]|2.|30|31)|192.168)\./ ) {
		    plan skip_all => "Cannot run these tests from this IP: $ip";		
		    exit;
		}else{
		    plan tests => 12;
		    NonFatalBegin();
		}
	    }

	} else {

		    plan skip_all => 'Online tests disabled.';		



	}
}


BEGIN { use_ok('Net::DNS::Resolver::Recurse'); }


{
	my $res = Net::DNS::Resolver::Recurse->new;

	isa_ok($res, 'Net::DNS::Resolver::Recurse');

	$res->debug(1);	
	$res->udp_timeout(20);
	
	# Hard code A and K.ROOT-SERVERS.NET hint 
	ok($res->hints("193.0.14.129", "198.41.0.4" ), "hints() set");
	
	ok(%{ $res->{'hints'} }, 'sanity check worked');
	
	my $packet;
	
	# Try a domain that is a CNAME
	$packet = $res->query_dorecursion("www.google.com.","A");
	ok($packet, 'got a packet');
	ok(scalar $packet->answer, 'answer has RRs');
	
	# Try a big hairy one
	undef $packet;
	$packet = $res->query_dorecursion("www.rob.com.au.","A");
	ok($packet, 'got a packet');
	ok(scalar $packet->answer, 'anwer section had RRs');
}

# test the callback


my @HINTS= qw(
			
			192.33.4.12
			128.8.10.90
			192.203.230.10
			192.5.5.241
			192.112.36.4
			128.63.2.53
			192.36.148.17
			192.58.128.30
			193.0.14.129
			199.7.83.42
			202.12.27.33
			198.41.0.4
			192.228.79.201

			);

my $res2 = Net::DNS::Resolver::Recurse->new ;
$res2->nameservers( @HINTS );
my $ans_at=$res2->send("a.t.", "A");
if ($ans_at->header->ancount == 1 ){
    diag "We are going to skip a bunch of checks.";
    diag "There seems to be a middle box in the path that modifies your packets";
}
SKIP: {
    skip "Modifying middlebox detected ",4 if ($ans_at->header->ancount == 1 );
    
    {
	my $res = Net::DNS::Resolver::Recurse->new ;
	my $count;
	$res->debug(1);
	# Hard code root hints, there are some environments that will fail
	# the test otherwise
	$res->hints( @HINTS );
	
	
	$res->recursion_callback(sub {
	    my $packet = shift;
	    
	    isa_ok($packet, 'Net::DNS::Packet');
	    
	    $count++;
				 });
	
	$res->query_dorecursion('a.t.net-dns.org', 'A');
	
	ok($count >= 3, "Lookup took $count queries which is at least 3.");
    }
} 

NonFatalEnd();
