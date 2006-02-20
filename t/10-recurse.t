# $Id$ -*-perl-*-

use Test::More;
use strict;

BEGIN {
	if (-e 't/online.enabled') {

	    #
	    # Some people try to run these on private address space."
	    use IO::Socket::INET;
	    my $sock = IO::Socket::INET->new(PeerAddr => '193.0.14.129', # k.root-servers.net.
					  PeerPort => '25',
					  Proto    => 'udp');
	    
	    
	    unless($sock){
		plan skip_all => "Cannot bind to socket:\n\t".$!."\n";
		diag "This is an indication you do not have network problems";
		exit;
	    }else{

		use Net::IP;
		my $ip=Net::IP->new(inet_ntoa($sock->sockaddr));
	    
		if ($ip->iptype() ne "PUBLIC"){
		    plan skip_all => 'Cannot run these tests from this IP:' .$ip->ip() ;		
		}else{
		    plan tests => 12;
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

	$res->debug(0);	
	$res->udp_timeout(20);
	
	# Hard code A and K.ROOT-SERVERS.NET hint 
	ok($res->hints("193.0.14.129", "198.41.0.4" ), "hints() set");
	
	ok(%{ $res->{'hints'} }, 'sanity check worked');
	
	my $packet;
	
	# Try a domain that is a CNAME
	$packet = $res->query_dorecursion("www.netscape.com.","A");
	ok($packet, 'got a packet');
	ok(scalar $packet->answer, 'answer has RRs');
	
	# Try a big hairy one
	undef $packet;
	$packet = $res->query_dorecursion("www.rob.com.au.","A");
	ok($packet, 'got a packet');
	ok(scalar $packet->answer, 'anwer section had RRs');
}

# test the callback



{
	my $res = Net::DNS::Resolver::Recurse->new ;
	my $count;


	$res->recursion_callback(sub {
		my $packet = shift;
		
		isa_ok($packet, 'Net::DNS::Packet');
		
		$count++;
	});

	$res->query_dorecursion('a.t.net-dns.org', 'A');
	
	is($count, 3);
}
