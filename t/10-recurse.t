# $Id: 10-recurse.t 101 2004-08-12 05:12:05Z ctriv $

use Test::More;
use strict;

BEGIN {
	if (-e 't/online.enabled') {
		plan tests => 12;
	} else {
		plan skip_all => 'Online tests disabled.';
	}
}


BEGIN { use_ok('Net::DNS::Resolver::Recurse'); }


{
	my $res = Net::DNS::Resolver::Recurse->new;
	

	isa_ok($res, 'Net::DNS::Resolver::Recurse');

	#$res->debug(1);	
	$res->udp_timeout(60);
	
	# Hard code A.ROOT-SERVERS.NET hint
	ok($res->hints("198.41.0.4"), "hints() set");
	
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
	my $res = Net::DNS::Resolver::Recurse->new;

	my $count;

	$res->recursion_callback(sub {
		my $packet = shift;
		
		isa_ok($packet, 'Net::DNS::Packet');
		
		$count++;
	});

	$res->query_dorecursion('a.t.net-dns.org', 'A');
	
	is($count, 3);
}
