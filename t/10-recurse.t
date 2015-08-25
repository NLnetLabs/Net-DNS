# $Id$ -*-perl-*-

use strict;
use Test::More;
use t::NonFatal;

use Net::DNS;
use Net::DNS::Resolver::Recurse;


my @HINTS = qw(
		192.33.4.12
		199.7.91.13
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


exit( plan skip_all => 'Online tests disabled.' ) if -e 't/online.disabled';
exit( plan skip_all => 'Online tests disabled.' ) unless -e 't/online.enabled';


eval {
	my $res = Net::DNS::Resolver->new( retry => 1 );
	$res->nameservers(@HINTS);

	my $reply = $res->send( "a.t.", "A" ) || die;

	if ( $reply->header->ancount ) {
		diag "There seems to be a middle box in the path that modifies your packets";
		exit( plan skip_all => "Modifying middlebox detected" );
	}

	1;
} || exit( plan skip_all => "Unable to access global root nameservers" );


plan 'no_plan';

NonFatalBegin();

{
	my $res = Net::DNS::Resolver::Recurse->new( debug => 0 );

	ok( $res->isa('Net::DNS::Resolver::Recurse'), 'new() created object' );

	$res->udp_timeout(20);

	my $packet = $res->query_dorecursion( "www.google.com.", "A" );
	ok( $packet, 'got a packet' );
	ok( scalar $packet->answer, 'answer section has RRs' ) if $packet;
}


{
	# test hints()
	my $res = Net::DNS::Resolver::Recurse->new( debug => 0 );

	$res->udp_timeout(20);

	ok( scalar( $res->hints(@HINTS) ), "hints() set" );

	my $packet = $res->query_dorecursion( 'www.net-dns.org', 'A' );
	ok( $packet, 'got a packet' );
	ok( scalar $packet->answer, 'answer section has RRs' ) if $packet;
}


{
	# test the callback
	my $res = Net::DNS::Resolver::Recurse->new( debug => 0 );

	my $count = 0;

	$res->recursion_callback(
		sub {
			ok( shift->isa('Net::DNS::Packet'), 'callback argument is a packet' );
			$count++;
		} );

	$res->query_dorecursion( 'a.t.net-dns.org', 'A' );

	ok( $count >= 3, "Lookup took $count queries which is at least 3" );
}


{
	my $res = Net::DNS::Resolver::Recurse->new( debug => 0 );

	my $count = 0;

	$res->recursion_callback(
		sub {
			$count++;
		} );

	$res->query_dorecursion( '2a04:b900:0:0:8:0:0:60', 'A' );

	ok( $count >= 3, "Reverse lookup took $count queries" );
}


NonFatalEnd();

exit;
