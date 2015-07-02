# $Id$ -*-perl-*-

use strict;
use Test::More;

use Net::DNS;
use t::NonFatal;
use Socket;


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
	my $res = new Net::DNS::Resolver();
	exit plan skip_all => "No nameservers" unless $res->nameservers;

	my $reply = $res->send( ".", "NS" ) || die;

	exit plan skip_all => "Local nameserver broken" unless $reply->header->ancount;

	1;
} || exit( plan skip_all => "Unable to access local nameserver" );


eval {
	my $res = new Net::DNS::Resolver( nameservers => [@HINTS] );

	my $reply = $res->send( "a.t.", "A" ) || die;

	if ( $reply->header->ancount ) {
		diag "There seems to be a middle box in the path that modifies your packets";
		exit( plan skip_all => "Modifying middlebox detected" );
	}

	1;
} || exit( plan skip_all => "Unable to access global root nameservers" );


eval {
	my $res = new Net::DNS::Resolver();

	my $reply = $res->send( "a.t.", "A" ) || die;

	if ( $reply->header->ancount ) {
		my $server = $reply->answerfrom;
		my ($rr) = $reply->answer;
		diag "\nFor unexplained reasons a query for 'a.t' resolves as";
		diag $rr->string;
		diag "\nUsers of 'dig' may try 'dig a.t.' to test this hypothesis";
	}

	1;
} || exit( plan skip_all => "Unable to access local nameserver" );


plan tests => 120;

NonFatalBegin();


sub timeoutres {
	return Net::DNS::Resolver->new(
		tcp_timeout => 3,
		udp_timeout => 3
		);
}


my $res = &timeoutres;

my @rrs = (
	{	type	=> 'A',
		name	=> 'a.t.net-dns.org',
		address => '10.0.1.128',
		},
	{	type	   => 'MX',
		name	   => 'mx.t.net-dns.org',
		exchange   => 'a.t.net-dns.org',
		preference => 10,
		},
	{	type  => 'CNAME',
		name  => 'cname.t.net-dns.org',
		cname => 'a.t.net-dns.org',
		},
	{	type	=> 'TXT',
		name	=> 'txt.t.net-dns.org',
		txtdata => 'Net-DNS',
		},

	);


foreach my $data (@rrs) {

	my $packet = $res->send( $data->{'name'}, $data->{'type'}, 'IN' );

SKIP: {
		my $subtests = 8 + scalar( keys %{$data} );
		skip( "undefined packet", $subtests )
				unless ok( $packet, "send( $data->{name} IN $data->{type} )" );

		ok( $packet->isa('Net::DNS::Packet'), "Net::DNS::Packet returned" );

		my $from = $packet->answerfrom || '';
		my $header = $packet->header;
		is( $header->qdcount, 1, 'Only one question' );

		skip( join( ' ', "Empty response from $from", "RCODE:", $header->rcode ), $subtests - 3 )
				unless ok( $header->ancount, "Received answer" );

		is( $header->ancount, 1, 'Got single answer' );

		my ($question) = $packet->question;
		my ($answer)   = $packet->answer;

		is( $question->qname,  $data->{'name'}, 'Question has right name' );
		is( $question->qtype,  $data->{'type'}, 'Question has right type' );
		is( $question->qclass, 'IN',		'Question has right class' );

		is( $answer->class, 'IN', 'RR class correct' );

		foreach my $meth ( keys %{$data} ) {
			if ( $meth eq "name" ) {

				#names should be case insensitive
				is( lc( $answer->$meth() ), lc( $data->{$meth} ), "$meth correct ($data->{name})" );
			} else {
				is( $answer->$meth(), $data->{$meth}, "$meth correct ($data->{name})" );
			}
		}
	}
}


#
# Does the mx() function work.
#
{
	my @mx = mx( &timeoutres, 'mx2.t.net-dns.org' );

	my $wanted_names = [qw(a.t.net-dns.org a2.t.net-dns.org)];
	my $names = [map { $_->exchange } @mx];

	is_deeply( $names, $wanted_names, "mx() seems to be working" );

	# some people seem to use mx() in scalar context
	is( scalar mx( &timeoutres, 'mx2.t.net-dns.org' ), 2, "mx() works in scalar context" );

	is( scalar mx( &timeoutres, 'bogus.t.net-dns.org' ), 0, "mx() works for bogus name" );

	is( scalar mx('mx2.t.net-dns.org'), 2, "mx() works with resolver defaults" );
}


#
# test that search() and query() DTRT with reverse lookups
#
{
	my @tests = (
		{	ip   => '198.41.0.4',
			host => 'a.root-servers.net',
			},
		{	ip   => '2001:500:1::803f:235',
			host => 'h.root-servers.net',
			},
		);

	foreach my $test (@tests) {
		foreach my $method (qw(search query)) {
			my $packet = $res->$method( $test->{'ip'} );

	SKIP: {
				skip( "undefined packet", 3 )
						unless ok( $packet, "$method( $test->{'ip'} )" );

				ok( $packet->isa('Net::DNS::Packet'), "$method returns Net::DNS::Packet" );
				my $from = $packet->answerfrom || '';
				my $header = $packet->header;
				skip( join( ' ', "Empty response from $from", "RCODE:", $header->rcode ), 1 )
						unless ok( $header->ancount, "Received answer" );

				my ($rr) = $packet->answer;
				is( lc( $rr->ptrdname ), lc( $test->{'host'} ), "$method($test->{'ip'}) works" );
			}
		}
	}
}


#
# test the search() and query() append the default domain and
# searchlist correctly.
#
{
	my $res = Net::DNS::Resolver->new(
		domain	       => 't.net-dns.org',
		searchlist     => ['t.net-dns.org', 'net-dns.org'],
		udp_timeout    => 3,
		tcp_timeout    => 3,
		defnames       => 1,
		dnsrch	       => 1,
		persistent_udp => 0,
		);

	my @tests = (
		{	method => 'query',
			name   => 'a',
			},
		{	method => 'search',
			name   => 'a',
			},
		{	method => 'search',
			name   => 'a.t',
			},
		);


	foreach my $test (@tests) {
		my $method = $test->{'method'};

		my $packet = $res->$method( $test->{'name'} );

SKIP: {
			skip( "undefined packet", 5 )
					unless ok( $packet, "$method( $test->{'name'} )" );
			ok( $packet->isa('Net::DNS::Packet'), "$method returns Net::DNS::Packet" );

			my $from = $packet->answerfrom || '';
			my $header = $packet->header;
			skip( join( ' ', "Empty response from $from", "RCODE:", $header->rcode ), 3 )
					unless ok( $header->ancount, "Received answer" );

			is( $header->ancount, 1, "Correct answer count (with $method)" );

			my ($rr) = $packet->answer;

			ok( $rr->isa('Net::DNS::RR::A'), 'answer is Net::DNS::RR::A' );
			is( lc( $rr->name ), 'a.t.net-dns.org', "Correct name (with $method)" );
		}
	}


	my $socket = $res->bgsend( 'a.t.net-dns.org', 'A' );
	diag( join ' ', 'Error:', $res->errorstring, 'Socket ref:', ref($socket) )
			unless ok( ref($socket) =~ /^IO::Socket::INET(6?)$/, "bgsend returns socket" );
	my $loop = 200000;
	while ( $loop-- ) { }					# burn CPU to get the socket ready

	$loop = 6;
	while ( $loop-- ) {
		last if $res->bgisready($socket);
		sleep(1);					# If burning CPU not sufficient
	}


	ok( $res->bgisready($socket), "Socket is ready" );
SKIP: {
		skip( "undefined socket", 7 ) unless $res->bgisready($socket);
		$res->debug(0);
		my $packet = $res->bgread($socket);

		skip( "undefined packet", 6 )
				unless ok( $packet, "bgread( socket )" );

		my $header = $packet->header;
		my $from   = $packet->answerfrom || '';
		my $size   = $packet->answersize || '';
		ok( $from, "answerfrom defined $from" );
		ok( $size, "answersize defined $size" );

		undef $socket;
		skip( join( ' ', "Empty response from $from", "RCODE:", $header->rcode ), 3 )
				unless ok( $header->ancount, "Received answer" );

		is( $header->ancount, 1, "Correct answer count" );

		my ($rr) = $packet->answer;

		ok( $rr->isa('Net::DNS::RR::A'), 'answer is Net::DNS::RR::A' );
		is( lc( $rr->name ), 'a.t.net-dns.org', "Correct name" );
	}
}


#
# test the search() and query() append the default domain and
# searchlist correctly.
#
{
	my $res = Net::DNS::Resolver->new(
		domain	       => 't.net-dns.org',
		searchlist     => ['t.net-dns.org', 'net-dns.org'],
		udp_timeout    => 3,
		tcp_timeout    => 3,
		defnames       => 1,
		dnsrch	       => 1,
		persistent_udp => 1,
		);

	my @tests = (
		{	method => 'query',
			name   => 'a',
			},
		{	method => 'search',
			name   => 'a',
			},
		{	method => 'search',
			name   => 'a.t',
			},
		);

	$res->send("a.t.net-dns.org A");

	my $sock_id = $res->{'sockets'}[AF_INET]{"UDP"};

	foreach my $test (@tests) {
SKIP: {
			my $method = $test->{'method'};
			my $packet = $res->$method( $test->{'name'} );

			skip( "undefined UDP socket id", 7 )
					unless ok( $sock_id, "Persistent UDP socket identified" );
			is( $res->{'sockets'}[AF_INET]{"UDP"}, $sock_id, "Persistent socket matches" );

			skip( "undefined packet", 5 )
					unless ok( $packet, "$method( $test->{'name'} )" );
			ok( $packet->isa('Net::DNS::Packet'), "$method returns Net::DNS::Packet" );

			my $from = $packet->answerfrom || '';
			my $header = $packet->header;
			skip( join( ' ', "Empty response from $from", "RCODE:", $header->rcode ), 3 )
					unless ok( $header->ancount, "Received answer" );

			is( $packet->header->ancount, 1, "Correct answer count ($method with persistent socket)" );
			my ($rr) = $packet->answer;

			ok( $rr->isa('Net::DNS::RR::A'), 'answer is Net::DNS::RR::A' );
			is( lc( $rr->name ), 'a.t.net-dns.org', "Correct name ($method with persistent socket)" );
		}
	}
}


NonFatalEnd();

exit;

