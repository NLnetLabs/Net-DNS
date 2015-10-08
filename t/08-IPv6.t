# $Id$ -*-perl-*-

use strict;
use Test::More;
use t::NonFatal;

use Net::DNS;

my $debug = 0;

my @hints = qw(
		2001:500:2::c
		2001:7fd::1
		2001:500:3::42
		2001:503:c27::2:30
		2001:500:84::b
		2001:500:1::803f:235
		2001:500:2d::d
		2001:503:ba3e::2:30
		2001:500:2f::f
		2001:7fe::53
		2001:dc3::35
		);


exit( plan skip_all => 'Online tests disabled.' ) if -e 't/IPv6.disabled';
exit( plan skip_all => 'Online tests disabled.' ) unless -e 't/IPv6.enabled';


eval {
	my $res = new Net::DNS::Resolver();
	exit plan skip_all => 'No nameservers' unless $res->nameservers;

	my $reply = $res->send( '.', 'NS' ) || return 0;

	my @ns = grep $_->type eq 'NS', $reply->answer, $reply->authority;
	exit plan skip_all => 'Local nameserver broken' unless scalar @ns;

	1;
} || exit( plan skip_all => 'Non-responding local nameserver' );


eval {
	my $res = new Net::DNS::Resolver( nameservers => [@hints] );
	exit plan skip_all => 'No IPv6 transport' unless $res->nameservers;

	my $reply = $res->send( '.', 'NS' ) || return 0;

	my @ns = grep $_->type eq 'NS', $reply->answer, $reply->authority;
	exit plan skip_all => 'Unexpected response from root server' unless scalar @ns;

	1;
} || exit( plan skip_all => 'Unable to access global root nameservers' );


plan tests => 20;


NonFatalBegin();


my $res = Net::DNS::Resolver->new( prefer_v6 => 1 );

my $IP;


# query local nameserver using any available transport
my $nsanswer = $res->send( 'net-dns.org', 'NS', 'IN' );
is( ( $nsanswer->answer )[0]->type, 'NS', 'got NS records for net-dns.org' );

foreach my $ns ( $nsanswer->answer ) {

	# assume any net-dns.org nameserver will do
	my $qtype = 'AAAA';
	my $reply = $res->send( $ns->nsdname, $qtype, 'IN' ) || next;
	next unless $reply->header->ancount;
	my @answer = $reply->answer;
	my @rr = grep $_->type eq $qtype, @answer;
	($IP) = map $_->address, @rr;
	diag join ' ', "\n\t\twill try", $ns->nsdname, "($IP)" if $debug;
	last;
}

ok( defined($IP), 'got IP address of nameserver' );


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	ok( $reply, 'UDP/IPv6 reply received' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), "Net::DNS::RR::$qtype", 'UDP/IPv6 query succeeded' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->force_v4(1);

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	is( $res->errorstring, 'IPv6 transport disabled', 'force_v4(1) gives error' );
	ok( !$reply, 'no UDP/IPv6 reply received' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->usevc(1);

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	ok( $reply, 'TCP/IPv6 reply received' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), 'Net::DNS::RR::SOA', 'TCP/IPv6 query succeeded' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->force_v4(1);
	$res->usevc(1);

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	is( $res->errorstring, 'IPv6 transport disabled', 'force_v4(1) gives error' );
	ok( !$reply, 'no TCP/IPv6 reply received' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );

	my $qtype = 'SOA';
	my $handle = $res->bgsend( 'net-dns.org', $qtype, 'IN' );
	ok( $handle, 'bgsend UDP/IPv6' );
	until ( $res->bgisready($handle) ) {
		sleep 1;
	}
	my $reply = $res->bgread($handle);
	ok( $reply, 'bgread UDP/IPv6' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), "Net::DNS::RR::$qtype", 'UDP/IPv6 query succeeded' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->usevc(1);

	my $qtype = 'SOA';
	my $handle = $res->bgsend( 'net-dns.org', $qtype, 'IN' );
	ok( $handle, 'bgsend TCP/IPv6' );
	until ( $res->bgisready($handle) ) {
		sleep 1;
	}
	my $reply = $res->bgread($handle);
	ok( $reply, 'bgread TCP/IPv6' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), "Net::DNS::RR::$qtype", 'TCP/IPv6 query succeeded' );
}


#
#  Now test AXFR functionality.
#
{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->tsig( 'MD5.example', 'ARDJZgtuTDzAWeSGYPAu9uJUkX0=' );
	my $iter = $res->axfr('example.com');
	is( ref($iter), 'CODE', 'axfr returns CODE ref' );
	my ($rr) = $iter->();
	is( $res->errorstring, 'RCODE from server: NOTAUTH', 'connection worked (NOTAUTH)' );

	ok( $res->axfr_start('example.com'), 'axfr_start	(historical)' );
	is( $res->axfr_next(), undef, 'axfr_next' );
}


NonFatalEnd();

exit;

__END__

