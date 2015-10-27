# $Id$ -*-perl-*-

use strict;
use Test::More;
use t::NonFatal;

use Net::DNS;

my $debug = 0;

my @hints = qw(
		198.41.0.4
		192.228.79.201
		192.33.4.12
		199.7.91.13
		192.203.230.10
		192.5.5.241
		192.112.36.4
		198.97.190.53
		192.36.148.17
		192.58.128.30
		193.0.14.129
		199.7.83.42
		202.12.27.33
		);


exit( plan skip_all => 'Online tests disabled.' ) if -e 't/online.disabled';
exit( plan skip_all => 'Online tests disabled.' ) unless -e 't/online.enabled';


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
	exit plan skip_all => 'No IPv4 transport' unless $res->nameservers;

	my $reply = $res->send( '.', 'NS' ) || return 0;

	my @ns = grep $_->type eq 'NS', $reply->answer, $reply->authority;
	exit plan skip_all => 'Unexpected response from root server' unless scalar @ns;

	1;
} || exit( plan skip_all => 'Unable to access global root nameservers' );


my $IP = eval {
	my $res	    = Net::DNS::Resolver->new( prefer_v4 => 1 );
	my $nsreply = $res->send(qw(net-dns.org NS IN)) || return 0;
	my @nsdname = map $_->nsdname, grep $_->type eq 'NS', $nsreply->answer;

	# assume any working net-dns.org nameserver will do
	$res->nameservers(@nsdname);
	$res->force_v4(1);
	my $test = $res->send(qw(net-dns.org NS IN)) || return 0;
	$test->answerfrom;
} || exit( plan skip_all => 'Unable to access target nameserver' );

diag join( ' ', "\n\t\twill use nameserver", $IP ) if $debug;


plan tests => 19;

NonFatalBegin();


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	ok( $reply, 'UDP/IPv4 reply received' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), "Net::DNS::RR::$qtype", 'UDP/IPv4 query succeeded' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->force_v6(1);

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	is( $res->errorstring, 'IPv4 transport disabled', 'force_v6(1) gives error' );
	ok( !$reply, 'no UDP/IPv4 reply received' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->usevc(1);

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	ok( $reply, 'TCP/IPv4 reply received' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), 'Net::DNS::RR::SOA', 'TCP/IPv4 query succeeded' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->force_v6(1);
	$res->usevc(1);

	my $qtype = 'SOA';
	my $reply = $res->send( 'net-dns.org', $qtype, 'IN' );
	is( $res->errorstring, 'IPv4 transport disabled', 'force_v6(1) gives error' );
	ok( !$reply, 'no TCP/IPv4 reply received' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );

	my $qtype = 'SOA';
	my $handle = $res->bgsend( 'net-dns.org', $qtype, 'IN' );
	ok( $handle, 'bgsend UDP/IPv4' );
	until ( $res->bgisready($handle) ) {
		sleep 1;
	}
	my $reply = $res->bgread($handle);
	ok( $reply, 'bgread UDP/IPv4' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), "Net::DNS::RR::$qtype", 'UDP/IPv4 query succeeded' );
}


{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->usevc(1);

	my $qtype = 'SOA';
	my $handle = $res->bgsend( 'net-dns.org', $qtype, 'IN' );
	ok( $handle, 'bgsend TCP/IPv4' );
	until ( $res->bgisready($handle) ) {
		sleep 1;
	}
	my $reply = $res->bgread($handle);
	ok( $reply, 'bgread TCP/IPv4' );
	my ($answer) = $reply->answer if $reply;
	is( ref($answer), "Net::DNS::RR::$qtype", 'TCP/IPv4 query succeeded' );
}


#
#  Now test AXFR functionality.
#
{
	my $res = Net::DNS::Resolver->new( nameserver => $IP );
	$res->tcp_timeout(10);
	$res->tsig( 'MD5.example', 'ARDJZgtuTDzAWeSGYPAu9uJUkX0=' );

	my $iter = $res->axfr('example.com');
	is( ref($iter), 'CODE', 'axfr returns CODE ref' );
	like( $res->errorstring, '/RCODE/', 'RCODE from server: NOTAUTH' );

	my @zone = eval { $res->axfr('example.com') };
	ok( $res->errorstring, 'axfr in list context' );

	ok( $res->axfr_start('example.com'), 'axfr_start	(historical)' );
	is( $res->axfr_next(), undef, 'axfr_next' );
}


NonFatalEnd();

exit;

__END__

