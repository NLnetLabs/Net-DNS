# $Id$	-*-perl-*-

use strict;
use Test::More tests => 12;

use Net::DNS::Resolver;

my $resolver = Net::DNS::Resolver->new();
my $class    = ref($resolver);


{					## exercise error paths in _accept_reply()
	my $query = new Net::DNS::Packet(qw(net-dns.org SOA IN));
	my $reply = new Net::DNS::Packet(qw(net-dns.org SOA IN));
	$reply->header->qr(1);

	ok( !$resolver->_accept_reply(undef), '_accept_reply()	no reply' );

	ok( !$resolver->_accept_reply($query), '_accept_reply()	qr not set' );

	ok( !$resolver->_accept_reply( $reply, $query ), '_accept_reply()	id mismatch' );

	ok( $resolver->_accept_reply( $reply, $reply ), '_accept_reply()	id match' );
	ok( $resolver->_accept_reply( $reply, undef ),	'_accept_reply()	query absent/undefined' );
}


{					## exercise error path in _cname_addr()
	is( scalar( Net::DNS::Resolver::Base::_cname_addr( undef, undef ) ), 0, '_cname_addr()  no reply packet' );
}


{					## exercise possibly unused socket code
					## check for smoke and flames only
	$resolver->persistent_udp(1);
	$resolver->persistent_tcp(1);
	$resolver->tcp_timeout(1);
	foreach my $ip (qw(127.0.0.1 ::1)) {
		eval { $resolver->_create_udp_socket($ip) };
		is( $@, '', "\$resolver->_create_udp_socket($ip)" );
		eval { $resolver->_create_dst_sockaddr( $ip, 53 ) };
		is( $@, '', "\$resolver->_create_dst_sockaddr($ip,53)" );
		eval { $resolver->_create_tcp_socket($ip) };
		is( $@, '', "\$resolver->_create_tcp_socket($ip)" );
	}
}


eval {					## exercise warning for make_query_packet()
	local *STDERR;
	my $filename = '01-resolver.tmp';
	open( STDERR, ">$filename" ) || die "Could not open $filename for writing";
	$resolver->make_query_packet('example.com');		# carp
	$resolver->make_query_packet('example.com');		# silent
	close(STDERR);
	unlink($filename);
};


exit;

__END__

