package Net::DNS::Resolver::Base;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use integer;
use Carp;
use Socket;

use Net::DNS::RR;
use Net::DNS::Packet;

use constant INT16SZ  => 2;
use constant PACKETSZ => 512;

#
#  Implementation notes wrt IPv6 support when using perl before 5.20.0.
#
#  In general we try to be gracious to those stacks that do not have IPv6 support.
#  We test that by means of the availability of IO::Socket::INET6
#
#  We have chosen not to use mapped IPv4 addresses, there seem to be
#  issues with this; as a result we use separate sockets for each
#  family type.
#
#  inet_pton is not available on WIN32, so we only use the getaddrinfo
#  call to translate IP addresses to socketaddress
#
#  Three configuration flags, force_v4, prefer_v6 and force_v6,
#  are provided to control IPv6 behaviour for test purposes.
#
# Olaf Kolkman, RIPE NCC, December 2003.


use constant USE_SOCKET => defined eval {
	require IO::Select;
	require IO::Socket;
	import IO::Socket;
};

use constant USE_SOCKET_IP => defined eval { require IO::Socket::IP; };

use constant USE_SOCKET_INET => defined eval { require IO::Socket::INET; };

use constant USE_SOCKET_INET6 => defined eval { require IO::Socket::INET6; };

use constant IPv4 => USE_SOCKET_IP || USE_SOCKET_INET;
use constant IPv6 => USE_SOCKET_IP || USE_SOCKET_INET6;


# If SOCKSified Perl, use TCP instead of UDP and keep the socket open.
use constant SOCKS => scalar eval { require Config; $Config::Config{usesocks}; };


use constant UTIL => defined eval { require Scalar::Util; };

sub _tainted { UTIL ? Scalar::Util::tainted(shift) : undef }

sub _untaint {
	map { m/^(.*)$/; $1 } grep defined, @_;
}


#
# Set up a closure to be our class data.
#
{
	my $defaults = bless {
		nameserver4	=> ['127.0.0.1'],
		nameserver6	=> ( IPv6 ? ['::1'] : [] ),
		port		=> 53,
		srcaddr		=> 0,
		srcport		=> 0,
		searchlist	=> [],
		retrans		=> 5,
		retry		=> 4,
		usevc		=> ( SOCKS ? 1 : 0 ),
		igntc		=> 0,
		recurse		=> 1,
		defnames	=> 1,
		dnsrch		=> 1,
		debug		=> 0,
		errorstring	=> 'unknown error or no error',
		tsig_rr		=> undef,
		answerfrom	=> '',
		tcp_timeout	=> 120,
		udp_timeout	=> 30,
		persistent_tcp	=> ( SOCKS ? 1 : 0 ),
		persistent_udp	=> 0,
		dnssec		=> 0,
		adflag		=> 0,	# see RFC6840, 5.7
		cdflag		=> 0,	# see RFC6840, 5.9
		udppacketsize	=> 0,	# value bounded below by PACKETSZ
		force_v4	=> 0,	# only relevant if IPv6 is supported
		force_v6	=> 0,	#
		prefer_v6	=> 0,	# prefer v6, otherwise prefer v4
		},
			__PACKAGE__;


	sub _defaults { return $defaults; }
}


# These are the attributes that the user may specify in the new() constructor.
my %public_attr = map { $_ => $_ } qw(
		nameserver
		nameservers
		port
		srcaddr
		srcport
		domain
		searchlist
		retrans
		retry
		usevc
		igntc
		recurse
		defnames
		dnsrch
		debug
		tcp_timeout
		udp_timeout
		persistent_tcp
		persistent_udp
		dnssec
		adflag
		cdflag
		prefer_v4
		prefer_v6

		ignqrid
		stayopen
		);


my $initial;

sub new {
	my ( $class, %args ) = @_;

	my $self;
	my $base = $class->_defaults;
	my $init = $initial;
	$initial ||= bless {%$base}, $class;
	if ( my $file = $args{config_file} ) {
		$self = bless {%$initial}, $class;
		$self->_read_config_file($file);		# user specified config
		$self->nameservers( _untaint $self->nameservers );
		$self->searchlist( _untaint $self->searchlist );
		%$base = %$self unless $init;			# define default configuration

	} elsif ($init) {
		$self = bless {%$base}, $class;

	} else {
		$class->_init();				# define default configuration
		$self = bless {%$base}, $class;
	}

	while ( my ( $attr, $value ) = each %args ) {
		next unless $public_attr{$attr};
		my $ref = ref($value);
		croak "usage: $class->new( $attr => [...] )"
				if $ref && ( $ref ne 'ARRAY' );
		$self->$attr( $ref ? @$value : $value );
	}

	return $self;
}


my %resolv_conf = (			## map traditional resolv.conf option names
	attempts => 'retry',
	inet6	 => 'prefer_v6',
	timeout	 => 'retrans',
	);

my %env_option = (			## any resolver attribute except as listed below
	%public_attr,
	%resolv_conf,
	map { $_ => 0 } qw(nameserver nameservers domain searchlist),
	);

sub _read_env {				## read resolver config environment variables
	my $self = shift;

	$self->nameservers( map split, $ENV{RES_NAMESERVERS} ) if exists $ENV{RES_NAMESERVERS};

	$self->domain( $ENV{LOCALDOMAIN} ) if exists $ENV{LOCALDOMAIN};

	$self->searchlist( map split, $ENV{RES_SEARCHLIST} ) if exists $ENV{RES_SEARCHLIST};

	if ( exists $ENV{RES_OPTIONS} ) {
		foreach ( map split, $ENV{RES_OPTIONS} ) {
			my ( $name, $val ) = split( m/:/, $_, 2 );
			my $attribute = $env_option{$name} || next;
			$val = 1 unless defined $val;
			$self->$attribute($val);
		}
	}
}


sub _read_config_file {			## read resolver config file
	my $self = shift;
	my $file = shift;

	my @ns;

	local *FILE;

	open( FILE, $file ) or croak "Could not open $file: $!";

	local $_;
	while (<FILE>) {
		s/[;#].*$//;					# strip comments

		/^nameserver/ && do {
			my ( $keyword, @ip ) = grep defined, split;
			push @ns, @ip;
			next;
		};

		/^option/ && do {
			my ( $keyword, @option ) = grep defined, split;
			foreach (@option) {
				my ( $name, $val ) = split( m/:/, $_, 2 );
				my $attribute = $resolv_conf{$name} || next;
				$val = 1 unless defined $val;
				$self->$attribute($val);
			}
			next;
		};

		/^domain/ && do {
			my ( $keyword, $domain ) = grep defined, split;
			$self->domain($domain);
			next;
		};

		/^search/ && do {
			my ( $keyword, @searchlist ) = grep defined, split;
			$self->searchlist(@searchlist);
			next;
		};
	}

	close(FILE);

	$self->nameservers(@ns);
}


sub string {
	my $self = shift;
	$self = $self->_defaults unless ref($self);

	my $IP6line = "prefer_v6\t= $self->{prefer_v6}\tforce_v6\t= $self->{force_v6}";
	my $IP6conf = IPv6 ? $IP6line : '(no IPv6 transport)';
	my @nslist  = $self->nameservers();
	my $domain  = $self->domain;
	return <<END;
;; RESOLVER state:
;; domain	= $domain
;; searchlist	= @{$self->{searchlist}}
;; nameservers	= @nslist
;; defnames	= $self->{defnames}	dnsrch		= $self->{dnsrch}
;; retrans	= $self->{retrans}	retry		= $self->{retry}
;; recurse	= $self->{recurse}	igntc		= $self->{igntc}
;; usevc	= $self->{usevc}	port		= $self->{port}
;; srcaddr	= $self->{srcaddr}	srcport		= $self->{srcport}
;; tcp_timeout	= $self->{tcp_timeout}	persistent_tcp	= $self->{persistent_tcp}
;; udp_timeout	= $self->{udp_timeout}	persistent_udp	= $self->{persistent_udp}
;; debug	= $self->{debug}	force_v4	= $self->{force_v4}
;; $IP6conf
END

}


sub print { print &string; }


sub domain {
	my $self   = shift;
	my ($head) = $self->searchlist(@_);
	my @list   = grep defined, $head;
	wantarray ? @list : "@list";
}

sub searchlist {
	my $self = shift;
	$self = $self->_defaults unless ref($self);

	return $self->{searchlist} = [@_] unless defined wantarray;
	$self->{searchlist} = [@_] if scalar @_;
	my @searchlist = @{$self->{searchlist}};
}


sub nameservers {
	my $self = shift;
	$self = $self->_defaults unless ref($self);

	my ( @ipv4, @ipv6 );
	foreach my $ns ( grep defined, @_ ) {
		do { push @ipv6, $ns; next } if _ip_is_ipv6($ns);
		do { push @ipv4, $ns; next } if _ip_is_ipv4($ns);

		my $defres = ref($self)->new( debug => $self->{debug} );
		$defres->{persistent} = $self->{persistent};

		my $names  = {};
		my $packet = $defres->search( $ns, 'A' );
		my @iplist = _cname_addr( $packet, $names );

		if (IPv6) {
			$packet = $defres->search( $ns, 'AAAA' );
			push @iplist, _cname_addr( $packet, $names );
		}

		$self->errorstring( $defres->errorstring );

		my %address = map { ( $_ => $_ ) } @iplist;	# tainted
		my @unique = values %address;
		carp "unresolvable name: $ns" unless @unique;
		push @ipv4, grep _ip_is_ipv4($_), @unique;
		push @ipv6, grep _ip_is_ipv6($_), @unique;
	}

	unless ( defined wantarray ) {
		$self->{nameserver4} = \@ipv4;
		$self->{nameserver6} = \@ipv6 if IPv6;
		return;
	}

	if ( scalar @_ ) {
		$self->{nameserver4} = \@ipv4;
		$self->{nameserver6} = \@ipv6 if IPv6;
	}

	my @ns4 = $self->force_v6 ? () : @{$self->{nameserver4}};
	my @ns6 = $self->force_v4 ? () : @{$self->{nameserver6}};
	my @returnval = $self->prefer_v6 ? ( @ns6, @ns4 ) : ( @ns4, @ns6 );

	return @returnval if scalar @returnval;

	my $error = 'no nameservers';
	$error = 'IPv4 transport disabled' if scalar(@ns4) < scalar @{$self->{nameserver4}};
	$error = 'IPv6 transport disabled' if scalar(@ns6) < scalar @{$self->{nameserver6}};
	$self->errorstring($error);
	return @returnval;
}

sub nameserver { &nameservers; }				# uncoverable pod

sub _cname_addr {

	# TODO 20081217
	# This code does not follow CNAME chains, it only looks inside the packet.
	# Out of bailiwick will fail.
	my @addr;
	my $packet = shift || return @addr;
	my $names = shift;

	map $names->{$_->qname}++, $packet->question;
	map $names->{$_->cname}++, grep $_->can('cname'), $packet->answer;

	foreach my $rr ( grep $names->{$_->name}, $packet->answer ) {
		push( @addr, $rr->address ) if $rr->can('address');
	}

	return @addr;
}


# if ($self->{udppacketsize} > PACKETSZ
# then we use EDNS and $self->{udppacketsize}
# should be taken as the maximum packet_data length
sub _packetsz {
	my $udpsize = shift->{udppacketsize} || 0;
	return $udpsize > PACKETSZ ? $udpsize : PACKETSZ;
}

sub answerfrom {
	my $self = shift;
	$self->{answerfrom} = shift if scalar @_;
	return $self->{answerfrom};
}

sub errorstring {
	my $self = shift;
	$self->{errorstring} = shift if scalar @_;
	return $self->{errorstring};
}

sub _reset_errorstring {
	my $self = shift;

	$self->errorstring( $self->_defaults->{errorstring} );
}


sub search {
	my $self = shift;
	my $name = shift || '.';

	# resolve name by trying as absolute name, then applying searchlist
	my @defdomain = ( $self->{defnames} ? $self->domain : (), undef );
	my @searchlist = $self->{dnsrch} ? ( undef, @{$self->{searchlist}} ) : @defdomain;

	# resolve name with no dots or colons by applying searchlist
	my @list = $name =~ m/[:.]/ ? (undef) : @searchlist;

	foreach my $suffix (@list) {
		my $fqname = $suffix ? join( '.', $name, $suffix ) : $name;

		$self->_diag( 'search(', $fqname, @_, ')' );

		my $packet = $self->send( $fqname, @_ );

		next unless $packet && $packet->header->rcode eq "NOERROR";
		return $packet if $packet->header->ancount;	# answer found
	}

	return undef;
}


sub query {
	my $self = shift;
	my $name = shift || '.';

	# resolve name containing no dots or colons by appending domain
	my $fqdn = $name !~ /[:.]/ && $self->{defnames} ? join( '.', $name, $self->domain ) : $name;

	$self->_diag( 'query(', $fqdn, @_, ')' );

	my $packet = $self->send( $fqdn, @_ );

	return $packet && $packet->header->ancount ? $packet : undef;
}


sub send {
	my $self	= shift;
	my $packet	= $self->_make_query_packet(@_);
	my $packet_data = $packet->data;

	my $ans;

	if ( $self->{usevc} || length $packet_data > $self->_packetsz ) {

		$ans = $self->_send_tcp( $packet, $packet_data );

	} else {
		$ans = $self->_send_udp( $packet, $packet_data );
		return $ans if $self->{igntc};

		if ( $ans && $ans->header->tc ) {
			$self->_diag('packet truncated: retrying using TCP');
			$ans = $self->_send_tcp( $packet, $packet_data );
		}
	}

	return $ans;
}


sub _send_tcp {
	my ( $self, $packet, $packet_data ) = @_;

	my $length = length $packet_data;
	$self->_reset_errorstring;
	my @ns = $self->nameservers();
	my $lastanswer;

	foreach my $ns (@ns) {
		my $sock = $self->_create_tcp_socket($ns) || next;

		$self->_diag( 'tcp send:', $length, 'bytes' );

		unless ( $sock->send( pack 'n a*', $length, $packet_data ) ) {
			$self->_diag( $self->errorstring($!) );
			next;
		}

		my $sel	    = IO::Select->new($sock);
		my $timeout = $self->{tcp_timeout};
		if ( $sel->can_read($timeout) ) {
			my $buf = _read_tcp( $sock, INT16SZ );
			next unless length($buf);		# failed to get anything
			my $len = unpack 'n', $buf;
			next unless $len;			# cannot determine size

			unless ( $sel->can_read($timeout) ) {
				$self->_diag( $self->errorstring('timeout') );
				next;
			}

			$buf = _read_tcp( $sock, $len );
			$self->answerfrom($ns);

			my $received = length $buf;
			$self->_diag( 'received', $received, 'bytes' );

			unless ( $received == $len ) {
				$self->errorstring("expected $len bytes, received $received");
				next;
			}

			my $ans = Net::DNS::Packet->new( \$buf, $self->{debug} );

			unless ( defined $ans ) {
				$self->errorstring($@);
			} else {
				my $rcode = $ans->header->rcode;
				$self->errorstring( $@ || $rcode );

				$ans->answerfrom($ns);

				if ( $rcode ne "NOERROR" && $rcode ne "NXDOMAIN" ) {
					$self->_diag("RCODE: $rcode; try next nameserver");
					$lastanswer = $ans;
					next;
				}
			}
			return $ans;
		} else {
			$self->errorstring('timeout');
		}
	}

	if ($lastanswer) {
		$self->errorstring( $lastanswer->header->rcode );
		return $lastanswer;
	}

	$self->_diag( $self->errorstring );
	return;
}


sub _send_udp {
	my ( $self, $packet, $packet_data ) = @_;

	$self->_reset_errorstring;

	# Constructing an array of arrays that contain 3 elements:
	# The socket, IP address and dst_sockaddr
	my $port = $self->{port};
	my $sel	 = IO::Select->new();
	my @ns;

	foreach my $ip ( $self->nameservers ) {
		my $socket = $self->_create_udp_socket($ip) || next;
		my $dst_sockaddr = $self->_create_dst_sockaddr( $ip, $port ) || next;
		push @ns, [$socket, $ip, $dst_sockaddr];
	}

	my $retrans = $self->{retrans};
	my $retry   = $self->{retry};
	my $servers = scalar(@ns);
	my $timeout = $servers ? do { no integer; $retrans / $servers } : 0;

	my $lastanswer;

	# Perform each round of retries.
RETRY: for ( 0 .. $retry ) {

		# Try each nameserver.
NAMESERVER: foreach my $ns (@ns) {
			my ( $socket, $ip, $dst_sockaddr, $failed ) = @$ns;
			next if $failed;

			$self->_diag("udp send [$ip]:$port");

			unless ( $socket->send( $packet_data, 0, $dst_sockaddr ) ) {
				$self->_diag( $ns->[3] = $self->errorstring($!) );
				next;
			}

			# handle failure to detect taint inside socket->send()
			die 'Insecure dependency while running with -T switch'
					if _tainted($dst_sockaddr);

			$sel->add($ns);

			my @ready = $sel->can_read($timeout);
			foreach my $ready (@ready) {
				my ( $socket, $ip ) = @$ready;
				$sel->remove($ready);

				my $buf = '';
				unless ( $socket->recv( $buf, $self->_packetsz ) ) {
					$self->_diag( "recv ERROR [$ip]", $ns->[3] = $self->errorstring($!) );
					next;
				}

				my $peerhost = $socket->peerhost;
				$self->answerfrom($peerhost);
				$self->_diag( "answer from [$peerhost]", 'length', length($buf) );

				next unless $peerhost eq $ip;

				my $ans = Net::DNS::Packet->new( \$buf, $self->{debug} );
				my $error = $@;

				unless ( defined $ans ) {
					$self->errorstring($error);
				} else {
					my $header = $ans->header;
					my $rcode  = $header->rcode;
					$ans->answerfrom($peerhost);

					next unless $header->qr;
					next unless $header->id == $packet->header->id;

					$self->errorstring( $error || $rcode );

					if ( $rcode ne "NOERROR" && $rcode ne "NXDOMAIN" ) {
						my $msg = $ns->[3] = "RCODE: $rcode";
						$self->_diag("$msg; try next nameserver");
						$lastanswer = $ans;
						next NAMESERVER;
					}
				}
				return $ans;
			}					#SELECTOR LOOP
		}						#NAMESERVER LOOP
		no integer;
		$timeout += $timeout;
	}							#RETRY LOOP

	my $error = scalar( $sel->handles ) ? 'query timed out' : $self->errorstring;
	$error = $lastanswer->header->rcode if $lastanswer;
	$self->_diag( $self->errorstring($error) );
	return $lastanswer;
}


sub bgsend {
	my $self = shift;

	my $packet = $self->_make_query_packet(@_);

	return $self->_bgsend_tcp( $packet, $packet->data ) if $self->{usevc};
	return $self->_bgsend_udp( $packet, $packet->data );
}


sub _bgsend_tcp {
	my ( $self, $packet, $packet_data ) = @_;

	$self->_reset_errorstring;

	my $port = $self->{port};

	foreach my $ns ( $self->nameservers ) {
		my $socket = $self->_create_tcp_socket($ns) || next;

		$self->_diag( 'bgsend', "[$ns]:$port" );

		my $length = length $packet_data;
		my $tcp_packet = pack 'n a*', $length, $packet_data;

		unless ( $socket->send($tcp_packet) ) {
			$self->errorstring("send: [$ns]:$port  $!");
			next;
		}

		my $expire = time() + $self->{tcp_timeout} || 0;
		return IO::Select->new( [$socket, $expire, $ns, $packet->header->id] );
	}

	$self->_diag( $self->errorstring );
	return undef;
}


sub _bgsend_udp {
	my ( $self, $packet, $packet_data ) = @_;

	$self->_reset_errorstring;

	my $port = $self->{port};

	foreach my $ns ( $self->nameservers ) {
		my $socket = $self->_create_udp_socket($ns) || next;

		my $dst_sockaddr = $self->_create_dst_sockaddr( $ns, $port ) || next;

		$self->_diag( 'bgsend', "[$ns]:$port" );

		unless ( $socket->send( $packet_data, 0, $dst_sockaddr ) ) {
			$self->errorstring("send: [$ns]:$port  $!");
			next;
		}

		# handle failure to detect taint inside $socket->send()
		die 'Insecure dependency while running with -T switch' if _tainted($dst_sockaddr);

		my $expire = time() + $self->{udp_timeout} || 0;
		return IO::Select->new( [$socket, $expire, $ns, $packet->header->id] );
	}

	$self->_diag( $self->errorstring );
	return undef;
}


sub bgisready {
	my $self = shift;
	my $sel = shift || return 1;

	return scalar( $sel->can_read(0.0) ) || do {
		return 0 unless $self->{udp_timeout};
		my $time = time();
		my ( $x, $expire ) = map @$_, $sel->handles, [0, $time - 1];
		$time > $expire;
	};
}


sub bgread {
	my $self = shift;
	my $sel = shift || return undef;

	my ($handle) = $sel->handles;
	my $time = time();
	my ( $socket, $expire, $ip, $id ) = map @$_, $sel->handles, [0, $time];

	my $timeout = $expire - $time;
	return undef unless $sel->can_read( $timeout > 0 ? $timeout : 0 );

	my $buffer;
	if ( $self->{usevc} ) {
		$buffer = _read_tcp( $socket, INT16SZ );
		return undef unless length($buffer);		# failed to get length
		my $len = unpack 'n', $buffer;
		return undef unless $len;			# can not determine size

		unless ( $sel->can_read( $self->{tcp_timeout} ) ) {
			$self->_diag( $self->errorstring('timeout') );
			return undef;
		}

		$buffer = _read_tcp( $socket, $len );
		$self->answerfrom($ip);				# $socket->peerhost unreliable
		$self->_diag("answer from [$ip]");

	} else {
		unless ( $socket->recv( $buffer, $self->_packetsz ) ) {
			$self->errorstring($!);
			return undef;
		}

		my $peerhost = $socket->peerhost;
		$self->answerfrom( $socket->peerhost );
		$self->_diag("answer from [$peerhost]");
		return undef unless $peerhost eq $ip;
	}


	my $ans = Net::DNS::Packet->new( \$buffer, $self->{debug} );

	unless ( defined $ans ) {
		$self->errorstring($@);
	} else {
		my $error  = $@;
		my $header = $ans->header;
		my $rcode  = $header->rcode;
		$self->errorstring( $error || $rcode );

		return undef unless $header->qr;
		return undef unless $header->id == $id;

		$ans->answerfrom( $self->answerfrom );
	}
	return $ans;
}


sub _make_query_packet {
	my $self = shift;
	my $packet;

	if ( ref( $_[0] ) and $_[0]->isa('Net::DNS::Packet') ) {
		$packet = shift;
	} else {
		$packet = Net::DNS::Packet->new(@_);
	}

	my $header = $packet->header;

	$header->rd( $self->{recurse} ) if $header->opcode eq 'QUERY';

	$header->ad(1) if $self->{adflag};			# RFC6840, 5.7
	$header->cd(1) if $self->{cdflag};			# RFC6840, 5.9

	if ( $self->dnssec ) {
		$self->_diag('Set EDNS DO flag');
		$header->ad(0);
		$header->do(1);
	}

	$packet->edns->size( $self->{udppacketsize} );		# advertise payload size for local stack

	if ( $self->{tsig_rr} && !grep $_->type eq 'TSIG', $packet->additional ) {
		$packet->sign_tsig( $self->{tsig_rr} );
	}

	return $packet;
}


sub axfr {				## zone transfer
	my $self = shift;

	my $query = $self->_axfr_start(@_);
	my $verfy = $query ? $query->sigrr : undef;
	my @rr;
	my $soa;

	my $iterator = sub {		## iterate over RRs
		my $rr = shift(@rr);
		return $rr if scalar @rr;

		if ( ( ref($rr) eq 'Net::DNS::RR::SOA' ) && ( $rr ne $soa ) ) {
			croak 'improperly terminated AXFR' unless $rr->encode eq $soa->encode;
			return $self->{axfr_sel} = undef;
		}

		my $reply = $self->_axfr_next() || return $rr;	# end of packet
		$verfy = $reply->verify($verfy) || croak $reply->verifyerr if $verfy;
		$self->_diag( $verfy ? 'verified' : 'not verified' );
		@rr = $reply->answer;
		return $rr;
	};

	$iterator->();						# read initial packet
	($soa) = @rr;

	return $iterator unless wantarray;

	my @zone = shift @rr;					# initial SOA
	my @null;

	until ( scalar(@rr) && $rr[$#rr]->type eq 'SOA' ) {
		push @zone, @rr;				# unpack non-terminal packet
		@rr = @null;
		my $reply = $self->_axfr_next() || last;
		$verfy = $reply->verify($verfy) || croak $reply->verifyerr if $verfy;
		$self->_diag( $verfy ? 'verified' : 'not verified' );
		@rr = $reply->answer;
	}

	my $last = pop @rr;					# unpack final packet
	push @zone, @rr;
	$self->{axfr_sel} = undef;
	return @zone if $last && $last->encode eq $soa->encode;
	croak 'improperly terminated AXFR';
}


sub axfr_start {			## historical
	my $self = shift;					# uncoverable pod
	my $iter = $self->{axfr_iter} = $self->axfr(@_);
	return defined($iter);
}


sub axfr_next {				## historical
	my $self = shift;					# uncoverable pod
	my $iter = $self->{axfr_iter} || return undef;
	$iter->() || return $self->{axfr_iter} = undef;
}


sub _axfr_start {
	my $self  = shift;
	my $dname = shift || $self->domain;
	my @class = @_;

	my $packet = $self->_make_query_packet( $dname, 'AXFR', @class );

	$self->_diag("axfr_start( $dname, @class )");

	foreach my $ns ( $self->nameservers ) {
		my $sock = $self->_create_tcp_socket($ns) || next;

		$self->_diag("axfr_start nameserver [$ns]");

		my $packet_data = $packet->data;
		my $TCP_msg = pack 'n a*', length($packet_data), $packet_data;

		unless ( $sock->send($TCP_msg) ) {
			$self->errorstring($!);
			next;
		}

		$self->{axfr_ns}  = $ns;
		$self->{axfr_sel} = IO::Select->new($sock);

		return $packet;
	}

	$self->_diag( $self->errorstring );
	return;
}


sub _axfr_next {
	my $self = shift;

	#--------------------------------------------------------------
	# Read the length of the response packet.
	#--------------------------------------------------------------

	my $select  = $self->{axfr_sel} || return;
	my $timeout = $self->{tcp_timeout};
	my @ready   = $select->can_read($timeout);
	unless (@ready) {
		$self->errorstring('timeout');
		return;
	}

	my $buf = _read_tcp( $ready[0], INT16SZ );
	unless ( length $buf ) {
		$self->errorstring('truncated zone transfer');
		return;
	}

	my ($len) = unpack( 'n', $buf );
	unless ($len) {
		$self->errorstring('truncated zone transfer');
		return;
	}

	#--------------------------------------------------------------
	# Read the response packet.
	#--------------------------------------------------------------

	@ready = $select->can_read($timeout);
	unless (@ready) {
		$self->errorstring('timeout');
		return;
	}

	$buf = _read_tcp( $ready[0], $len );

	my $received = length $buf;
	$self->_diag( 'received', $received, 'bytes' );

	unless ( $received == $len ) {
		$self->_diag( $self->errorstring("expected $len bytes, received $received") );
		return;
	}

	my $ans = Net::DNS::Packet->new( \$buf, $self->{debug} );

	if ($ans) {
		$ans->answerfrom( $self->{axfr_ns} );

		my $rcode = $ans->header->rcode;
		unless ( $rcode eq 'NOERROR' ) {
			$self->_diag( $self->errorstring("RCODE from server: $rcode") );
			return;
		}

	} else {
		my $err = $@ || 'unknown error during packet parsing';
		$self->_diag( $self->errorstring($err) );
		return;
	}

	return $ans;
}


sub tsig {
	my $self = shift;

	return $self->{tsig_rr} unless scalar @_;
	$self->{tsig_rr} = eval {
		local $SIG{__DIE__};
		require Net::DNS::RR::TSIG;
		Net::DNS::RR::TSIG->create(@_);
	} || undef;
	croak "$@ unable to create TSIG record" if $@;
}


sub dnssec {
	my $self = shift;

	return $self->{dnssec} unless scalar @_;

	# increase default udppacket size if flag set
	$self->udppacketsize(2048) if $self->{dnssec} = shift;

	return $self->{dnssec};
}


#
# Usage:  $data = _read_tcp($socket, $nbytes);
#
sub _read_tcp {
	my ( $sock, $nbytes ) = @_;
	my $buf = '';

	while ( ( my $unread = $nbytes - length $buf ) > 0 ) {

		# During some of my tests recv() returned undef even
		# though there wasn't an error.	 Checking for the amount
		# of data read appears to work around that problem.

		my $read_buf = '';
		unless ( $sock->recv( $read_buf, $unread ) ) {
			if ( length($read_buf) < 1 ) {
				warn "ERROR: tcp recv failed: $!\n" if $!;
				last;
			}
		}

		$buf .= $read_buf if length($read_buf);
	}

	return $buf;
}


sub _create_tcp_socket {
	my $self = shift;
	my $ns	 = shift;

	my $dstport  = $self->{port};
	my $sock_key = "[$ns]:$dstport";
	my $sock;

	if ( $self->{persistent_tcp} ) {
		$sock = $self->{persistent}{$sock_key};
		$self->_diag( 'using persistent socket', $sock_key ) if $sock;
		return $sock if $sock && $sock->connected;
		$self->_diag('socket disconnected (trying to connect)');
	}

	my $srcaddr = $self->{srcaddr};
	my $srcport = $self->{srcport};
	my $timeout = $self->{tcp_timeout};

	if ( IPv6 && _ip_is_ipv6($ns) ) {
		my $localaddr = $srcaddr =~ /[:].*[:]/ ? $srcaddr : '::';

		$sock = IO::Socket::IP->new(
			LocalAddr => $localaddr,
			LocalPort => $srcport,
			PeerAddr  => $ns,
			PeerPort  => $dstport,
			Proto	  => 'tcp',
			Timeout	  => $timeout,
			)
				if USE_SOCKET_IP;

		$sock = IO::Socket::INET6->new(
			LocalAddr => $localaddr,
			LocalPort => ( $srcport || undef ),
			PeerAddr  => $ns,
			PeerPort  => $dstport,
			Proto	  => 'tcp',
			Timeout	  => $timeout,
			)
				unless USE_SOCKET_IP;
	} else {
		my $localaddr = $srcaddr =~ /[.].*[.]/ ? $srcaddr : '0.0.0.0';

		$sock = IO::Socket::IP->new(
			LocalAddr => $localaddr,
			LocalPort => $srcport,
			PeerAddr  => $ns,
			PeerPort  => $dstport,
			Proto	  => 'tcp',
			Timeout	  => $timeout,
			)
				if USE_SOCKET_IP;

		$sock = IO::Socket::INET->new(
			LocalAddr => $localaddr,
			LocalPort => ( $srcport || undef ),
			PeerAddr  => $ns,
			PeerPort  => $dstport,
			Proto	  => 'tcp',
			Timeout	  => $timeout
			)
				unless USE_SOCKET_IP;
	}

	unless ($sock) {
		$self->_diag( $self->errorstring("connection failed [$ns]") );
	} elsif ( $self->{persistent_tcp} ) {
		$self->{persistent}{$sock_key} = $sock;
	}

	return $sock;
}


sub _create_udp_socket {
	my $self = shift;
	my $ns	 = shift;

	my $srcaddr = $self->{srcaddr};
	my $srcport = $self->{srcport};
	my $sock_key;
	my $sock;

	if ( IPv6 && _ip_is_ipv6($ns) ) {
		$sock_key = 'UDP/IPv6';
		return $sock if $sock = $self->{persistent}{$sock_key};

		my $localaddr = $srcaddr =~ /[:].*[:]/ ? $srcaddr : '::';

		$sock = IO::Socket::IP->new(
			LocalAddr => $localaddr,
			LocalPort => $srcport,
			Proto	  => 'udp',
			Type	  => SOCK_DGRAM,
			)
				if USE_SOCKET_IP;

		$sock = IO::Socket::INET6->new(
			LocalAddr => $localaddr,
			LocalPort => ( $srcport || undef ),
			Proto	  => 'udp',
			Type	  => SOCK_DGRAM,
			)
				unless USE_SOCKET_IP;
	} else {
		$sock_key = 'UDP/IPv4';
		return $sock if $sock = $self->{persistent}{$sock_key};

		my $localaddr = $srcaddr =~ /[.].*[.]/ ? $srcaddr : '0.0.0.0';

		$sock = IO::Socket::IP->new(
			LocalAddr => $localaddr,
			LocalPort => $srcport,
			Proto	  => 'udp',
			Type	  => SOCK_DGRAM,
			)
				if USE_SOCKET_IP;

		$sock = IO::Socket::INET->new(
			LocalAddr => $localaddr,
			LocalPort => ( $srcport || undef ),
			Proto	  => 'udp',
			Type	  => SOCK_DGRAM,
			)
				unless USE_SOCKET_IP;
	}

	$self->_diag( $self->errorstring( 'could not get', $sock_key, 'socket' ) ) unless $sock;
	return $self->{persistent}{$sock_key} = $sock if $self->{persistent_udp};
	return $sock;
}


sub _create_dst_sockaddr {		## create UDP destination sockaddr structure
	my ( $self, $ip, $port ) = @_;

	unless ( IPv6 && _ip_is_ipv6($ip) ) {
		return sockaddr_in( $port, inet_aton($ip) );

	} elsif (USE_SOCKET_INET6) {
		no strict;
		local $^W = 0;					# circumvent perl -w warnings

		my @res = Socket6::getaddrinfo( $ip, $port, AF_INET6, SOCK_DGRAM, 0, AI_NUMERICHOST );
		if ( scalar(@res) < 5 ) {
			my ($error) = @res;
			$self->errorstring("send: $ip\t$error");
			return;
		}

		return $res[3];

	} elsif (USE_SOCKET_IP) {
		no strict;
		my $addr = Socket::inet_pton( AF_INET6, $ip );
		return sockaddr_in6( $port, $addr );
	}
}


# Lightweight versions of subroutines from Net::IP module, recoded to fix RT#96812

sub _ip_is_ipv4 {
	for (shift) {
		return /^[0-9.]+\.[0-9]+$/;			# dotted digits
	}
}

sub _ip_is_ipv6 {
	for (shift) {
		return 1 if /^[:0-9a-f]+:[0-9a-f]*$/i;		# mixed : and hexdigits
		return 1 if /^[:0-9a-f]+:[0-9.]+$/i;		# prefix + dotted digits
		return /^[:0-9a-f]+:[0-9a-f]*[%].+$/i;		# RFC4007 scoped address
	}
}


sub force_v4 {
	my $self = shift;
	return $self->{force_v4} unless scalar @_;
	my $value = shift;
	$self->force_v6(0) if $value;
	$self->{force_v4} = $value ? 1 : 0;
}

sub force_v6 {
	my $self = shift;
	return $self->{force_v6} unless scalar @_;
	my $value = shift;
	$self->force_v4(0) if $value;
	$self->{force_v6} = $value ? 1 : 0;
}

sub prefer_v4 {
	my $self = shift;
	return $self->{prefer_v6} ? 0 : 1 unless scalar @_;
	my $value = shift;
	$self->{prefer_v6} = $value ? 0 : 1;
	return $value;
}

sub prefer_v6 {
	my $self = shift;
	return $self->{prefer_v6} unless scalar @_;
	$self->{prefer_v6} = shift() ? 1 : 0;
}


sub udppacketsize {
	my $self = shift;
	$self->{udppacketsize} = shift if scalar @_;
	return $self->_packetsz;
}


#
# Keep this method around. Folk depend on it although it is neither documented nor exported.
#
my $warned;

sub make_query_packet {			## historical
	carp 'deprecated method; see RT#37104' unless $warned++;
	&_make_query_packet;					# uncoverable pod
}


sub _diag {				## debug output
	my $self = shift;
	print "\n;; @_\n" if $self->{debug};
}


use vars qw($AUTOLOAD);

sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)

sub AUTOLOAD {				## Default method
	my ($self) = @_;

	my $name = $AUTOLOAD;
	$name =~ s/.*://;
	croak "$name: no such method" unless $public_attr{$name};

	no strict q/refs/;
	*{$AUTOLOAD} = sub {
		my $self = shift;
		$self = $self->_defaults unless ref($self);
		$self->{$name} = shift if scalar @_;
		return $self->{$name};
	};

	goto &{$AUTOLOAD};
}


1;

__END__


=head1 NAME

Net::DNS::Resolver::Base - DNS resolver base class

=head1 SYNOPSIS

    use base qw(Net::DNS::Resolver::Base);

=head1 DESCRIPTION

This class is the common base class for the different platform
sub-classes of L<Net::DNS::Resolver>.

No user serviceable parts inside, see L<Net::DNS::Resolver>
for all your resolving needs.


=head1 METHODS

=head2 new, domain, searchlist, nameservers, print, string, errorstring,

=head2 search, query, send, bgsend, bgisready, bgread, axfr, answerfrom,

=head2 force_v4, force_v6, prefer_v4, prefer_v6, udppacketsize, dnssec, tsig

See L<Net::DNS::Resolver>.


=head1 COPYRIGHT

Copyright (c)2003,2004 Chris Reinhardt.

Portions Copyright (c)2005 Olaf Kolkman.

Portions Copyright (c)2014,2015 Dick Franks.

All rights reserved.


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation, and that the name of the author not be used in advertising
or publicity pertaining to distribution of the software without specific
prior written permission.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Resolver>

=cut

