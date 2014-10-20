package Net::DNS::Resolver::Base;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use integer;
use Carp;
use Config ();
use Socket;
use IO::Socket;
use IO::Select;

use Net::DNS::RR;
use Net::DNS::Packet;

use constant DNSSEC => eval { require Net::DNS::RR::DNSKEY; } || 0;
use constant INT16SZ  => 2;
use constant PACKETSZ => 512;

use constant UTIL => eval { require Scalar::Util; } || 0;
sub tainted { return UTIL ? Scalar::Util::tainted(shift) : undef }
sub _untaint { map defined && /^(.+)$/ ? $1 : (), @_; }


#
#  A few implementation notes wrt IPv6 support.
#
#  In general we try to be gracious to those stacks that do not have IPv6 support.
#  We test that by means of the availability of Socket6 and IO::Socket::INET6
#


#  We have chosen to not use mapped IPv4 addresses, there seem to be
#  issues with this; as a result we have to use sockets for both
#  family types.  To be able to deal with persistent sockets and
#  sockets of both family types we use an array that is indexed by the
#  socketfamily type to store the socket handlers. I think this could
#  be done more efficiently.


#  inet_pton is not available on WIN32, so we only use the getaddrinfo
#  call to translate IP addresses to socketaddress


#  Three configuration flags, force_v4, prefer_v6 and force_v6,
#  are provided to control IPv6 behaviour for test purposes.


# Olaf Kolkman, RIPE NCC, December 2003.


use vars qw($has_inet6);

BEGIN {
	$has_inet6 = eval {
		require IO::Socket::INET6;
		IO::Socket::INET6->VERSION("2.01");
		1;
	} || 0;
}


#
# Set up a closure to be our class data.
#
{
	my %defaults = (
		nameserver4	=> ['127.0.0.1'],
		nameserver6	=> ['::1'],
		port		=> 53,
		srcaddr		=> '0.0.0.0',
		srcport		=> 0,
		domain		=> '',
		searchlist	=> [],
		retrans		=> 5,
		retry		=> 4,
		usevc		=> 0,
		stayopen	=> 0,
		igntc		=> 0,
		recurse		=> 1,
		defnames	=> 1,
		dnsrch		=> 1,
		debug		=> 0,
		errorstring	=> 'unknown error or no error',
		tsig_rr		=> undef,
		answerfrom	=> '',
		tcp_timeout	=> 120,
		udp_timeout	=> undef,
		persistent_tcp	=> 0,
		persistent_udp	=> 0,
		dnssec		=> 0,
		adflag		=> 0,	# this is only used when {dnssec} == 1
		cdflag		=> 0,	# this is only used when {dnssec} == 1
		udppacketsize	=> 0,	# value bounded below by PACKETSZ
		force_v4	=> 0,	# only relevant if IPv6 is supported
		force_v6	=> 0,	#
		prefer_v6	=> 0,	# prefer v6, otherwise prefer v4
		ignqrid		=> 0,	# normally packets with non-matching ID
					# or with the qr bit on are thrown away,
					# but with 'ignqrid' these packets
					# are accepted.
					# USE WITH CARE, YOU ARE VULNERABLE TO
					# SPOOFING IF SET.
					# This may be a temporary feature
		);

	# If running under a SOCKSified Perl, use TCP instead of UDP
	# and keep the sockets open.
	if ( $Config::Config{'usesocks'} ) {
		$defaults{'usevc'}	    = 1;
		$defaults{'persistent_tcp'} = 1;
	}

	my $defaults = bless \%defaults, __PACKAGE__;

	sub defaults { return $defaults; }
}

# These are the attributes that the user may specify in the new() constructor.
my %public_attr = map { $_ => 1 } qw(
		nameservers
		port
		srcaddr
		srcport
		domain
		searchlist
		retrans
		retry
		usevc
		stayopen
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
		prefer_v6
		ignqrid
		);


my $initial;

sub new {
	my $class = shift;
	my %args = ( scalar(@_) % 2 ) ? () : @_;

	my $self;
	my $base = $class->defaults;
	my $init = $initial;
	$initial ||= bless {%$base}, $class;
	if ( my $file = $args{'config_file'} ) {
		$self = bless {%$initial}, $class;
		$self->read_config_file($file);			# user specified config
		$self->nameservers( _untaint $self->nameservers );
		my @searchlist = _untaint $base->searchlist;
		$base->searchlist( _untaint $base->domain || () ) unless @searchlist;
		$base->domain(@searchlist) unless $base->domain;
		%$base = %$self unless $init;			# define default configuration

	} elsif ($init) {
		$self = bless {%$base}, $class;

	} else {
		$class->init();					# define default configuration
		my @searchlist = $base->searchlist;
		$base->searchlist( $base->domain || () ) unless @searchlist;
		$base->domain(@searchlist) unless $base->domain;
		$self = bless {%$base}, $class;
	}

	while ( my ( $attr, $value ) = each %args ) {
		next unless $public_attr{$attr};

		if ( $attr eq 'nameservers' || $attr eq 'searchlist' ) {

			croak "usage: Net::DNS::Resolver->new( $attr => [ ... ] )"
					unless UNIVERSAL::isa( $value, 'ARRAY' );
			$self->$attr(@$value);
		} else {
			$self->$attr($value);			# attribute => value
		}
	}

	return $self;
}


#
# $class->read_env() or $object->read_env()
#
my %netdns_conf = ( %public_attr, map { $_ => 0 } qw(nameservers domain searchlist ignqrid) );
my %resolv_conf = (
	attempts => 'retry',
	inet6	 => 'prefer_v6',
	timeout	 => 'retrans',
	);

sub read_env {
	my ($invocant) = @_;
	my $config = ref($invocant) ? $invocant : $invocant->defaults;

	$config->nameservers( map split, $ENV{RES_NAMESERVERS} ) if exists $ENV{RES_NAMESERVERS};

	$config->searchlist( map split, $ENV{RES_SEARCHLIST} ) if exists $ENV{RES_SEARCHLIST};

	$config->domain( $ENV{LOCALDOMAIN} ) if exists $ENV{LOCALDOMAIN};

	if ( exists $ENV{RES_OPTIONS} ) {
		foreach ( map split, $ENV{RES_OPTIONS} ) {
			my ( $name, $val ) = split( m/:/, $_, 2 );
			my $attribute = $resolv_conf{$name};
			$val = 1 unless defined $val;
			$config->$attribute($val) if $attribute;
			$config->$name($val) if $netdns_conf{$name};
		}
	}
}


#
# $class->read_config_file($filename) or $object->read_config_file($filename)
#
sub read_config_file {
	my ( $invocant, $file ) = @_;
	my $config = ref($invocant) ? $invocant : $invocant->defaults;

	my @ns;

	local *FILE;

	open( FILE, $file ) or croak "Could not open $file: $!";

	local $SIG{__WARN__} = sub { die @_ };
	local $_;
	while (<FILE>) {
		s/[;#].*$//;					# strip comments

		/^nameserver/ && do {
			my ( $keyword, @ip ) = grep defined, split;
			push @ns, map $_ eq '0' ? '0.0.0.0' : $_, @ip;
			next;
		};

		/^option/ && do {
			my ( $keyword, $option ) = grep defined, split;
			my ( $name, $val ) = split( m/:/, $option, 2 );
			my $attribute = $resolv_conf{$name};
			$val = 1 unless defined $val;
			$config->$attribute($val) if $attribute;
			next;
		};

		/^domain/ && do {
			my ( $keyword, $domain ) = grep defined, split;
			$config->domain($domain);
			next;
		};

		/^search/ && do {
			my ( $keyword, @searchlist ) = grep defined, split;
			$config->searchlist(@searchlist);
			next;
		};
	}

	close(FILE) || croak "close $file: $!";

	$config->nameservers(@ns);
}


sub print { print shift->string; }


sub string {
	my $self = shift;

	my $timeout = $self->{'tcp_timeout'} || 'indefinite';
	my $IP6line = "prefer_v6\t= $self->{prefer_v6}\tforce_v6 = $self->{force_v6}";
	my $IP6conf = $has_inet6 ? $IP6line : '(no IPv6 transport)';
	my @nslist  = $self->nameservers();
	my $ignqrid = $self->{'ignqrid'} ? 'ACCEPTING ALL PACKETS (IGNQRID)' : '';
	return <<END;
;; RESOLVER state:
;;  domain	= $self->{domain}
;;  searchlist	= @{$self->{searchlist}}
;;  nameservers = @nslist
;;  port	= $self->{port}
;;  srcport	= $self->{srcport}
;;  srcaddr	= $self->{srcaddr}
;;  tcp_timeout = $timeout
;;  retrans	= $self->{retrans}	retry    = $self->{retry}
;;  usevc	= $self->{usevc}	stayopen = $self->{stayopen}
;;  defnames	= $self->{defnames}	dnsrch   = $self->{dnsrch}
;;  recurse	= $self->{recurse}	igntc    = $self->{igntc}
;;  debug	= $self->{debug}	force_v4 = $self->{force_v4}	$ignqrid
;;  $IP6conf
END

}


sub searchlist {
	my $self = shift;
	$self->{'searchlist'} = [@_] if scalar @_;
	my @searchlist = @{$self->{'searchlist'}};
}

sub empty_searchlist {
	my $self = shift;
	$self->{'searchlist'} = [];
	return $self->searchlist();
}

sub nameservers {
	my $self = shift;
	$self = $self->defaults unless ref($self);

	my ( @ipv4, @ipv6 );
	foreach my $ns (@_) {
		croak 'nameservers: invalid argument' unless $ns;
		do { push @ipv6, $ns; next } if _ip_is_ipv6($ns);
		do { push @ipv4, $ns; next } if _ip_is_ipv4($ns);

		my $defres = ref($self)->new(
			udp_timeout => $self->udp_timeout,
			tcp_timeout => $self->tcp_timeout,
			debug	    => $self->{debug} );
		$defres->{cache} = $self->{cache} if $self->{cache};

		my @names;
		if ( $ns =~ /\./ ) {
			@names = ($ns);
		} else {
			my @suffix = $defres->searchlist;
			@suffix = grep length, ( $defres->domain ) unless @suffix;
			@names = map "$ns.$_", @suffix;
		}

		my $packet = $defres->search( $ns, 'A' );
		$self->errorstring( $defres->errorstring );
		my @address = $packet ? cname_addr( [@names], $packet ) : ();

		if ($has_inet6) {
			$packet = $defres->search( $ns, 'AAAA' );
			$self->errorstring( $defres->errorstring );
			push @address, cname_addr( [@names], $packet ) if defined $packet;
		}

		my %address = map { $_ => $_ } @address;	# tainted
		my @unique = values %address;
		carp "unresolvable name: $ns" unless @unique;
		push @ipv4, grep _ip_is_ipv4($_), @unique;
		push @ipv6, grep _ip_is_ipv6($_), @unique;
	}

	if ( scalar @_ ) {
		$self->{nameserver4} = \@ipv4;
		$self->{nameserver6} = \@ipv6;
		return unless defined wantarray;
	}

	my @ns4 = $self->force_v6 ? () : @{$self->{nameserver4}};
	my @ns6 = $has_inet6 && !$self->force_v4 ? @{$self->{nameserver6}} : ();
	my @returnval = $self->prefer_v6 ? ( @ns6, @ns4 ) : ( @ns4, @ns6 );

	return @returnval if scalar @returnval;

	$self->errorstring('no nameservers');
	$self->errorstring('IPv4 transport not available') if scalar(@ns4) < scalar @{$self->{nameserver4}};
	$self->errorstring('IPv6 transport not available') if scalar(@ns6) < scalar @{$self->{nameserver6}};
	return @returnval;
}

sub empty_nameservers {
	my $self = shift;
	$self->{nameserver4} = $self->{nameserver6} = [];
	my @empty;
}

sub nameserver { &nameservers; }

sub cname_addr {

	# TODO 20081217
	# This code does not follow CNAME chains, it only looks inside the packet.
	# Out of bailiwick will fail.
	my $names  = shift;
	my $packet = shift;
	my @addr;
	my @names = @{$names};

	foreach my $rr ( $packet->answer ) {
		next unless grep $rr->name, @names;

		my $type = $rr->type;
		push( @addr,  $rr->address ) if $type eq 'A';
		push( @addr,  $rr->address ) if $type eq 'AAAA';
		push( @names, $rr->cname )   if $type eq 'CNAME';
	}

	return @addr;
}


# if ($self->{udppacketsize}  > PACKETSZ
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

	$self->errorstring( $self->defaults->{'errorstring'} );
}


sub search {
	my $self = shift;
	my $name = shift || '.';

	my $defdomain  = $self->{defnames} ? $self->{domain}	      : undef;
	my @searchlist = $self->{dnsrch}   ? @{$self->{'searchlist'}} : ();

	# resolve name by trying as absolute name, then applying searchlist
	my @list = ( undef, @searchlist );
	for ($name) {

		# resolve name with no dots or colons by applying searchlist (or domain)
		@list = @searchlist ? @searchlist : ($defdomain) unless m/[:.]/;

		# resolve name with trailing dot as absolute name
		@list = (undef) if m/\.$/;
	}

	foreach my $suffix (@list) {
		my $fqname = join '.', $name, ( $suffix || () );

		print ';; search(', join( ', ', $fqname, @_ ), ")\n" if $self->{debug};

		my $packet = $self->send( $fqname, @_ ) || return undef;

		next unless ( $packet->header->rcode eq "NOERROR" );	# something
								#useful happened
		return $packet if $packet->header->ancount;	# answer found
		next unless $packet->header->qdcount;		# question empty?

		last if ( $packet->question )[0]->qtype eq 'PTR';	# abort search if IP
	}
	return undef;
}


sub query {
	my $self = shift;
	my $name = shift || '.';

	# resolve name containing no dots or colons by appending domain
	my @suffix = ( $name !~ m/[:.]/ && $self->{defnames} ) ? ( $self->{domain} || () ) : ();

	my $fqname = join '.', $name, @suffix;

	print ';; query(', join( ', ', $fqname, @_ ), ")\n" if $self->{debug};

	my $packet = $self->send( $fqname, @_ ) || return undef;

	return $packet if $packet->header->ancount;		# answer found
	return undef;
}


sub send {
	my $self	= shift;
	my $packet	= $self->make_query_packet(@_);
	my $packet_data = $packet->data;

	my $ans;

	if ( $self->{'usevc'} || length $packet_data > $self->_packetsz ) {

		$ans = $self->send_tcp( $packet, $packet_data );

	} else {
		$ans = $self->send_udp( $packet, $packet_data );

		if ( $ans && $ans->header->tc && !$self->{'igntc'} ) {
			print ";;\n;; packet truncated: retrying using TCP\n" if $self->{'debug'};
			$ans = $self->send_tcp( $packet, $packet_data );
		}
	}

	return $ans;
}


sub send_tcp {
	my ( $self, $packet, $packet_data ) = @_;
	my $lastanswer;

	my $srcport = $self->{'srcport'};
	my $srcaddr = $self->{'srcaddr'};
	my $dstport = $self->{'port'};

	$self->_reset_errorstring;

	my @ns = $self->nameservers();
	unless ( scalar(@ns) ) {
		print ';; ', $self->errorstring, "\n" if $self->{debug};
		return;
	}


NAMESERVER: foreach my $ns (@ns) {
		my $sock;
		my $sock_key = "$ns:$dstport";

		print ";; send_tcp [$ns]:$dstport  (src port = $srcport)\n" if $self->{'debug'};

		if ( $self->persistent_tcp && $self->{'sockets'}[AF_UNSPEC]{$sock_key} ) {
			$sock = $self->{'sockets'}[AF_UNSPEC]{$sock_key};
			print ";; using persistent socket\n"
					if $self->{'debug'};
			unless ( $sock->connected ) {
				print ";; persistent socket disconnected (trying to reconnect)"
						if $self->{'debug'};
				undef($sock);
				$sock = $self->_create_tcp_socket($ns);
				next NAMESERVER unless $sock;
				$self->{'sockets'}[AF_UNSPEC]{$sock_key} = $sock;
			}

		} else {
			$sock = $self->_create_tcp_socket($ns);
			next NAMESERVER unless $sock;

			$self->{'sockets'}[AF_UNSPEC]{$sock_key} = $sock
					if $self->persistent_tcp;
		}

		my $lenmsg = pack( 'n', length($packet_data) );
		print ';; sending ', length($packet_data), " bytes\n"
				if $self->{'debug'};

		# note that we send the length and packet data in a single call
		# as this produces a single TCP packet rather than two. This
		# is more efficient and also makes things much nicer for sniffers.
		# (ethereal doesn't seem to reassemble DNS over TCP correctly)

		unless ( $sock->send( $lenmsg . $packet_data ) ) {
			$self->errorstring($!);
			print ";; ERROR: send_tcp: data send failed: $!\n"
					if $self->{'debug'};
			next NAMESERVER;
		}

		my $sel	    = IO::Select->new($sock);
		my $timeout = $self->{'tcp_timeout'};
		if ( $sel->can_read($timeout) ) {
			my $buf = read_tcp( $sock, INT16SZ, $self->{'debug'} );
			next NAMESERVER unless length($buf);	# Failure to get anything
			my ($len) = unpack( 'n', $buf );
			next NAMESERVER unless $len;		# Cannot determine size

			unless ( $sel->can_read($timeout) ) {
				$self->errorstring('timeout');
				print ";; TIMEOUT\n" if $self->{'debug'};
				next;
			}

			$buf = read_tcp( $sock, $len, $self->{'debug'} );

			# Cannot use $sock->peerhost, because on some systems it
			# returns garbage after reading from TCP. I have observed
			# this myself on cygwin.
			# -- Willem
			#
			$self->answerfrom($ns);

			print ';; received ', length($buf), " bytes\n"
					if $self->{'debug'};

			unless ( length($buf) == $len ) {
				$self->errorstring( "expected $len bytes, " . 'received ' . length($buf) );
				next;
			}

			my $ans = Net::DNS::Packet->new( \$buf, $self->{debug} );
			my $error = $@;

			unless ( defined $ans ) {
				$self->errorstring($error);
			} else {
				my $rcode = $ans->header->rcode;
				$self->errorstring( $error || $rcode );

				$ans->answerfrom( $self->answerfrom );

				if ( $rcode ne "NOERROR" && $rcode ne "NXDOMAIN" ) {

					# Remove this one from the stack
					print "RCODE: $rcode; trying next nameserver\n" if $self->{debug};
					$lastanswer = $ans;
					next NAMESERVER;
				}

			}
			return $ans;
		} else {
			$self->errorstring('timeout');
			next;
		}
	}

	if ($lastanswer) {
		$self->errorstring( $lastanswer->header->rcode );
		return $lastanswer;

	}

	return;
}


sub send_udp {
	my ( $self, $packet, $packet_data ) = @_;
	my $retrans = $self->{'retrans'};
	my $timeout = $retrans;

	my $lastanswer;

	my $stop_time = $self->{'udp_timeout'} ? time + $self->{'udp_timeout'} : undef;

	$self->_reset_errorstring;

	my @ns;
	my $dstport = $self->{'port'};
	my $srcport = $self->{'srcport'};
	my $srcaddr = $self->{'srcaddr'};

	my @sock;


	if ( $self->persistent_udp ) {
		if ($has_inet6) {
			if ( defined( $self->{'sockets'}[AF_INET6()]{'UDP'} ) ) {
				$sock[AF_INET6()] = $self->{'sockets'}[AF_INET6()]{'UDP'};
				print ";; using persistent AF_INET6() family type socket\n"
						if $self->{'debug'};
			}
		}
		if ( defined( $self->{'sockets'}[AF_INET]{'UDP'} ) ) {
			$sock[AF_INET] = $self->{'sockets'}[AF_INET]{'UDP'};
			print ";; using persistent AF_INET() family type socket\n"
					if $self->{'debug'};
		}
	}

	if ( $has_inet6 && !$self->force_v4() && !defined( $sock[AF_INET6()] ) ) {

		# '::' Otherwise the INET6 socket will fail.

		my $srcaddr6 = $srcaddr eq '0.0.0.0' ? '::' : $srcaddr;

		print ";; setting up AF_INET6 UDP socket with srcaddr [$srcaddr6] ... "
				if $self->{'debug'};

		# IO::Socket carps on errors if Perl's -w flag is turned on.
		# Uncomment the next two lines and the line following the "new"
		# call to turn off these messages.

		#my $old_wflag = $^W;
		#$^W = 0;

		$sock[AF_INET6()] = IO::Socket::INET6->new(
			LocalAddr => $srcaddr6,
			LocalPort => ( $srcport || undef ),
			Proto	  => 'udp',
			);

		print( defined( $sock[AF_INET6()] ) ? "done\n" : "failed\n" ) if $self->{debug};
	}

	# Always set up an AF_INET socket.
	# It will be used if the address family of the endpoint is V4.

	unless ( defined( $sock[AF_INET] ) ) {
		print ";; setting up AF_INET  UDP socket with srcaddr [$srcaddr] ... "
				if $self->{'debug'};

		#my $old_wflag = $^W;
		#$^W = 0;

		$sock[AF_INET] = IO::Socket::INET->new(
			LocalAddr => $srcaddr,
			LocalPort => ( $srcport || undef ),
			Proto	  => 'udp',
			);

		#$^W = $old_wflag;
	}

	print( defined( $sock[AF_INET] ) ? "done\n" : "failed\n" ) if $self->{debug};

	unless ( defined $sock[AF_INET] || ( $has_inet6 && defined $sock[AF_INET6()] ) ) {
		$self->errorstring("could not get socket");
		return;
	}

	$self->{'sockets'}[AF_INET]{'UDP'} = $sock[AF_INET] if ( $self->persistent_udp ) && defined( $sock[AF_INET] );
	$self->{'sockets'}[AF_INET6()]{'UDP'} = $sock[AF_INET6()]
			if $has_inet6
			&& ( $self->persistent_udp )
			&& defined( $sock[AF_INET6()] )
			&& !$self->force_v4();

	# Constructing an array of arrays that contain 3 elements: The
	# nameserver IP address, its sockaddr and the sockfamily for
	# which the sockaddr structure is constructed.

	my $nmbrnsfailed = 0;
NSADDRESS: foreach my $ns_address ( $self->nameservers() ) {

		# The logic below determines the $dst_sockaddr.
		# If getaddrinfo is available that is used for both INET4 and INET6
		# If getaddrinfo is not available (Socket6 failed to load) we revert
		# to the 'classic' mechanism
		if ( $has_inet6 && !$self->force_v4() ) {

			# we can use getaddrinfo
			no strict 'subs';			# Because of the eval statement in the BEGIN
								# AI_NUMERICHOST is not available at compile time.
								# The AI_NUMERICHOST suppresses lookups.

			my $old_wflag = $^W;			#circumvent perl -w warnings about 'udp'
			$^W = 0;

			my @res = Socket6::getaddrinfo( $ns_address, $dstport, AF_UNSPEC, SOCK_DGRAM, 0,
				AI_NUMERICHOST );

			$^W = $old_wflag;

			use strict 'subs';

			my ( $sockfamily, $socktype_tmp, $proto_tmp, $dst_sockaddr, $canonname_tmp ) = @res;

			if ( scalar(@res) < 5 ) {
				die("can't resolve \"$ns_address\" to address");
			}

			push @ns, [$ns_address, $dst_sockaddr, $sockfamily];

		} else {
			next NSADDRESS unless ( _ip_is_ipv4($ns_address) );
			my $dst_sockaddr = sockaddr_in( $dstport, inet_aton($ns_address) );
			push @ns, [$ns_address, $dst_sockaddr, AF_INET];
		}
	}

	unless ( scalar(@ns) ) {
		$self->errorstring('no nameservers') if $self->nameservers;
		print ';; ', $self->errorstring, "\n" if $self->{debug};
		return;
	}

	my $sel = IO::Select->new();

	# We already tested that one of the two socket exists

	$sel->add( $sock[AF_INET] ) if defined( $sock[AF_INET] );
	$sel->add( $sock[AF_INET6()] ) if $has_inet6 && defined( $sock[AF_INET6()] ) && !$self->force_v4();

	# Perform each round of retries.
	for ( my $i = 0 ; $i < $self->{'retry'} ; ++$i, $retrans *= 2 ) {

		$timeout = int( $retrans / ( scalar @ns || 1 ) );
		$timeout = 1 if $timeout < 1;

		# Try each nameserver.
NAMESERVER: foreach my $ns (@ns) {
			my ( $nsname, $nsaddr, $nssockfamily, $err ) = @$ns;
			next if defined $err;

			if ($stop_time) {
				my $now = time;
				if ( $stop_time < $now ) {
					$self->errorstring('query timed out');
					return;
				}
				if ( $timeout > 1 && $timeout > ( $stop_time - $now ) ) {
					$timeout = $stop_time - $now;
				}
			}

			# If we do not have a socket for the transport
			# we are supposed to reach the namserver on we
			# should skip it.
			unless ( defined( $sock[$nssockfamily] ) ) {
				print "Send error: cannot reach $nsname (" .

						( ( $has_inet6 && $nssockfamily == AF_INET6() ) ? "IPv6" : "" )
						. ( ( $nssockfamily == AF_INET ) ? "IPv4" : "" )
						. ") not available"
						if $self->debug();


				$self->errorstring( "Send error: cannot reach $nsname ("
							. (
						( $has_inet6 && $nssockfamily == AF_INET6() ) ? "IPv6" : "" )
							. ( ( $nssockfamily == AF_INET ) ? "IPv4" : "" )
							. ") not available" );
				next NAMESERVER;
			}

			print ";; send_udp [$nsname]:$dstport\n" if $self->{'debug'};

			unless ( $sock[$nssockfamily]->send( $packet_data, 0, $nsaddr ) ) {
				my $err = $ns->[3] = $self->errorstring("Send error: $!");
				print ";; $err\n" if $self->{'debug'};
				$nmbrnsfailed++;
				next;
			}

			# handle failure to detect taint inside socket->send()
			die 'Insecure dependency while running with -T switch' if tainted($nsaddr);


			# See tickets #11931 and #97502
			my $time_limit = time + $timeout;
			while ( time() < $time_limit ) {
				my @ready = $sel->can_read($timeout);
		SELECTOR: foreach my $ready (@ready) {
					my $buf = '';

					if ( $ready->recv( $buf, $self->_packetsz ) ) {
						my $peerhost = $ready->peerhost;

						$self->answerfrom($peerhost);

						print ';; answer from [', $peerhost, ']',
								'  (', length($buf), " bytes)\n"
								if $self->{'debug'};

						my $ans = Net::DNS::Packet->new( \$buf, $self->{debug} );
						my $error = $@;

						unless ( defined $ans ) {
							$self->errorstring($error);
						} else {
							my $header = $ans->header;
							next SELECTOR unless ( $header->qr || $self->{'ignqrid'} );
							next SELECTOR
									unless ( ( $header->id == $packet->header->id )
								|| $self->{'ignqrid'} );
							my $rcode = $header->rcode;
							$self->errorstring( $error || $rcode );

							$ans->answerfrom($peerhost);
							if ( $rcode ne "NOERROR" && $rcode ne "NXDOMAIN" ) {

								# Remove this one from the stack
								print "RCODE: $rcode; trying next nameserver\n"
										if $self->{'debug'};
								$nmbrnsfailed++;
								$ns->[3] = "RCODE: $rcode";
								$lastanswer = $ans;
								next NAMESERVER;

							}
						}
						return $ans;

					} else {
						$self->errorstring($!);
						print ';; recv ERROR [', $ready->peerhost, ']:',
								$ready->peerport, '  ', $self->errorstring, "\n"
								if $self->{'debug'};
						$ns->[3] = "Recv error " . $self->errorstring();
						$nmbrnsfailed++;

						# We want to remain in the SELECTOR LOOP...
						# unless there are no more nameservers
						return unless ( $nmbrnsfailed < @ns );
						print ';; Number of failed nameservers: $nmbrnsfailed out of '
								. scalar @ns . "\n"
								if $self->{'debug'};
					}
				}				#SELECTOR LOOP
			}					# until stop_time loop
		}						#NAMESERVER LOOP

	}

	if ($lastanswer) {
		$self->errorstring( $lastanswer->header->rcode );
		return $lastanswer;
	}

	if ( $sel->handles ) {

		# If there are valid handles then we have either a timeout or a send error.
		$self->errorstring('query timed out') unless ( $self->errorstring =~ /Send error:/ );
	} else {
		if ( $nmbrnsfailed < @ns ) {
			$self->errorstring('Unexpected Error');
		} else {
			$self->errorstring('all nameservers failed');
		}
	}
	return;
}


sub bgsend {
	my $self = shift;

	$self->_reset_errorstring;

	my @ns = $self->nameservers;
	unless ( scalar(@ns) ) {
		print ';; ', $self->errorstring, "\n" if $self->{debug};
		return;
	}

	my $packet	= $self->make_query_packet(@_);
	my $packet_data = $packet->data;

	my $srcaddr = $self->{'srcaddr'};
	my $srcport = $self->{'srcport'};

	my ( @res, $sockfamily, $dst_sockaddr );
	my ($ns_address) = @ns;
	my $dstport = $self->{'port'};

	# The logic below determines the $dst_sockaddr.
	# If getaddrinfo is available that is used for both INET4 and INET6
	# If getaddrinfo is not available (Socket6 failed to load) we revert
	# to the 'classic' mechanism
	if ( $has_inet6 && !$self->force_v4() ) {

		my ( $socktype_tmp, $proto_tmp, $canonname_tmp );

		no strict 'subs';				# Because of the eval statement in the BEGIN
								# AI_NUMERICHOST is not available at compile time.

		my $old_wflag = $^W;				#circumvent perl -w warnings about 'udp'
		$^W = 0;

		# The AI_NUMERICHOST suppresses lookups.
		my @res = Socket6::getaddrinfo( $ns_address, $dstport, AF_UNSPEC, SOCK_DGRAM, 0, AI_NUMERICHOST );

		$^W = $old_wflag;

		use strict 'subs';

		( $sockfamily, $socktype_tmp, $proto_tmp, $dst_sockaddr, $canonname_tmp ) = @res;

		if ( scalar(@res) < 5 ) {
			die("can't resolve \"$ns_address\" to address (it could have been an IP address)");
		}

	} else {
		$sockfamily = AF_INET;

		unless ( _ip_is_ipv4($ns_address) ) {
			$self->errorstring("bgsend(ipv4 only):$ns_address does not seem to be a valid IPv4 address");
			return;
		}

		$dst_sockaddr = sockaddr_in( $dstport, inet_aton($ns_address) );
	}
	my @socket;

	if ( $sockfamily == AF_INET ) {
		$socket[$sockfamily] = IO::Socket::INET->new(
			Proto	  => 'udp',
			Type	  => SOCK_DGRAM,
			LocalAddr => $srcaddr,
			LocalPort => ( $srcport || undef ),
			);
	} elsif ( $has_inet6 && $sockfamily == AF_INET6() ) {

		# Otherwise the INET6 socket will just fail
		my $srcaddr6 = $srcaddr eq "0.0.0.0" ? '::' : $srcaddr;
		$socket[$sockfamily] = IO::Socket::INET6->new(
			Proto	  => 'udp',
			Type	  => SOCK_DGRAM,
			LocalAddr => $srcaddr6,
			LocalPort => ( $srcport || undef ),
			);
	} else {
		die ref($self) . " bgsend: Unsupported Socket Family: $sockfamily";
	}

	unless ( $socket[$sockfamily] ) {
		$self->errorstring("could not get socket");
		return;
	}

	print ";; bgsend [$ns_address]:$dstport\n" if $self->{debug};

	foreach my $socket (@socket) {
		next unless defined $socket;

		unless ( $socket->send( $packet_data, 0, $dst_sockaddr ) ) {
			$self->errorstring("Send: [$ns_address]:$dstport  $!");
			print ";; ", $self->errorstring(), "\n" if $self->{'debug'};
		}

		# handle failure to detect taint inside socket->send()
		die 'Insecure dependency while running with -T switch' if tainted($dst_sockaddr);
		return $socket;
	}
	$self->errorstring("Could not find a socket to send on");
	return;
}


sub bgread {
	my ( $self, $sock ) = @_;

	my $buf = '';

	my $peeraddr = $sock->recv( $buf, $self->_packetsz );

	if ($peeraddr) {
		print ';; answer from [', $sock->peerhost, ']  (', length($buf), " bytes)\n"
				if $self->{'debug'};

		my $ans = Net::DNS::Packet->new( \$buf, $self->{debug} );
		$self->errorstring($@);

		$ans->answerfrom( $sock->peerhost ) if defined $ans;
		return $ans;

	} else {
		$self->errorstring($!);
		return;
	}
}

sub bgisready {
	my $self  = shift;
	my $sel	  = IO::Select->new(@_);
	my @ready = $sel->can_read(0.0);
	return @ready > 0;
}


#
# Keep this method around. Folk depend on it although it is neither documented nor exported.
#
sub make_query_packet {
	my $self = shift;
	my $packet;

	if ( ref( $_[0] ) and $_[0]->isa('Net::DNS::Packet') ) {
		$packet = shift;
	} else {
		$packet = Net::DNS::Packet->new(@_);
	}

	my $header = $packet->header;

	$header->rd( $self->{recurse} ) if $header->opcode eq 'QUERY';

	unless ( $self->dnssec ) {
		$header->ad(0);
		$header->do(0);

	} elsif ( $self->{adflag} ) {				# RFC6840, 5.7
		print ";; Set AD flag\n" if $self->{debug};
		$header->ad(1);
		$header->cd(0);
		$header->do(0);

	} else {
		print ";; Set EDNS DO flag\n" if $self->{debug};
		$header->ad(0);
		$header->cd( $self->{cdflag} );
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

	my $whole = wantarray;
	my @null;
	my $query = $self->_axfr_start(@_) || return $whole ? @null : sub {undef};
	my $reply = $self->_axfr_next()	   || return $whole ? @null : sub {undef};
	my @rr	  = $reply->answer;
	my $soa	  = $rr[0];
	my $verfy = $query->sigrr();
	$verfy = $reply->verify($query) || croak $reply->verifyerr if $verfy;
	print ';; ', $verfy ? '' : 'not ', "verified\n" if $self->{debug};

	if ($whole) {
		my @zone = shift @rr;

		until ( scalar @rr && $rr[$#rr]->type eq 'SOA' ) {
			push @zone, @rr;			# unpack non-terminal packet
			@rr    = @null;
			$reply = $self->_axfr_next() || last;
			$verfy = $reply->verify($verfy) || croak $reply->verifyerr if $verfy;
			print ';; ', $verfy ? '' : 'not ', "verified\n" if $self->{debug};
			@rr    = $reply->answer;
		}

		my $last = pop @rr;				# unpack final packet
		push @zone, @rr;
		$self->{axfr_sel} = undef;
		croak 'improperly terminated AXFR' unless $last && $last->encode eq $soa->encode;
		return @zone;
	}

	return sub {			## iterator over RRs
		my $rr = shift @rr;
		croak 'improperly terminated AXFR' unless $rr;
		return $rr if scalar @rr;

		if ( $rr->type eq 'SOA' ) {
			unless ( $rr eq $soa ) {		# start of zone
				$self->{axfr_sel} = undef;	# end of zone
				croak 'improperly terminated AXFR' unless $rr->encode eq $soa->encode;
				return undef;
			}
		}

		$reply = $self->_axfr_next() || return undef;	# end of packet
		$verfy = $reply->verify($verfy) || croak $reply->verifyerr if $verfy;
		print ';; ', $verfy ? '' : 'not ', "verified\n" if $self->{debug};
		@rr = $reply->answer;
		return $rr;
	};
}


sub axfr_start {			## historical
	my $self = shift;
	my $iter = $self->{axfr_iter} = $self->axfr(@_);
	return defined($iter) || undef;
}


sub axfr_next {				## historical
	my $self = shift;
	my $iter = $self->{axfr_iter} || return undef;
	$iter->() || return $self->{axfr_iter} = undef;
}


sub _axfr_start {
	my $self  = shift;
	my $dname = shift || $self->{'searchlist'}->[0];
	my $class = shift || 'IN';

	my $debug = $self->{debug};

	unless ($dname) {
		$self->errorstring('no zone specified');
		print ';; ', $self->errorstring, "\n" if $debug;
		return;
	}

	print ";; axfr_start( $dname, $class )\n" if $debug;

	my $packet = $self->make_query_packet( $dname, 'AXFR', $class );

	foreach my $ns ( $self->nameservers ) {
		if ($debug) {
			my $dstport = $self->{port};
			print ";; axfr_start nameserver [$ns]:$dstport\n";
		}

		my $sock;
		my $sock_key = "$ns:$self->{port}";

		if ( $self->persistent_tcp && $self->{axfr_sockets}[AF_UNSPEC]{$sock_key} ) {
			$sock = $self->{axfr_sockets}[AF_UNSPEC]{$sock_key};
			print ";; using persistent socket\n" if $debug;
		} else {
			$sock = $self->_create_tcp_socket($ns) || next;
			$self->{axfr_sockets}[AF_UNSPEC]{$sock_key} = $sock if $self->persistent_tcp;
		}

		my $packet_data = $packet->data;
		my $lenmsg = pack( 'n', length($packet_data) );

		unless ( $sock->send($lenmsg) ) {
			$self->errorstring($!);
			next;
		}

		unless ( $sock->send($packet_data) ) {
			$self->errorstring($!);
			next;
		}

		$self->{axfr_ns}  = $ns;
		$self->{axfr_sel} = IO::Select->new($sock);

		return $packet;
	}

	print ';; ', $self->errorstring, "\n" if $debug;
	return;
}


sub _axfr_next {
	my $self = shift;

	my $debug = $self->{debug};
	my $sel	  = $self->{axfr_sel};
	unless ($sel) {
		$self->errorstring('no zone transfer in progress');
		print ';; ', $self->errorstring, "\n" if $debug;
		return;
	}

	#--------------------------------------------------------------
	# Read the length of the response packet.
	#--------------------------------------------------------------

	my $timeout = $self->{tcp_timeout};
	my @ready   = $sel->can_read($timeout);
	unless (@ready) {
		$self->errorstring('timeout');
		return;
	}

	my $buf = read_tcp( $ready[0], INT16SZ, $self->{debug} );
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

	@ready = $sel->can_read($timeout);
	unless (@ready) {
		$self->errorstring('timeout');
		return;
	}

	$buf = read_tcp( $ready[0], $len, $self->{debug} );

	print ';; received ', length($buf), " bytes\n" if $debug;

	unless ( length($buf) == $len ) {
		$self->errorstring( "expected $len bytes, received " . length($buf) );
		print ';; ', $self->errorstring, "\n" if $debug;
		return;
	}

	my $ans = Net::DNS::Packet->new( \$buf );
	my $err = $@;

	if ($ans) {
		$ans->answerfrom( $self->{axfr_ns} );
		$ans->print if $debug;

		unless ( $ans->header->rcode eq 'NOERROR' ) {
			$self->errorstring( 'RCODE from server: ' . $ans->header->rcode );
			print ';; ', $self->errorstring, "\n" if $debug;
			return;
		}
		unless ( $ans->header->ancount ) {
			$self->errorstring('truncated zone transfer');
			print ';; ', $self->errorstring, "\n" if $debug;
			return;
		}

	} else {
		$err ||= 'unknown error during packet parsing';
		$self->errorstring($err);
		print ';; ', $self->errorstring, "\n" if $debug;
		return;
	}

	return $ans;
}


sub tsig {
	my $self = shift;

	return $self->{tsig_rr} unless scalar @_;
	$self->{tsig_rr} = eval {
		require Net::DNS::RR::TSIG;
		Net::DNS::RR::TSIG->create(@_);
	} || croak "$@\nunable to create TSIG record";
}


sub dnssec {
	my $self = shift;

	unless (DNSSEC) {
		carp 'resolver->dnssec(1) without Net::DNS::SEC installed' if shift;
		return $self->{dnssec} = 0;
	}

	return $self->{dnssec} unless scalar @_;

	# set flag and increase default udppacket size
	$self->udppacketsize(2048) if $self->{dnssec} = shift;

	return $self->{dnssec};
}


#
# Usage:  $data = read_tcp($socket, $nbytes, $debug);
#
sub read_tcp {
	my ( $sock, $nbytes, $debug ) = @_;
	my $buf = '';

	while ( length($buf) < $nbytes ) {
		my $nread    = $nbytes - length($buf);
		my $read_buf = '';

		print ";; read_tcp: expecting $nread bytes\n" if $debug;

		# During some of my tests recv() returned undef even
		# though there wasn't an error.	 Checking for the amount
		# of data read appears to work around that problem.

		unless ( $sock->recv( $read_buf, $nread ) ) {
			if ( length($read_buf) < 1 ) {
				my $errstr = $!;

				print ";; ERROR: read_tcp: recv failed: $errstr\n"
						if $debug;

				if ( $errstr eq 'Resource temporarily unavailable' ) {
					warn "ERROR: read_tcp: recv failed: $errstr\n";
					warn "ERROR: try setting \$res->timeout(undef)\n";
				}

				last;
			}
		}

		print ';; read_tcp: received ', length($read_buf), " bytes\n"
				if $debug;

		last unless length($read_buf);
		$buf .= $read_buf;
	}

	return $buf;
}


sub _create_tcp_socket {
	my $self = shift;
	my $ns	 = shift;
	my $sock;

	my $srcport = $self->{'srcport'};
	my $srcaddr = $self->{'srcaddr'};
	my $dstport = $self->{'port'};

	my $timeout = $self->{'tcp_timeout'};

	# IO::Socket carps on errors if Perl's -w flag is
	# turned on.  Uncomment the next two lines and the
	# line following the "new" call to turn off these
	# messages.

	#my $old_wflag = $^W;
	#$^W = 0;

	if ( $has_inet6 && !$self->force_v4() && _ip_is_ipv6($ns) ) {

		# XXX IO::Socket::INET6 fails in a cryptic way upon send()
		# on AIX5L if "0" is passed in as LocalAddr
		# $srcaddr="0" if $srcaddr eq "0.0.0.0";  # Otherwise the INET6 socket will just fail

		my $srcaddr6 = $srcaddr eq '0.0.0.0' ? '::' : $srcaddr;

		$sock = IO::Socket::INET6->new(
			PeerPort  => $dstport,
			PeerAddr  => $ns,
			LocalAddr => $srcaddr6,
			LocalPort => ( $srcport || undef ),
			Proto	  => 'tcp',
			Timeout	  => $timeout,
			);

		unless ($sock) {
			$self->errorstring('connection failed(IPv6 socket failure)');
			print ";; ERROR: send_tcp connection to [$ns] failed: $!\n"
					if $self->{'debug'};
			return ();
		}
	}

	# At this point we have sucessfully obtained an
	# INET6 socket to an IPv6 nameserver, or we are
	# running forced v4, or we do not have v6 at all.
	# Try v4.

	unless ($sock) {
		if ( _ip_is_ipv6($ns) ) {
			$self->errorstring('connection failed (IPv6 nameserver without having IPv6)');
			print ';; ERROR: send_tcp: You are trying to connect to '
					. "[$ns] but you do not have IPv6 available\n"
					if $self->{'debug'};
			return ();
		}

		$sock = IO::Socket::INET->new(
			PeerAddr  => $ns,
			PeerPort  => $dstport,
			LocalAddr => $srcaddr,
			LocalPort => ( $srcport || undef ),
			Proto	  => 'tcp',
			Timeout	  => $timeout
			);
	}

	#$^W = $old_wflag;

	unless ($sock) {
		$self->errorstring('connection failed');
		print ';; ERROR: send_tcp: connection ', "failed: $!\n" if $self->{'debug'};
		return ();
	}

	return $sock;
}


# Lightweight versions of subroutines from Net::IP module, recoded to fix RT#96812

sub _ip_is_ipv4 {
	return shift =~ /^[0-9.]+\.[0-9]+$/;			# dotted digits
}


sub _ip_is_ipv6 {

	for (shift) {
		return 1 if /^[:0-9a-f]+:[0-9a-f]*$/i;		# mixed : and hexdigits
		return 1 if /^[:0-9a-f]+:[0-9.]+$/i;		# prefix + dotted digits
	}

	return 0;
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


sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)

use vars qw($AUTOLOAD);

sub AUTOLOAD {				## Default method
	my ($self) = @_;
	confess "method '$AUTOLOAD' undefined" unless ref $self;

	my $name = $AUTOLOAD;
	$name =~ s/.*://;
	croak "$name: no such method" unless exists $public_attr{$name};

	no strict q/refs/;
	*{$AUTOLOAD} = sub {
		my $self = shift;
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

=head1 COPYRIGHT

Copyright (c) 1997-2002 Michael Fuhr.

Portions Copyright (c) 2002-2004 Chris Reinhardt.

Portions Copyright (c) 2005 Olaf Kolkman.

Portions Copyright (c) 2006,2014 Dick Franks.

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Resolver>

=cut

