package Net::DNS::Resolver;

# $Id: Resolver.pm,v 1.24 2002/10/14 21:12:07 ctriv Exp $

=head1 NAME

Net::DNS::Resolver - DNS resolver class

=head1 SYNOPSIS

C<use Net::DNS::Resolver;>

=head1 DESCRIPTION

Instances of the C<Net::DNS::Resolver> class represent resolver objects.
A program can have multiple resolver objects, each maintaining its
own state information such as the nameservers to be queried, whether
recursion is desired, etc.

Resolver configuration is read from the following files, in the
order indicated:

    /etc/resolv.conf
    $HOME/.resolv.conf
    ./.resolv.conf

The following keywords are recognized in resolver configuration files:

=over 4

=item B<domain>

The default domain.

=item B<search>

A space-separated list of domains to put in the search list.

item B<nameserver>

A space-separated list of nameservers to query.

=back

Files except for F</etc/resolv.conf> must be owned by the effective
userid running the program or they won't be read.  In addition, several
environment variables can also contain configuration information;
see L</ENVIRONMENT>.

=head1 METHODS

=cut

#'  Stupid Emacs!

use Config;
use strict;

use vars qw(
	$VERSION
	$resolv_conf
	$dotfile
	$os
	$can_time
	@confpath
	%default
	%global
	$AUTOLOAD
);

# XXX Not used till query timing is implemented

# Need these because we're using eval to get Time::HiRes.
#use subs qw(
#	Time::HiRes::gettimeofday
#	Time::HiRes::tv_interval
#);

use Carp;
use Socket;
use IO::Socket;
use Net::DNS;
use Net::DNS::Packet;
use Net::DNS::Select;

use constant MAX_ID => 65535;

eval 'use Win32::Registry';
$os = $@ ? 'unix' : 'microsoft';

# XXX See above
#eval 'use Time::HiRes';
#$can_time = $@ ? 0 : 1;


$VERSION = $Net::DNS::VERSION;

#------------------------------------------------------------------------------
# Configurable defaults.
#------------------------------------------------------------------------------

$resolv_conf = '/etc/resolv.conf';
$dotfile     = '.resolv.conf';

push(@confpath, $ENV{'HOME'}) if exists $ENV{'HOME'};
push(@confpath, '.');

%default = (
	nameservers	   => ['127.0.0.1'],
	port		   => 53,
	srcaddr        => '0.0.0.0',
	srcport        => 0,
	domain	       => '',
	searchlist	   => [],
	retrans	       => 5,
	retry		   => 4,
	usevc		   => 0,
	stayopen       => 0,
	igntc          => 0,
	recurse        => 1,
	defnames       => 1,
	dnsrch         => 1,
	debug          => 0,
	errorstring	   => 'unknown error or no error',
	tsig_rr        => undef,
	answerfrom     => '',
	answersize     => 0,
	querytime      => undef,
	tcp_timeout    => 120,
	axfr_sel       => undef,
	axfr_rr        => [],
	axfr_soa_count => 0,
	persistent_tcp => 0,
    dnssec         => 0,
    udppacketsize  => 0,  # The actual default is lower bound by Net::DNS::PACKETSZ
    cdflag         => 1,  # this is only used when {dnssec} == 1
);

%global = (
	id		       => int(rand(MAX_ID)),
);

=head2 new

    $res = Net::DNS::Resolver->new;

Creates a new DNS resolver object.

=cut

sub new {
	my $class = shift;
	my $self = { %default };
	return bless $self, $class;
}

#
# Some people have reported that Net::DNS dies because AUTOLOAD picks up
# calls to DESTROY.
#
sub DESTROY {}

sub res_init {
	if ($os eq 'unix') {
		res_init_unix();
	} elsif ($os eq 'microsoft') {
		res_init_microsoft();
	}

	# If we're running under a SOCKSified Perl, use TCP instead of UDP
	# and keep the sockets open.
	if ($Config::Config{'usesocks'}) {
		$default{'usevc'} = 1;
		$default{'persistent_tcp'} = 1;
	}
}

sub res_init_unix {
	read_config($resolv_conf) if (-f $resolv_conf) and (-r $resolv_conf);

	foreach my $dir (@confpath) {
		my $file = "$dir/$dotfile";
		read_config($file) if (-f $file) and (-r $file) and (-o $file);
	}

	read_env();

	if (!$default{'domain'} && @{$default{'searchlist'}}) {
		$default{'domain'} = $default{'searchlist'}[0];
	}
	elsif (!@{$default{'searchlist'}} && $default{'domain'}) {
		$default{'searchlist'} = [ $default{'domain'} ];
	}
}

sub res_init_microsoft {
	my ($resobj, %keys);
	my $root = 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';

	$main::HKEY_LOCAL_MACHINE->Open($root, $resobj)
		or Carp::croak "can't read registry: $!";

	$resobj->GetValues(\%keys)
		or Carp::croak "can't read registry values: $!";

	my $domain      = $keys{'Domain'}->[2] || $keys{'DhcpDomain'}->[2];
	my $searchlist  = $keys{'SearchList'}->[2];
	my $nameservers = $keys{'NameServer'}->[2] || $keys{'DhcpNameServer'}->[2];

	if ($domain) {
		$default{'domain'} = $domain;
	}

	if ($searchlist) {
		$default{'searchlist'} = [ split(' ', $searchlist) ];
	}

	if ($nameservers) {
		$default{'nameservers'} = [ split(' ', $nameservers) ];
	}

	if (!$default{'domain'} && @{$default{'searchlist'}}) {
		$default{'domain'} = $default{'searchlist'}[0];
	}
	elsif (!@{$default{'searchlist'}} && $default{'domain'}) {
		$default{'searchlist'} = [ $default{'domain'} ];
	}

	$default{'usevc'} = 1;
	$default{'tcp_timeout'} = undef;
}

sub read_config {
	my $file = shift;
	my @ns;
	my @searchlist;
	local *FILE;

	open(FILE, $file) or die "can't open $file: $!";
	local $/ = "\n";
	local $_;
	
	while (<FILE>) {
		s/\s*[;#].*//;
		next if /^\s*$/;

		SWITCH: {
			/^\s*domain\s+(\S+)/ && do {
				$default{'domain'} = $1;
				last SWITCH;
			};

			/^\s*search\s+(.*)/ && do {
				push(@searchlist, split(' ', $1));
				last SWITCH;
			};

			/^\s*nameserver\s+(.*)/ && do {
				foreach my $ns (split(' ', $1)) {
					$ns = '0.0.0.0' if $ns eq '0';
					push @ns, $ns;
				}
				last SWITCH;
			};
		}
	}
	close FILE;

	$default{'nameservers'} = [ @ns ]         if @ns;
	$default{'searchlist'}  = [ @searchlist ] if @searchlist;
}

sub read_env {
	$default{'nameservers'} = [ split(' ', $ENV{'RES_NAMESERVERS'}) ]
		if exists $ENV{'RES_NAMESERVERS'};

	$default{'searchlist'} = [ split(' ', $ENV{'RES_SEARCHLIST'}) ]
		if exists $ENV{'RES_SEARCHLIST'};
	
	$default{'domain'} = $ENV{'LOCALDOMAIN'}
		if exists $ENV{'LOCALDOMAIN'};

	if (exists $ENV{'RES_OPTIONS'}) {
		my @env = split(' ', $ENV{'RES_OPTIONS'});
		foreach (@env) {
			my ($name, $val) = split(/:/);
			$val = 1 unless defined $val;
			$default{$name} = $val if exists $default{$name};
		}
	}
}

=head2 print

    $res->print;

Prints the resolver state on the standard output.

=cut

sub print {
	my $self = shift;
	print $self->string;
}

=head2 string

    print $res->string;

Returns a string representation of the resolver state.

=cut
#"

sub string {
	my $self = shift;

	my $timeout = defined $self->{'tcp_timeout'} ? $self->{'tcp_timeout'} : 'indefinite';
	
	return <<END;
;; RESOLVER state:
;;  domain       = $self->{domain}
;;  searchlist   = @{$self->{searchlist}}
;;  nameservers  = @{$self->{nameservers}}
;;  port         = $self->{port}
;;  srcport      = $self->{srcport}
;;  srcaddr      = $self->{srcaddr}
;;  tcp_timeout  = $timeout
;;  retrans  = $self->{retrans}  retry    = $self->{retry}
;;  usevc    = $self->{usevc}  stayopen = $self->{stayopen}    igntc = $self->{igntc}
;;  defnames = $self->{defnames}  dnsrch   = $self->{dnsrch}
;;  recurse  = $self->{recurse}  debug    = $self->{debug}
END
}

sub nextid {
	return $global{'id'}++ % (MAX_ID + 1);
}

=head2 searchlist

    @searchlist = $res->searchlist;
    $res->searchlist('example.com', 'sub1.example.com', 'sub2.example.com');

Gets or sets the resolver search list.

=cut

sub searchlist {
	my $self = shift;
	$self->{'searchlist'} = [ @_ ] if @_;
	return @{$self->{'searchlist'}};
}

=head2 nameservers

    @nameservers = $res->nameservers;
    $res->nameservers('192.168.1.1', '192.168.2.2', '192.168.3.3');

Gets or sets the nameservers to be queried.

=head2 port

    print 'sending queries to port ', $res->port, "\n";
    $res->port(9732);

Gets or sets the port to which we send queries.  This can be useful
for testing a nameserver running on a non-standard port.  The
default is port 53.

=head2 srcport

    print 'sending queries from port ', $res->srcport, "\n";
    $res->srcport(5353);

Gets or sets the port from which we send queries.  The default is 0,
meaning any port.

=head2 srcaddr

    print 'sending queries from address ', $res->srcaddr, "\n";
    $res->srcaddr('192.168.1.1');

Gets or sets the source address from which we send queries.  Convenient
for forcing queries out a specific interfaces on a multi-homed host.
The default is 0.0.0.0, meaning any local address.

=cut

sub nameservers {
	my $self   = shift;
	my $defres = Net::DNS::Resolver->new;

	if (@_) {
		my @a;
		foreach my $ns (@_) {
			if ($ns =~ /^\d+(\.\d+){0,3}$/) {
				push @a, ($ns eq '0') ? '0.0.0.0' : $ns;
			}
			else {
				my @names;

				if ($ns !~ /\./) {
					if (defined $defres->searchlist) {
						@names = map { $ns . '.' . $_ }
							    $defres->searchlist;
					}
					elsif (defined $defres->domain) {
						@names = ($ns . '.' . $defres->domain);
					}
				}
				else {
					@names = ($ns);
				}

				my $packet = $defres->search($ns);
				$self->errorstring($defres->errorstring);
				if (defined($packet)) {
					push @a, cname_addr([@names], $packet);
				}
			}
		}

		$self->{'nameservers'} = [ @a ];
	}

	return @{$self->{'nameservers'}};
}

sub nameserver { &nameservers }


sub cname_addr {
	my $names  = shift;
	my $packet = shift;
	my @addr;
	my @names = @{$names};

	my $oct2 = '(?:2[0-4]\d|25[0-5]|[0-1]?\d\d|\d)';

	RR: foreach my $rr ($packet->answer) {
		next RR unless grep {$rr->name} @names;
				
		if ($rr->type eq 'CNAME') {
			push(@names, $rr->cname);
		} elsif ($rr->type eq 'A') {
			# Run a basic taint check.
			next RR unless $rr->address =~ m/^($oct2\.$oct2\.$oct2\.$oct2)$/o;
			
			push(@addr, $1)
		}
	}
	
	
	return @addr;
}


# if ($self->{"udppacketsize"}  > &Net::DNS::PACKETSZ 
# then we use EDNS and $self->{"udppacketsize"} 
# should be taken as the maximum packet_data length
sub _packetsz {
	my ($self) = @_;

	return $self->{"udppacketsize"} > &Net::DNS::PACKETSZ ? 
		   $self->{"udppacketsize"} : &Net::DNS::PACKETSZ; 
}

=head2 search

    $packet = $res->search('mailhost');
    $packet = $res->search('mailhost.example.com');
    $packet = $res->search('192.168.1.1');
    $packet = $res->search('example.com', 'MX');
    $packet = $res->search('user.passwd.example.com', 'TXT', 'HS');

Performs a DNS query for the given name, applying the searchlist
if appropriate.  The search algorithm is as follows:

=over 4

=item 1.

If the name contains at least one dot, try it as is.

=item 2.

If the name doesn't end in a dot then append each item in
the search list to the name.  This is only done if B<dnsrch>
is true.

=item 3.

If the name doesn't contain any dots, try it as is.

=back

The record type and class can be omitted; they default to A and
IN.  If the name looks like an IP address (4 dot-separated numbers),
then an appropriate PTR query will be performed.

Returns a C<Net::DNS::Packet> object, or C<undef> if no answers
were found.

=cut

sub search {
	my $self = shift;
	my ($name, $type, $class) = @_;
	my $ans;

	$type  = 'A'  unless defined($type);
	$class = 'IN' unless defined($class);

	# If the name looks like an IP address then do an appropriate
	# PTR query.
	if ($name =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
		$name = "$4.$3.$2.$1.in-addr.arpa.";
		$type = 'PTR';
	}

	# If the name contains at least one dot then try it as is first.
	if (index($name, '.') >= 0) {
		print ";; search($name, $type, $class)\n" if $self->{'debug'};
		$ans = $self->query($name, $type, $class);
		return $ans if (defined $ans) && ($ans->header->ancount > 0);
	}

	# If the name doesn't end in a dot then apply the search list.
	if (($name !~ /\.$/) && $self->{'dnsrch'}) {
		foreach my $domain (@{$self->{'searchlist'}}) {
			my $newname = "$name.$domain";
			print ";; search($newname, $type, $class)\n"
				if $self->{'debug'};
			$ans = $self->query($newname, $type, $class);
			return $ans if (defined $ans) && ($ans->header->ancount > 0);
		}
	}

	# Finally, if the name has no dots then try it as is.
	if (index($name, '.') < 0) {
		print ";; search($name, $type, $class)\n" if $self->{'debug'};
		$ans = $self->query("$name.", $type, $class);
		return $ans if (defined $ans) && ($ans->header->ancount > 0);
	}

	# No answer was found.
	return undef;
}

=head2 query

    $packet = $res->query('mailhost');
    $packet = $res->query('mailhost.example.com');
    $packet = $res->query('192.168.1.1');
    $packet = $res->query('example.com', 'MX');
    $packet = $res->query('user.passwd.example.com', 'TXT', 'HS');

Performs a DNS query for the given name; the search list is not
applied.  If the name doesn't contain any dots and B<defnames>
is true then the default domain will be appended.

The record type and class can be omitted; they default to A and
IN.  If the name looks like an IP address (4 dot-separated numbers),
then an appropriate PTR query will be performed.

Returns a C<Net::DNS::Packet> object, or C<undef> if no answers
were found.

=cut
#'

sub query {
	my ($self, $name, $type, $class) = @_;

	$type  = 'A'  unless defined($type);
	$class = 'IN' unless defined($class);

	# If the name doesn't contain any dots then append the default domain.
	if ((index($name, '.') < 0) && $self->{'defnames'}) {
		$name .= ".$self->{domain}";
	}

	# If the name looks like an IP address then do an appropriate
	# PTR query.
	if ($name =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
		$name = "$4.$3.$2.$1.in-addr.arpa";
		$type = 'PTR';
	}

	print ";; query($name, $type, $class)\n" if $self->{'debug'};
	my $packet = Net::DNS::Packet->new($name, $type, $class);


	
	my $ans = $self->send($packet);

	return (defined($ans) && ($ans->header->ancount > 0)) ? $ans : undef;
}

=head2 send

    $packet = $res->send($packet_object);
    $packet = $res->send('mailhost.example.com');
    $packet = $res->send('example.com', 'MX');
    $packet = $res->send('user.passwd.example.com', 'TXT', 'HS');

Performs a DNS query for the given name.  Neither the searchlist
nor the default domain will be appended.  

The argument list can be either a C<Net::DNS::Packet> object or a list
of strings.  The record type and class can be omitted; they default to
A and IN.  If the name looks like an IP address (4 dot-separated numbers),
then an appropriate PTR query will be performed.

Returns a C<Net::DNS::Packet> object whether there were any answers or not.
Use C<$packet-E<gt>header-E<gt>ancount> or C<$packet-E<gt>answer> to find out
if there were any records in the answer section.  Returns C<undef> if there
was an error.

=cut

sub send {
	my $self = shift;
	my $packet = $self->make_query_packet(@_);
	my $packet_data = $packet->data;

	my $ans;

	if ($self->{'usevc'} || length $packet_data > $self->_packetsz) {
	  
	    $ans = $self->send_tcp($packet, $packet_data);
	    
	} else {
	    $ans = $self->send_udp($packet, $packet_data);
	    
	    if ($ans && $ans->header->tc && !$self->{'igntc'}) {
			print ";;\n;; packet truncated: retrying using TCP\n" if $self->{'debug'};
			$ans = $self->send_tcp($packet, $packet_data);
	    }
	}
	
	return $ans;
}



sub send_tcp {
	my ($self, $packet, $packet_data) = @_;

	unless (@{$self->{'nameservers'}}) {
		$self->errorstring('no nameservers');
		print ";; ERROR: send_tcp: no nameservers\n" if $self->{'debug'};
		return;
	}

	$self->errorstring($default{'errorstring'});
	my $timeout = $self->{'tcp_timeout'};

	foreach my $ns (@{$self->{'nameservers'}}) {
		my $srcport = $self->{'srcport'};
		my $srcaddr = $self->{'srcaddr'};
		my $dstport = $self->{'port'};

		print ";; send_tcp($ns:$dstport) (src port = $srcport)\n"
			if $self->{'debug'};

		my $sock;
		my $sock_key = "$ns:$dstport";

		if ($self->persistent_tcp && $self->{'sockets'}{$sock_key}) {
			$sock = $self->{'sockets'}{$sock_key};
			print ";; using persistent socket\n"
				if $self->{'debug'};
		}
		else {

			# IO::Socket carps on errors if Perl's -w flag is
			# turned on.  Uncomment the next two lines and the
			# line following the "new" call to turn off these
			# messages.

			#my $old_wflag = $^W;
			#$^W = 0;

			$sock = IO::Socket::INET->new(
			    PeerAddr  => $ns,
			    PeerPort  => $dstport,
			    LocalAddr => $srcaddr,
			    LocalPort => ($srcport || undef),
			    Proto     => 'tcp',
			    Timeout   => $timeout
			);

			#$^W = $old_wflag;

			unless ($sock) {
				$self->errorstring('connection failed');
				print ';; ERROR: send_tcp: connection ',
				      "failed: $!\n" if $self->{'debug'};
				next;
			}

			$self->{'sockets'}{$sock_key} = $sock;
		}

		my $lenmsg = pack('n', length($packet_data));
		print ';; sending ', length($packet_data), " bytes\n"
			if $self->{'debug'};

		# note that we send the length and packet data in a single call
		# as this produces a single TCP packet rather than two. This
		# is more efficient and also makes things much nicer for sniffers.
		# (ethereal doesn't seem to reassemble DNS over TCP correctly)
		unless ($sock->send($lenmsg . $packet_data)) {
			$self->errorstring($!);
			print ";; ERROR: send_tcp: data send failed: $!\n"
				if $self->{'debug'};
			next;
		}

		my $sel = Net::DNS::Select->new($os, $sock);

		if ($sel->can_read($timeout)) {
			my $buf = read_tcp($sock, &Net::DNS::INT16SZ, $self->{'debug'});
			next unless length($buf);
			my ($len) = unpack('n', $buf);
			next unless $len;

			unless ($sel->can_read($timeout)) {
				$self->errorstring('timeout');
				print ";; TIMEOUT\n" if $self->{'debug'};
				next;
			}

			$buf = read_tcp($sock, $len, $self->{'debug'});

			$self->answerfrom($sock->peerhost);
			$self->answersize(length $buf);

			print ';; received ', length($buf), " bytes\n"
				if $self->{'debug'};

			unless (length($buf) == $len) {
				$self->errorstring("expected $len bytes, " .
						   'received ' . length($buf));
				next;
			}

			my ($ans, $err) = Net::DNS::Packet->new(\$buf, $self->{'debug'});
			if (defined $ans) {
				$self->errorstring($ans->header->rcode);
				$ans->answerfrom($self->answerfrom);
				$ans->answersize($self->answersize);
			}
			elsif (defined $err) {
				$self->errorstring($err);
			}

			return $ans;
		}
		else {
			$self->errorstring('timeout');
			next;
		}
	}

	return;
}

sub send_udp {
	my ($self, $packet, $packet_data) = @_;
	my $retrans = $self->{'retrans'};
	my $timeout = $retrans;

	$self->errorstring($default{'errorstring'});

	my $dstport = $self->{'port'};
	my $srcport = $self->{'srcport'};
	my $srcaddr = $self->{'srcaddr'};

	# IO::Socket carps on errors if Perl's -w flag is turned on.
	# Uncomment the next two lines and the line following the "new"
	# call to turn off these messages.

	#my $old_wflag = $^W;
	#$^W = 0;

	# XXX Why is PeerPort defined here?
	my $sock = IO::Socket::INET->new(
			    PeerPort  => $dstport,
			    LocalAddr => $srcaddr,
			    LocalPort => ($srcport || undef),
			    Proto     => 'udp',
	);

	#$^W = $old_wflag;

	unless ($sock) {
		$self->errorstring("couldn't create socket: $!");
		return;
	}

	my @ns = grep { $_->[0] && $_->[1] }
	         map  { [ $_, scalar(sockaddr_in($dstport, inet_aton($_))) ] }
	         @{$self->{'nameservers'}};

	unless (@ns) {
		$self->errorstring('no nameservers');
		return;
	}

	my $sel = Net::DNS::Select->new($os, $sock);

	# Perform each round of retries.
	for (my $i = 0;
	     $i < $self->{'retry'};
	     ++$i, $retrans *= 2, $timeout = int($retrans / (@ns || 1))) {

		$timeout = 1 if ($timeout < 1);

		# Try each nameserver.
		foreach my $ns (@ns) {
			my $nsname = $ns->[0];
			my $nsaddr = $ns->[1];

			print ";; send_udp($nsname:$dstport)\n"
				if $self->{'debug'};

			unless ($sock->send($packet_data, 0, $nsaddr)) {
				print ";; send error: $!\n" if $self->{'debug'};
				@ns = grep { $_->[0] ne $nsname } @ns;
				next;
			}

			my @ready = $sel->can_read($timeout);

			foreach my $ready (@ready) {
				my $buf = '';

				if ($ready->recv($buf, $self->_packetsz)) {
				
					$self->answerfrom($ready->peerhost);
					$self->answersize(length $buf);
				
					print ';; answer from ',
					      $ready->peerhost, ':',
					      $ready->peerport, ' : ',
					      length($buf), " bytes\n"
						if $self->{'debug'};
				
					my ($ans, $err) = Net::DNS::Packet->new(\$buf, $self->{'debug'});
				
					if (defined $ans) {
						next unless $ans->header->qr;
						next unless $ans->header->id == $packet->header->id;
						$self->errorstring($ans->header->rcode);
						$ans->answerfrom($self->answerfrom);
						$ans->answersize($self->answersize);
					} elsif (defined $err) {
						$self->errorstring($err);
					}
					
					return $ans;
				} else {
					$self->errorstring($!);
					
					print ';; recv ERROR(',
					      $ready->peerhost, ':',
					      $ready->peerport, '): ',
					      $self->errorstring, "\n"
						if $self->{'debug'};

					@ns = grep { $_->[0] ne $ready->peerhost } @ns;
					
					return unless @ns;
				}
			}
		}
	}

	if ($sel->handles) {
		$self->errorstring('query timed out');
	}
	else {
		$self->errorstring('all nameservers failed');
	}
	return;
}

=head2 bgsend

    $socket = $res->bgsend($packet_object);
    $socket = $res->bgsend('mailhost.example.com');
    $socket = $res->bgsend('example.com', 'MX');
    $socket = $res->bgsend('user.passwd.example.com', 'TXT', 'HS');

Performs a background DNS query for the given name, i.e., sends a
query packet to the first nameserver listed in C<$res>->C<nameservers>
and returns immediately without waiting for a response.  The program
can then perform other tasks while waiting for a response from the 
nameserver.

The argument list can be either a C<Net::DNS::Packet> object or a list
of strings.  The record type and class can be omitted; they default to
A and IN.  If the name looks like an IP address (4 dot-separated numbers),
then an appropriate PTR query will be performed.

Returns an C<IO::Socket::INET> object.  The program must determine when
the socket is ready for reading and call C<$res>->C<bgread> to get
the response packet.  You can use C<$res>->C<bgisready> or C<IO::Select>
to find out if the socket is ready before reading it.

=cut

sub bgsend {
	my $self = shift;

	unless (@{$self->{'nameservers'}}) {
		$self->errorstring('no nameservers');
		return;
	}

	$self->errorstring($default{'errorstring'});

	my $packet = $self->make_query_packet(@_);
	my $packet_data = $packet->data;

	my $srcaddr = $self->{'srcaddr'};
	my $srcport = $self->{'srcport'};

	my $dstaddr = $self->{'nameservers'}->[0];
	my $dstport = $self->{'port'};

	my $sock = IO::Socket::INET->new(
		Proto => 'udp',
		LocalAddr => $srcaddr,
		LocalPort => ($srcport || undef),
	);

	unless ($sock) {
		$self->errorstring(q|couldn't get socket|);   #'
		return;
	}
	
	my $dst_sockaddr = sockaddr_in($dstport, inet_aton($dstaddr));

	print ";; bgsend($dstaddr:$dstport)\n" if $self->{'debug'};

	unless ($sock->send($packet_data, 0, $dst_sockaddr)) {
		my $err = $!;
		print ";; send ERROR($dstaddr): $err\n" if $self->{'debug'};
		$self->errorstring($err);
		return;
	}

	return $sock;
}

=head2 bgread

    $packet = $res->bgread($socket);
    undef $socket;

Reads the answer from a background query (see L</bgsend>).  The argument
is an C<IO::Socket> object returned by C<bgsend>.

Returns a C<Net::DNS::Packet> object or C<undef> on error.

The programmer should close or destroy the socket object after reading it.

=cut

sub bgread {
	my ($self, $sock) = @_;

	my $buf = '';

	my $peeraddr = $sock->recv($buf, $self->_packetsz);
	
	if ($peeraddr) {
		print ';; answer from ', $sock->peerhost, ':',
		      $sock->peerport, ' : ', length($buf), " bytes\n"
			if $self->{'debug'};

		my ($ans, $err) = Net::DNS::Packet->new(\$buf, $self->{'debug'});
		
		if (defined $ans) {
			$self->errorstring($ans->header->rcode);
		} elsif (defined $err) {
			$self->errorstring($err);
		}
		
		return $ans;
	} else {
		$self->errorstring($!);
		return;
	}
}

=head2 bgisready

    $socket = $res->bgsend('foo.example.com');
    until ($res->bgisready($socket)) {
	# do some other processing
    }
    $packet = $res->bgread($socket);
    $socket = undef;

Determines whether a socket is ready for reading.  The argument is
an C<IO::Socket> object returned by C<$res>->C<bgsend>.

Returns true if the socket is ready, false if not.

=cut

sub bgisready {
	my $self = shift;
	my $sel = Net::DNS::Select->new($os, @_);
	my @ready = $sel->can_read(0.0);
	return @ready > 0;
}

sub make_query_packet {
	my $self = shift;
	my $packet;

	if (ref($_[0]) and $_[0]->isa('Net::DNS::Packet')) {
		$packet = shift;
	} else {
		my ($name, $type, $class) = @_;

		$name  ||= '';
		$type  ||= 'A';
		$class ||= 'IN';

		# If the name looks like an IP address then do an appropriate
		# PTR query.
		if ($name =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
			$name = "$4.$3.$2.$1.in-addr.arpa.";
			$type = 'PTR';
		}

		$packet = Net::DNS::Packet->new($name, $type, $class);
	}

	if ($packet->header->opcode eq 'QUERY') {
		$packet->header->rd($self->{'recurse'});
	}

    if ($self->{'dnssec'}) {
	    # RFC 3225
    	print ";; Adding EDNS extention with UDP packetsize $self->{'udppacketsize'} and DNS OK bit set\n" 
    		if $self->{'debug'};
    	
    	my $optrr = Net::DNS::RR->new(
						Type         => 'OPT',
						Name         => '',
						Class        => $self->{'udppacketsize'},  # Decimal UDPpayload
						ednsflags    => 0x8000, # first bit set see RFC 3225 
				   );
				 
	    $packet->push('additional', $optrr);
	    
	} elsif ($self->{'udppacketsize'} > &Net::DNS::PACKETSZ) {
	    print ";; Adding EDNS extention with UDP packetsize  $self->{'udppacketsize'}.\n" if $self->{'debug'};
	    # RFC 3225
	    my $optrr = Net::DNS::RR->new( 
						Type         => 'OPT',
						Name         => '',
						Class        => $self->{'udppacketsize'},  # Decimal UDPpayload
						TTL          => 0x0000 # RCODE 32bit Hex
				    );
				    
	    $packet->push('additional', $optrr);
	}
	

	if ($self->{'tsig_rr'}) {
		if (!grep { $_->type eq 'TSIG' } $packet->additional) {
			$packet->push('additional', $self->{'tsig_rr'});
		}
	}

	return $packet;
}

=head2 axfr

    @zone = $res->axfr;
    @zone = $res->axfr('example.com');
    @zone = $res->axfr('passwd.example.com', 'HS');

Performs a zone transfer from the first nameserver listed in C<nameservers>.
If the zone is omitted, it defaults to the first zone listed in the resolver's
search list.  If the class is omitted, it defaults to IN.

Returns a list of C<Net::DNS::RR> objects, or C<undef> if the zone
transfer failed.

The redundant SOA record that terminates the zone transfer is not
returned to the caller.

See also L</axfr_start> and L</axfr_next>.

Here's an example that uses a timeout:

    $res->tcp_timeout(10);
    @zone = $res->axfr('example.com');
    if (@zone) {
        foreach $rr (@zone) {
            $rr->print;
        }
    }
    else {
        print 'Zone transfer failed: ', $res->errorstring, "\n";
    }

=cut

sub axfr {
	my $self = shift;
	my @zone;

	if ($self->axfr_start(@_)) {
		my ($rr, $err);
		while (($rr, $err) = $self->axfr_next, $rr && !$err) {
			push @zone, $rr;
		}
		@zone = () if $err && $err ne 'no zone transfer in progress';
	}

	return @zone;
}

sub axfr_old {
	my $self = shift;
	my ($dname, $class) = @_;
	$dname ||= $self->{'searchlist'}->[0];
	$class ||= 'IN';

	unless ($dname) {
		print ";; ERROR: axfr: no zone specified\n" if $self->{'debug'};
		$self->errorstring('no zone');
		return;
	}

	print ";; axfr($dname, $class)\n" if $self->{'debug'};

	unless (@{$self->{'nameservers'}}) {
		$self->errorstring('no nameservers');
		print ";; ERROR: no nameservers\n" if $self->{'debug'};
		return;
	}

	my $packet = $self->make_query_packet($dname, 'AXFR', $class);
	my $packet_data = $packet->data;

	my $ns = $self->{'nameservers'}->[0];

	print ";; axfr nameserver = $ns\n" if $self->{'debug'};

	my $srcport = $self->{'srcport'};

	my $sock;
	my $sock_key = "$ns:$self->{'port'}";

	if ($self->{'persistent_tcp'} && $self->{'sockets'}{$sock_key}) {
		$sock = $self->{'sockets'}{$sock_key};
		print ";; using persistent socket\n" if $self->{'debug'};
	}
	else {

		# IO::Socket carps on errors if Perl's -w flag is turned on.
		# Uncomment the next two lines and the line following the "new"
		# call to turn off these messages.

		my $old_wflag = $^W;
		$^W = 0;

		$sock = IO::Socket::INET->new(
		    PeerAddr  => $ns,
		    PeerPort  => $self->{'port'},
		    LocalAddr => $self->{'srcaddr'},
		    LocalPort => ($srcport || undef),
		    Proto     => 'tcp',
		    Timeout   => $self->{'tcp_timeout'}
		);

		$^W = $old_wflag;

		unless ($sock) {
			$self->errorstring(q|couldn't connect|);
			return;
		}

		$self->{'sockets'}{$sock_key} = $sock;
	}

	my $lenmsg = pack('n', length($packet_data));

	unless ($sock->send($lenmsg)) {
		$self->errorstring($!);
		return;
	}

	unless ($sock->send($packet_data)) {
		$self->errorstring($!);
		return;
	}

	my $sel = Net::DNS::Select->new($os, $sock);

	my @zone;
	my $soa_count = 0;
	my $timeout = $self->{'tcp_timeout'};

	while (1) {
		my @ready = $sel->can_read($timeout);
		unless (@ready) {
			$self->errorstring('timeout');
			return;
		}

		my $buf = read_tcp($sock, &Net::DNS::INT16SZ, $self->{'debug'});
		last unless length($buf);
		my ($len) = unpack('n', $buf);
		last unless $len;

		@ready = $sel->can_read($timeout);
		unless (@ready) {
			$self->errorstring('timeout');
			return;
		}

		$buf = read_tcp($sock, $len, $self->{'debug'});

		print ';; received ', length($buf), " bytes\n"
			if $self->{'debug'};

		unless (length($buf) == $len) {
			$self->errorstring("expected $len bytes, received " . length($buf));
			return;
		}

		my ($ans, $err) = Net::DNS::Packet->new(\$buf, $self->{'debug'});

		if (defined $ans) {
			if ($ans->header->ancount < 1) {
				$self->errorstring($ans->header->rcode);
				last;
			}
		}
		elsif (defined $err) {
			$self->errorstring($err);
			last;
		}

		foreach ($ans->answer) {
			# $_->print if $self->{'debug'};
			if ($_->type eq 'SOA') {
				++$soa_count;
				push @zone, $_ unless $soa_count >= 2;
			}
			else {
				push @zone, $_;
			}
		}

		last if $soa_count >= 2;
	}

	return @zone;
}

=head2 axfr_start

    $res->axfr_start;
    $res->axfr_start('example.com');
    $res->axfr_start('example.com', 'HS');

Starts a zone transfer from the first nameserver listed in C<nameservers>.
If the zone is omitted, it defaults to the first zone listed in the resolver's
search list.  If the class is omitted, it defaults to IN.

Returns the C<IO::Socket::INET> object that will be used for reading, or
C<undef> on error.

Use C<axfr_next> to read the zone records one at a time.

=cut

sub axfr_start {
	my $self = shift;
	my ($dname, $class) = @_;
	$dname ||= $self->{'searchlist'}->[0];
	$class ||= 'IN';

	unless ($dname) {
		print ";; ERROR: axfr: no zone specified\n" if $self->{'debug'};
		$self->errorstring('no zone');
		return;
	}

	print ";; axfr_start($dname, $class)\n" if $self->{'debug'};

	unless (@{$self->{'nameservers'}}) {
		$self->errorstring('no nameservers');
		print ";; ERROR: no nameservers\n" if $self->{'debug'};
		return;
	}

	my $packet = $self->make_query_packet($dname, 'AXFR', $class);
	my $packet_data = $packet->data;

	my $ns = $self->{'nameservers'}->[0];

	print ";; axfr_start nameserver = $ns\n" if $self->{'debug'};

	my $srcport = $self->{'srcport'};

	my $sock;
	my $sock_key = "$ns:$self->{'port'}";

	if ($self->{'persistent_tcp'} && $self->{'sockets'}->{$sock_key}) {
	    $sock = $self->{'sockets'}->{$sock_key};
	    print ";; using persistent socket\n" if $self->{'debug'};
	    
	} else {

		# IO::Socket carps on errors if Perl's -w flag is turned on.
		# Uncomment the next two lines and the line following the "new"
		# call to turn off these messages.

		#my $old_wflag = $^W;
		#$^W = 0;

		$sock = IO::Socket::INET->new(
		    PeerAddr  => $ns,
		    PeerPort  => $self->{'port'},
		    LocalAddr => $self->{'srcaddr'},
		    LocalPort => ($srcport || undef),
		    Proto     => 'tcp',
		    Timeout   => $self->{'tcp_timeout'}
		 );

		#$^W = $old_wflag;

		unless ($sock) {
			$self->errorstring(q|couldn't connect|);
			return;
		}

		$self->{'sockets'}->{$sock_key} = $sock;
	}

	my $lenmsg = pack('n', length($packet_data));

	unless ($sock->send($lenmsg)) {
		$self->errorstring($!);
		return;
	}

	unless ($sock->send($packet_data)) {
		$self->errorstring($!);
		return;
	}

	my $sel = Net::DNS::Select->new($os, $sock);

	$self->{'axfr_sel'}       = $sel;
	$self->{'axfr_rr'}        = [];
	$self->{'axfr_soa_count'} = 0;

	return $sock;
}

=head2 axfr_next

    $res->axfr_start('example.com');
    while ($rr = $res->axfr_next) {
	$rr->print;
    }

Reads records from a zone transfer one at a time.

Returns C<undef> at the end of the zone transfer.  The redundant
SOA record that terminates the zone transfer is not returned.

See also L</axfr>.

=cut

sub axfr_next {
	my $self = shift;
	my $err  = '';

	unless (@{$self->{'axfr_rr'}}) {
		unless ($self->{'axfr_sel'}) {
			$err = 'no zone transfer in progress';
			$self->errorstring($err);
			return wantarray ? (undef, $err) : undef;
		}

		my $sel = $self->{'axfr_sel'};
		my $timeout = $self->{'tcp_timeout'};

		#--------------------------------------------------------------
		# Read the length of the response packet.
		#--------------------------------------------------------------

		my @ready = $sel->can_read($timeout);
		unless (@ready) {
			$err = 'timeout';
			$self->errorstring($err);
			return wantarray ? (undef, $err) : undef;
		}

		my $buf = read_tcp($ready[0], &Net::DNS::INT16SZ, $self->{'debug'});
		unless (length $buf) {
			$err = 'truncated zone transfer';
			$self->errorstring($err);
			return wantarray ? (undef, $err) : undef;
		}

		my ($len) = unpack('n', $buf);
		unless ($len) {
			$err = 'truncated zone transfer';
			$self->errorstring($err);
			return wantarray ? (undef, $err) : undef;
		}

		#--------------------------------------------------------------
		# Read the response packet.
		#--------------------------------------------------------------

		@ready = $sel->can_read($timeout);
		unless (@ready) {
			$err = 'timeout';
			$self->errorstring($err);
			return wantarray ? (undef, $err) : undef;
		}

		$buf = read_tcp($ready[0], $len, $self->{'debug'});

		print ';; received ', length($buf), " bytes\n"
			if $self->{'debug'};

		unless (length($buf) == $len) {
			$err = "expected $len bytes, received " . length($buf);
			$self->errorstring($err);
			print ";; $err\n" if $self->{'debug'};
			return wantarray ? (undef, $err) : undef;
		}

		my $ans;
		($ans, $err) = Net::DNS::Packet->new(\$buf, $self->{'debug'});

		if ($ans) {
			if ($ans->header->ancount < 1) {
				$err = 'truncated zone transfer';
				$self->errorstring($err);
				print ";; $err\n" if $self->{'debug'};
				return wantarray ? (undef, $err) : undef;
			}
		}
		else {
			$err ||= 'unknown error during packet parsing';
			$self->errorstring($err);
			print ";; $err\n" if $self->{'debug'};
			return wantarray ? (undef, $err) : undef;
		}

		foreach my $rr ($ans->answer) {
			if ($rr->type eq 'SOA') {
				if (++$self->{'axfr_soa_count'} < 2) {
					push @{$self->{'axfr_rr'}}, $rr;
				}
			}
			else {
				push @{$self->{'axfr_rr'}}, $rr;
			}
		}

		if ($self->{'axfr_soa_count'} >= 2) {
			$self->{'axfr_sel'} = undef;
		}
	}

	my $rr = shift @{$self->{'axfr_rr'}};

	return wantarray ? ($rr, undef) : $rr;
}

=head2 tsig

    $tsig = $res->tsig;

    $res->tsig(Net::DNS::RR->new("$key_name TSIG $key"));

    $tsig = Net::DNS::RR->new("$key_name TSIG $key");
    $tsig->fudge(60);
    $res->tsig($tsig);

    $res->tsig($key_name, $key);

    $res->tsig(0);

Get or set the TSIG record used to automatically sign outgoing
queries and updates.  Call with an argument of 0 or '' to turn off
automatic signing.

The default resolver behavior is not to sign any packets.  You must
call this method to set the key if you'd like the resolver to sign
packets automatically.

You can also sign packets manually -- see the C<Net::DNS::Packet>
and C<Net::DNS::Update> manual pages for examples.  TSIG records
in manually-signed packets take precedence over those that the
resolver would add automatically.

=cut

sub tsig {
	my $self = shift;

	if (@_ == 1) {
		if ($_[0] && ref($_[0])) {
			$self->{'tsig_rr'} = $_[0];
		}
		else {
			$self->{'tsig_rr'} = undef;
		}
	}
	elsif (@_ == 2) {
		my ($key_name, $key) = @_;
		$self->{'tsig_rr'} = Net::DNS::RR->new("$key_name TSIG $key");
	}

	return $self->{'tsig_rr'};
}

#
# Usage:  $data = read_tcp($socket, $nbytes, $debug);
#
sub read_tcp {
	my ($sock, $nbytes, $debug) = @_;
	my $buf = '';

	while (length($buf) < $nbytes) {
		my $nread = $nbytes - length($buf);
		my $read_buf = '';

		print ";; read_tcp: expecting $nread bytes\n" if $debug;

		# During some of my tests recv() returned undef even
		# though there wasn't an error.  Checking for the amount
		# of data read appears to work around that problem.

		unless ($sock->recv($read_buf, $nread)) {
			if (length($read_buf) < 1) {
				my $errstr = $!;

				print ";; ERROR: read_tcp: recv failed: $!\n"
					if $debug;

				if ($errstr eq 'Resource temporarily unavailable') {
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

=head2 retrans

    print 'retrans interval: ', $res->retrans, "\n";
    $res->retrans(3);

Get or set the retransmission interval.  The default is 5.

=head2 retry

    print 'number of tries: ', $res->retry, "\n";
    $res->retry(2);

Get or set the number of times to try the query.  The default is 4.

=head2 recurse

    print 'recursion flag: ', $res->recurse, "\n";
    $res->recurse(0);

Get or set the recursion flag.  If this is true, nameservers will
be requested to perform a recursive query.  The default is true.

=head2 defnames

    print 'defnames flag: ', $res->defnames, "\n";
    $res->defnames(0);

Get or set the defnames flag.  If this is true, calls to B<query> will
append the default domain to names that contain no dots.  The default
is true.

=head2 dnsrch

    print 'dnsrch flag: ', $res->dnsrch, "\n";
    $res->dnsrch(0);

Get or set the dnsrch flag.  If this is true, calls to B<search> will
apply the search list.  The default is true.

=head2 debug

    print 'debug flag: ', $res->debug, "\n";
    $res->debug(1);

Get or set the debug flag.  If set, calls to B<search>, B<query>,
and B<send> will print debugging information on the standard output.
The default is false.

=head2 usevc

    print 'usevc flag: ', $res->usevc, "\n";
    $res->usevc(1);

Get or set the usevc flag.  If true, then queries will be performed
using virtual circuits (TCP) instead of datagrams (UDP).  The default
is false.

=head2 tcp_timeout

    print 'TCP timeout: ', $res->tcp_timeout, "\n";
    $res->tcp_timeout(10);

Get or set the TCP timeout in seconds.  A timeout of C<undef> means
indefinite.  The default is 120 seconds (2 minutes).

=head2 persistent_tcp

    print 'Persistent TCP flag: ', $res->persistent_tcp, "\n";
    $res->persistent_tcp(1);

Get or set the persistent TCP setting.  If set to true, Net::DNS
will keep a TCP socket open for each host:port to which it connects.
This is useful if you're using TCP and need to make a lot of queries
or updates to the same nameserver.

This option defaults to false unless you're running under a
SOCKSified Perl, in which case it defaults to true.

=head2 igntc

    print 'igntc flag: ', $res->igntc, "\n";
    $res->igntc(1);

Get or set the igntc flag.  If true, truncated packets will be
ignored.  If false, truncated packets will cause the query to
be retried using TCP.  The default is false.

=head2 errorstring

    print 'query status: ', $res->errorstring, "\n";

Returns a string containing the status of the most recent query.

=head2 answerfrom

    print 'last answer was from: ', $res->answerfrom, "\n";

Returns the IP address from which we received the last answer in
response to a query.

=head2 answersize

    print 'size of last answer: ', $res->answersize, "\n";

Returns the size in bytes of the last answer we received in
response to a query.


=head2 dnssec

    print "dnssec flag: ", $res->dnssec, "\n";
    $res->dnssec(0);

Enabled DNSSEC this will set the checking disabled flag in the query header
and add EDNS0 data as in RFC2671 and RFC3225

When set to true the answer and additional section of queries from
secured zones will contain KEY, NXT and SIG records.


=head2 cdflag

    print "checking disabled flag: ", $res->dnssec, "\n";
    $res->dnssec(1);
    $res->cdflag(1);

Sets or gets the CD bit for a dnssec query.  This bit is always zero
for non dnssec queries. When the dnssec is enabled the flag can be set
to 1.

=head2 udppacketsize

    print "udppacketsize: ", $res->udppacketsize, "\n";
    $res->udppacketsize(2048);

udppacketsize will set or get the packet size. If set to a value greater than 
&Net::DNS::PACKETSZ an EDNS extention will be added indicating suppport for MTU path 
recovery.

Default udppacketsize is &Net::DNS::PACKETSZ (512)
=cut

sub AUTOLOAD {
	my ($self) = @_;

	my $name = $AUTOLOAD;
	$name =~ s/.*://;

	Carp::croak "$name: no such method" unless exists $self->{$name};
	
	no strict q/refs/;
	
	*{$AUTOLOAD} = sub {
		my ($self, $new_val) = @_;
		
		if (defined $new_val) {
			$self->{"$name"} = $new_val;
		}
		
		return $self->{"$name"};
	};
	
	goto &{$AUTOLOAD};	
}

=head1 ENVIRONMENT

The following environment variables can also be used to configure
the resolver:

=head2 RES_NAMESERVERS

    # Bourne Shell
    RES_NAMESERVERS="192.168.1.1 192.168.2.2 192.168.3.3"
    export RES_NAMESERVERS

    # C Shell
    setenv RES_NAMESERVERS "192.168.1.1 192.168.2.2 192.168.3.3"

A space-separated list of nameservers to query.

=head2 RES_SEARCHLIST

    # Bourne Shell
    RES_SEARCHLIST="example.com sub1.example.com sub2.example.com"
    export RES_SEARCHLIST

    # C Shell
    setenv RES_SEARCHLIST "example.com sub1.example.com sub2.example.com"

A space-separated list of domains to put in the search list.

=head2 LOCALDOMAIN

    # Bourne Shell
    LOCALDOMAIN=example.com
    export LOCALDOMAIN

    # C Shell
    setenv LOCALDOMAIN example.com

The default domain.

=head2 RES_OPTIONS

    # Bourne Shell
    RES_OPTIONS="retrans:3 retry:2 debug"
    export RES_OPTIONS

    # C Shell
    setenv RES_OPTIONS "retrans:3 retry:2 debug"

A space-separated list of resolver options to set.  Options that
take values are specified as I<option>:I<value>.

=head1 BUGS

Error reporting and handling needs to be improved.

The current implementation supports TSIG only on outgoing packets.
No validation of server replies is performed.

=head1 COPYRIGHT

Copyright (c) 1997-2000 Michael Fuhr.  All rights reserved.  This
program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. 

=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Packet>, L<Net::DNS::Update>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
L<resolver(5)>, RFC 1035, RFC 1034 Section 4.3.5

=cut

res_init();

1;
