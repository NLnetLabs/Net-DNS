package Net::DNS::Packet;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::Packet - DNS protocol packet

=head1 SYNOPSIS

    use Net::DNS::Packet;

    $query = new Net::DNS::Packet('example.com', 'MX', 'IN');

    $reply = $resolver->send($query);


=head1 DESCRIPTION

A C<Net::DNS::Packet> object represents a DNS protocol packet.

=cut


use base Exporter;
@EXPORT_OK = qw(dn_expand);

use strict;
use integer;
use Carp;

use Net::DNS::Header;
use Net::DNS::Question;
use Net::DNS::RR;


=head1 METHODS

=head2 new

    $packet = new Net::DNS::Packet('example.com');
    $packet = new Net::DNS::Packet('example.com', 'MX', 'IN');

    $packet = new Net::DNS::Packet();

If passed a domain, type, and class, C<new> creates a packet
object appropriate for making a DNS query for the requested
information.  The type and class can be omitted; they default
to A and IN.

If called with an empty argument list, C<new> creates an empty packet.

=cut

sub new {
	return &decode if ref $_[1];
	my $class = shift;

	my $self = bless {
		question   => [],
		answer	   => [],
		authority  => [],
		additional => []}, $class;

	$self->{question} = [Net::DNS::Question->new(@_)] if @_;

	$self->header->rd(1);
	return $self;
}


#=head2 decode

=pod

    $packet = new Net::DNS::Packet(\$data);
    $packet = new Net::DNS::Packet(\$data, 1);		# set debugging

If passed a reference to a scalar containing DNS packet data,
a new packet object is created by decoding the data.  The optional
second boolean argument is used to enable debugging output.

Returns undef if unable to create a packet object.

Decoding errors, including data corruption and truncation,
are collected in the $@ ($EVAL_ERROR) variable.


    ($packet, $length) = new Net::DNS::Packet(\$data);

If called in array context, returns a packet object and the
number of octets successfully decoded.

=cut

use constant HEADER_LENGTH => length pack 'n6', (0) x 6;

sub decode {
	my $class = shift;
	my $data  = shift;
	my $debug = shift || 0;

	my $offset = 0;
	my $self;
	eval {
		die 'corrupt wire-format data' if length($$data) < HEADER_LENGTH;

		$self = bless {
			question   => [],
			answer	   => [],
			authority  => [],
			additional => [],
			answersize => length $$data
			}, $class;

		# header section
		my $header = $self->header;
		$header->decode($data);
		my ( $qd, $an, $ns, $ar ) = map { $header->$_ } qw(qdcount ancount nscount arcount);
		$offset = HEADER_LENGTH;

		# question/zone section
		my $hash = {};
		my $record;
		while ( $qd-- ) {
			( $record, $offset ) = decode Net::DNS::Question( $data, $offset, $hash );
			CORE::push( @{$self->{question}}, $record );
		}

		# RR sections
		while ( $an-- ) {
			( $record, $offset ) = decode Net::DNS::RR( $data, $offset, $hash );
			CORE::push( @{$self->{answer}}, $record );
		}

		while ( $ns-- ) {
			( $record, $offset ) = decode Net::DNS::RR( $data, $offset, $hash );
			CORE::push( @{$self->{authority}}, $record );
		}

		while ( $ar-- ) {
			( $record, $offset ) = decode Net::DNS::RR( $data, $offset, $hash );
			CORE::push( @{$self->{additional}}, $record );
		}
	};

	if ( $debug && $self ) {
		local $@;
		$self->print;
	}

	return wantarray ? ( $self, $offset ) : $self;
}


=head2 data

    $data = $packet->data;
    $data = $packet->data($limit);

Returns the packet data in binary format, suitable for sending to
a nameserver.

=cut


sub encode {&data}

sub data {
	my $self = shift;

	for ( my $edns = $self->edns ) {			# EDNS support
		my @xopt = grep { $_->type ne 'OPT' } @{$self->{additional}};
		$self->{additional} = $edns->default ? [@xopt] : [$edns, @xopt];
	}

	my $data = $self->header->encode;			# packet header

	my $hash = {};						# packet body
	foreach my $component ( @{$self->{question}},
				@{$self->{answer}},
				@{$self->{authority}},
				@{$self->{additional}}	) {
		$data .= $component->encode( length $data, $hash, $self );
	}

	return $data;
}


=head2 header

    $header = $packet->header;

Constructor method which returns a reference to the unique
C<Net::DNS::Header> object which represents the header section
of the packet.

=cut

sub header {
	my $self = shift;
	$self->{header} ||= new Net::DNS::Header($self);
}


=head2 EDNS extended header

    $edns    = $packet->edns;
    $version = $edns->version;
    $size    = $edns->size;

Auxilliary function edns() provides access to EDNS extensions.

=cut

sub edns {
	shift->header->edns;
}


=head2 reply

    $reply = $query->reply( $UDPmax );

Constructor method which returns a new reply packet.

The optional UDPsize argument is the maximum UDP packet size which
can be reassembled by the local network stack, and is advertised in
response to an EDNS query.

=cut

sub reply {
	my $query  = shift;
	my $UDPmax = shift;
	die 'erroneous qr flag in query packet' if $query->header->qr;

	my $reply  = new Net::DNS::Packet();
	my $header = $reply->header;
	$header->qr(1);						# reply with same id, opcode and question
	$header->id( $query->header->id );
	$header->opcode( $query->header->opcode );
	$reply->{question} = [$query->question];

	$header->rcode('FORMERR');				# failure to provide RCODE is sinful!

	$header->rd( $query->header->rd );			# copy these flags into reply
	$header->cd( $query->header->cd );

	$reply->edns->size($UDPmax) unless $query->edns->default;
	return $reply;
}


=head2 question, zone

    @question = $packet->question;

Returns a list of C<Net::DNS::Question> objects representing the
question section of the packet.

In dynamic update packets, this section is known as C<zone> and
specifies the zone to be updated.

=cut

sub question {
	return @{shift->{question}};
}

sub zone {&question}


=head2 answer, pre, prerequisite

    @answer = $packet->answer;

Returns a list of C<Net::DNS::RR> objects representing the answer
section of the packet.

In dynamic update packets, this section is known as C<pre> or
C<prerequisite> and specifies the RRs or RRsets which must or
must not preexist.

=cut

sub answer {
	return @{shift->{answer}};
}

sub pre		 {&answer}
sub prerequisite {&answer}


=head2 authority, update

    @authority = $packet->authority;

Returns a list of C<Net::DNS::RR> objects representing the authority
section of the packet.

In dynamic update packets, this section is known as C<update> and
specifies the RRs or RRsets to be added or deleted.

=cut

sub authority {
	return @{shift->{authority}};
}

sub update {&authority}


=head2 additional

    @additional = $packet->additional;

Returns a list of C<Net::DNS::RR> objects representing the additional
section of the packet.

=cut

sub additional {
	return @{shift->{additional}};
}


=head2 print

    $packet->print;

Prints the packet data on the standard output in an ASCII format
similar to that used in DNS zone files.

=cut

sub print { print &string; }


=head2 string

    print $packet->string;

Returns a string representation of the packet.

=cut

sub string {
	my $self = shift;

	my $header = $self->header;
	my $update = $header->opcode eq 'UPDATE';

	my $server = $self->{answerfrom};
	my $string = $server ? ";; Answer received from $server ($self->{answersize} bytes)\n" : "";

	$string .= ";; HEADER SECTION\n" . $header->string;

	my $question = $update ? 'ZONE' : 'QUESTION';
	my @question = map $_->string, $self->question;
	my $qdcount  = scalar @question;
	my $qds	     = $qdcount != 1 ? 's' : '';
	$string .= join "\n;; ", "\n;; $question SECTION ($qdcount record$qds)", @question;

	my $answer = $update ? 'PREREQUISITE' : 'ANSWER';
	my @answer  = map $_->string, $self->answer;
	my $ancount = scalar @answer;
	my $ans	    = $ancount != 1 ? 's' : '';
	$string .= join "\n", "\n\n;; $answer SECTION ($ancount record$ans)", @answer;

	my $authority = $update ? 'UPDATE' : 'AUTHORITY';
	my @authority = map $_->string, $self->authority;
	my $nscount   = scalar @authority;
	my $nss	      = $nscount != 1 ? 's' : '';
	$string .= join "\n", "\n\n;; $authority SECTION ($nscount record$nss)", @authority;

	my @additional = map $_->string, $self->additional;
	my $arcount    = scalar @additional;
	my $ars	       = $arcount != 1 ? 's' : '';
	$string .= join "\n", "\n\n;; ADDITIONAL SECTION ($arcount record$ars)", @additional;

	return "$string\n\n";
}


=head2 answerfrom

    print "packet received from ", $packet->answerfrom, "\n";

Returns the IP address from which we received this packet.  User-created
packets will return undef for this method.

=cut

sub answerfrom {
	my $self = shift;

	return $self->{answerfrom} = shift if @_;

	return $self->{answerfrom};
}


=head2 answersize

    print "packet size: ", $packet->answersize, " bytes\n";

Returns the size of the packet in bytes as it was received from a
nameserver.  User-created packets will return undef for this method
(use C<< length $packet->data >> instead).

=cut

sub answersize {
	return shift->{answersize};
}


=head2 push

    $ancount = $packet->push(prereq => $rr);
    $nscount = $packet->push(update => $rr);
    $arcount = $packet->push(additional => $rr);

    $nscount = $packet->push(update => $rr1, $rr2, $rr3);
    $nscount = $packet->push(update => @rr);

Adds RRs to the specified section of the packet.

Returns the number of resource records in the specified section.

=cut

sub push {
	my $self    = shift;
	my $section = lc shift || '';
	my @rr	    = grep ref($_), @_;

	for ($section) {
		return CORE::push( @{$self->{question}}, @rr ) if /^question/;

		if ( $self->header->opcode eq 'UPDATE' ) {
			my ($zone) = $self->zone;
			my $zclass = $zone->zclass;
			foreach (@rr) {
				$_->class($zclass) unless $_->class =~ /ANY|NONE/;
			}
		}

		return CORE::push( @{$self->{answer}},	   @rr ) if /^ans|^pre/;
		return CORE::push( @{$self->{authority}},  @rr ) if /^auth|^upd/;
		return CORE::push( @{$self->{additional}}, @rr ) if /^add/;
	}

	carp qq(invalid section "$section");
	return undef;
}


=head2 unique_push

    $ancount = $packet->unique_push(prereq => $rr);
    $nscount = $packet->unique_push(update => $rr);
    $arcount = $packet->unique_push(additional => $rr);

    $nscount = $packet->unique_push(update => $rr1, $rr2, $rr3);
    $nscount = $packet->unique_push(update => @rr);

Adds RRs to the specified section of the packet provided that
the RRs do not already exist in the packet.

Returns the number of resource records in the specified section.

=cut

sub unique_push {
	my $self    = shift;
	my $section = shift;
	my @rr	    = grep ref($_), @_;

	my @unique = grep !$self->{seen}->{lc( $_->name ) . $_->class . $_->type . $_->rdatastr}++, @rr;

	return $self->push( $section, @unique );
}

sub safe_push {
	carp('safe_push() is deprecated, please use unique_push() instead,');
	&unique_push;
}


=head2 pop

    my $rr = $packet->pop("pre");
    my $rr = $packet->pop("update");
    my $rr = $packet->pop("additional");
    my $rr = $packet->pop("question");

Removes RRs from the specified section of the packet.

=cut

sub pop {
	my $self = shift;
	my $section = lc shift || '';

	for ($section) {
		return CORE::pop( @{$self->{additional}} ) if /^add/;
		return CORE::pop( @{$self->{answer}} )	   if /^ans|^pre/;
		return CORE::pop( @{$self->{authority}} )  if /^auth|^upd/;
		return CORE::pop( @{$self->{question}} )   if /^question/;
	}

	carp qq(invalid section "$section");
	return undef;
}



=head2 dn_comp

    $compname = $packet->dn_comp("foo.example.com", $offset);

Returns a domain name compressed for a particular packet object, to
be stored beginning at the given offset within the packet data.  The
name will be added to a running list of compressed domain names for
future use.

=cut

sub dn_comp {
	my ($self, $fqdn, $offset) = @_;

	my @labels = Net::DNS::name2labels($fqdn);
	my $hash   = $self->{compnames};
	my $data   = '';
	while (@labels) {
		my $name = join( '.', @labels );

		return $data . pack( 'n', 0xC000 | $hash->{$name} ) if defined $hash->{$name};

		my $label = shift @labels;
		my $length = length($label) || next;		   # skip if null
		if ( $length > 63 ) {
			$length = 63;
			$label = substr( $label, 0, $length );
			carp "\n$label...\ntruncated to $length octets (RFC1035 2.3.1)";
		}
		$data .= pack( 'C a*', $length, $label );

		next unless $offset < 0x4000;
		$hash->{$name} = $offset;
		$offset += 1 + $length;
	}
	$data .= chr(0);
}


=head2 dn_expand

    use Net::DNS::Packet qw(dn_expand);
    ($name, $nextoffset) = dn_expand(\$data, $offset);

    ($name, $nextoffset) = Net::DNS::Packet::dn_expand(\$data, $offset);

Expands the domain name stored at a particular location in a DNS
packet.  The first argument is a reference to a scalar containing
the packet data.  The second argument is the offset within the
packet where the (possibly compressed) domain name is stored.

Returns the domain name and the offset of the next location in the
packet.

Returns undef if the domain name could not be expanded.

=cut


# This is very hot code, so we try to keep things fast.  This makes for
# odd style sometimes.

sub dn_expand {
#FYI	my ($packet, $offset) = @_;
	return dn_expand_XS(@_) if $Net::DNS::HAVE_XS;
#	warn "USING PURE PERL dn_expand()\n";
	return dn_expand_PP(@_, {} );	# $packet, $offset, anonymous hash
}

sub dn_expand_PP {
	my ($packet, $offset, $visited) = @_;
	my $packetlen = length $$packet;
	my $name = '';

	while ( $offset < $packetlen ) {
		unless ( my $length = unpack("\@$offset C", $$packet) ) {
			$name =~ s/\.$//o;
			return ($name, ++$offset);

		} elsif ( ($length & 0xc0) == 0xc0 ) {		# pointer
			my $point = 0x3fff & unpack("\@$offset n", $$packet);
			die 'Exception: unbounded name expansion' if $visited->{$point}++;

			my ($suffix) = dn_expand_PP($packet, $point, $visited);

			return ($name.$suffix, $offset+2) if defined $suffix;

		} else {
			my $element = substr($$packet, ++$offset, $length);
			$name .= Net::DNS::wire2presentation($element).'.';
			$offset += $length;
		}
	}
	return undef;
}


=head2 sign_tsig

    $key_name = "tsig-key";
    $key      = "awwLOtRfpGE+rRKF2+DEiw==";

    $update = Net::DNS::Update->new("example.com");
    $update->push("update", rr_add("foo.example.com A 10.1.2.3"));

    $update->sign_tsig($key_name, $key);

    $response = $res->send($update);

Attaches a TSIG resource record object containing a key, which will
be used to sign a packet with a TSIG resource record (see RFC 2845).
Uses the following defaults:

    algorithm   = HMAC-MD5.SIG-ALG.REG.INT
    time_signed = current time
    fudge       = 300 seconds

If you wish to customize the TSIG record, you'll have to create it
yourself and call the appropriate Net::DNS::RR::TSIG methods.  The
following example creates a TSIG record and sets the fudge to 60
seconds:

    $key_name = "tsig-key";
    $key      = "awwLOtRfpGE+rRKF2+DEiw==";

    $tsig = Net::DNS::RR->new("$key_name TSIG $key");
    $tsig->fudge(60);

    $query = Net::DNS::Packet->new("www.example.com");
    $query->sign_tsig($tsig);

    $response = $res->send($query);

=cut

sub sign_tsig {
	my $self = shift;
	my $tsig = shift || return undef;

	unless ( ref $tsig && ($tsig->type eq "TSIG") ) {
		my $key = shift || return undef;
		$tsig = Net::DNS::RR->new("$tsig TSIG $key");
	}

	my @additional = grep { $_->type ne 'TSIG' } @{$self->{additional}};
	my $arcount = scalar @{$self->{additional}};
	carp("A TSIG RR is already present, removing...") if scalar @additional < $arcount;

	CORE::push( @additional, $tsig ) if $tsig;
	@{$self}{additional} = [@additional];
	return $tsig;
}


=head2 sign_sig0

SIG0 support is provided through the Net::DNS::RR::SIG class. This class is not part
of the default Net::DNS distribution but resides in the Net::DNS::SEC distribution.

    $update = Net::DNS::Update->new("example.com");
    $update->push("update", rr_add("foo.example.com A 10.1.2.3"));
    $update->sign_sig0("Kexample.com+003+25317.private");


SIG0 support is experimental see Net::DNS::RR::SIG for details.

The method will call C<Carp::croak()> if Net::DNS::RR::SIG cannot be found.

=cut

sub sign_sig0 {
	my $self = shift;
	my $arg = shift || return undef;
	my $sig0;

	croak('sign_sig0() is only available when Net::DNS::SEC is installed')
		unless $Net::DNS::DNSSEC;

	if ( ref $arg ) {
		if ( UNIVERSAL::isa($arg,'Net::DNS::RR::SIG') ) {
			$sig0 = $arg;

		} elsif ( UNIVERSAL::isa($arg,'Net::DNS::SEC::Private') ) {
			$sig0 = Net::DNS::RR::SIG->create('', $arg);

		} elsif ( UNIVERSAL::isa($arg,'Net::DNS::RR::SIG::Private') ) {
			carp ref($arg).' is deprecated - use Net::DNS::SEC::Private instead';
			$sig0 = Net::DNS::RR::SIG->create('', $arg);

		} else {
			croak 'Incompatible class as argument to sign_sig0: '.ref($arg);

		}

	} else {
		$sig0 = Net::DNS::RR::SIG->create('', $arg);
	}

	$self->push('additional', $sig0) if $sig0;
	return $sig0;
}


=head2 truncate

The truncate method takes a maximum length as argument and then tries
to truncate the packet an set the TC bit according to the rules of
RFC2181 Section 9.

The minimum maximum length that is honored is 512 octets.

=cut

# From RFC2181:
#9. The TC (truncated) header bit
#
#   The TC bit should be set in responses only when an RRSet is required
#   as a part of the response, but could not be included in its entirety.
#   The TC bit should not be set merely because some extra information
#   could have been included, but there was insufficient room.  This
#   includes the results of additional section processing.  In such cases
#   the entire RRSet that will not fit in the response should be omitted,
#   and the reply sent as is, with the TC bit clear.  If the recipient of
#   the reply needs the omitted data, it can construct a query for that
#   data and send that separately.
#
#   Where TC is set, the partial RRSet that would not completely fit may
#   be left in the response.  When a DNS client receives a reply with TC
#   set, it should ignore that response, and query again, using a
#   mechanism, such as a TCP connection, that will permit larger replies.

# Code inspired on a contribution from Aaron Crane via rt.cpan.org 33547

sub truncate {
	my $self=shift;
	my $max_len=shift;
	my $debug=0;
	$max_len=$max_len>512?$max_len:512;

	print "Truncating to $max_len\n" if $debug;

	if (length $self->data() > $max_len) {
		# first remove data from the additional section
		while (length $self->data() > $max_len){
			# first remove _complete_ RRstes from the additonal section.
			my $popped= CORE::pop(@{$self->{'additional'}});
			last unless defined($popped);
			print "Removed ".$popped->string." from additional \n" if $debug;
			my $i=0;
			my @stripped_additonal;

			while ($i< @{$self->{'additional'}}){
				#remove all of these same RRtypes
				if  (
				    ${$self->{'additional'}}[$i]->type eq $popped->type &&
				    ${$self->{'additional'}}[$i]->name eq $popped->name &&
				    ${$self->{'additional'}}[$i]->class eq $popped->class ){
					print "       Also removed ". ${$self->{'additional'}}[$i]->string." from additonal \n" if $debug;				}else{
					CORE::push @stripped_additonal,  ${$self->{'additional'}}[$i];
				}
				$i++;
			}
			$self->{'additional'}=\@stripped_additonal;
		}

		return $self if length $self->data <= $max_len;

      		my @sections = qw<authority answer question>;
		while (@sections) {
			while (my $popped=$self->pop($sections[0])) {
				last unless defined($popped);
				print "Popped ".$popped->string." from the $sections[0] section\n" if $debug;
				$self->header->tc(1);
				return $self if length $self->data <= $max_len;
				next;
			}
			shift @sections;
		}
	}
	return $self;
}


sub dump {				## print internal data structure
	use Data::Dumper;
	$Data::Dumper::Sortkeys = sub { return [sort keys %{$_[0]}] };
	my $self = shift;
	return Dumper($self) if defined wantarray;
	print Dumper($self);
}


1;
__END__


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr.

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2002-2009 Olaf Kolkman

Portions Copyright (c)2007-2008 Dick Franks

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Update>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC 1035 Section 4.1, RFC 2136 Section 2, RFC 2845

=cut

