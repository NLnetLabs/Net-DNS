package Net::DNS::Header;

use strict;
use warnings;

our $VERSION = (qw$Id$)[2];


=head1 NAME

Net::DNS::Header - DNS packet header

=head1 SYNOPSIS

    use Net::DNS;

    $packet = Net::DNS::Packet->new();
    $header = $packet->header;


=head1 DESCRIPTION

C<Net::DNS::Header> represents the header portion of a DNS packet.

=cut


use integer;
use Carp;

use Net::DNS::Parameters qw(:opcode :rcode);


=head1 METHODS


=head2 $packet->header

    $packet = Net::DNS::Packet->new();
    $header = $packet->header;

Net::DNS::Header objects emanate from the Net::DNS::Packet header()
method, and contain an opaque reference to the parent Packet object.

Header objects may be assigned to suitably scoped lexical variables.
They should never be stored in global variables or persistent data
structures.


=head2 string

    print $packet->header->string;

Returns a string representation of the packet header.

=cut

sub string {
	my $self = shift;

	my $id	   = $self->id;
	my $qr	   = $self->qr;
	my $opcode = $self->opcode;
	my $rcode  = $self->rcode;
	my $qd	   = $self->qdcount;
	my $an	   = $self->ancount;
	my $ns	   = $self->nscount;
	my $ar	   = $self->arcount;

	my $opt	 = $$self->edns;
	my $edns = $opt->_specified ? $opt->string : '';

	return <<END . $edns if $opcode eq 'UPDATE';
;;	id = $id
;;	qr = $qr		opcode = $opcode	rcode = $rcode
;;	zocount = $qd	prcount = $an	upcount = $ns	adcount = $ar
END

	my $aa = $self->aa;
	my $tc = $self->tc;
	my $rd = $self->rd;
	my $ra = $self->ra;
	my $zz = $self->z;
	my $ad = $self->ad;
	my $cd = $self->cd;
	my $do = $self->do;

	return <<END . $edns;
;;	id = $id
;;	qr = $qr	aa = $aa	tc = $tc	rd = $rd	opcode = $opcode
;;	ra = $ra	z  = $zz	ad = $ad	cd = $cd	rcode  = $rcode
;;	qdcount = $qd	ancount = $an	nscount = $ns	arcount = $ar
;;	do = $do
END
}


=head2 print

    $packet->header->print;

Prints the string representation of the packet header.

=cut

sub print {
	print &string;
	return;
}


=head2 id

    print "query id = ", $packet->header->id, "\n";
    $packet->header->id(1234);

Gets or sets the query identification number.

A random value is assigned if the argument value is undefined.

=cut

my ( $cache1, $cache2, $limit );				# two layer cache

sub id {
	my $self  = shift;
	my $ident = scalar(@_) ? ( $$self->{id} = shift ) : $$self->{id};
	return $ident if $ident;
	$ident = int rand(0xffff);				# preserve short-term uniqueness
	$ident = int rand(0xffff) while $cache1->{$ident}++ + exists( $cache2->{$ident} );
	( $cache1, $cache2, $limit ) = ( {0 => 1}, $cache1, 50 ) unless $limit--;
	return $$self->{id} = $ident;
}


=head2 opcode

    print "query opcode = ", $packet->header->opcode, "\n";
    $packet->header->opcode("UPDATE");

Gets or sets the query opcode (the purpose of the query).

=cut

sub opcode {
	my ( $self, $arg ) = @_;
	my $opcode;
	for ( $$self->{status} ) {
		return opcodebyval( ( $_ >> 11 ) & 0x0f ) unless defined $arg;
		$opcode = opcodebyname($arg);
		$_	= ( $_ & 0x87ff ) | ( $opcode << 11 );
	}
	return $opcode;
}


=head2 rcode

    print "query response code = ", $packet->header->rcode, "\n";
    $packet->header->rcode("SERVFAIL");

Gets or sets the query response code (the status of the query).

=cut

sub rcode {
	my ( $self, $arg ) = @_;
	my $rcode;
	for ( $$self->{status} ) {
		my $opt = $$self->edns;
		unless ( defined $arg ) {
			$rcode = ( $opt->rcode & 0xff0 ) | ( $_ & 0x00f );
			$opt->rcode($rcode);			# write back full 12-bit rcode
			return $rcode == 16 ? 'BADVERS' : rcodebyval($rcode);
		}
		$rcode = rcodebyname($arg);
		$opt->rcode($rcode);				# full 12-bit rcode
		$_ &= 0xfff0;					# low 4-bit rcode
		$_ |= ( $rcode & 0x000f );
	}
	return $rcode;
}


=head2 qr

    print "query response flag = ", $packet->header->qr, "\n";
    $packet->header->qr(0);

Gets or sets the query response flag.

=cut

sub qr {
	return shift->_dnsflag( 0x8000, @_ );
}


=head2 aa

    print "response is ", $packet->header->aa ? "" : "non-", "authoritative\n";
    $packet->header->aa(0);

Gets or sets the authoritative answer flag.

=cut

sub aa {
	return shift->_dnsflag( 0x0400, @_ );
}


=head2 tc

    print "packet is ", $packet->header->tc ? "" : "not ", "truncated\n";
    $packet->header->tc(0);

Gets or sets the truncated packet flag.

=cut

sub tc {
	return shift->_dnsflag( 0x0200, @_ );
}


=head2 rd

    print "recursion was ", $packet->header->rd ? "" : "not ", "desired\n";
    $packet->header->rd(0);

Gets or sets the recursion desired flag.

=cut

sub rd {
	return shift->_dnsflag( 0x0100, @_ );
}


=head2 ra

    print "recursion is ", $packet->header->ra ? "" : "not ", "available\n";
    $packet->header->ra(0);

Gets or sets the recursion available flag.

=cut

sub ra {
	return shift->_dnsflag( 0x0080, @_ );
}


=head2 z

Unassigned bit, should always be zero.

=cut

sub z {
	return shift->_dnsflag( 0x0040, @_ );
}


=head2 ad

    print "The response has ", $packet->header->ad ? "" : "not", "been verified\n";

Relevant in DNSSEC context.

(The AD bit is only set on a response where signatures have been
cryptographically verified or the server is authoritative for the data
and is allowed to set the bit by policy.)

=cut

sub ad {
	return shift->_dnsflag( 0x0020, @_ );
}


=head2 cd

    print "checking was ", $packet->header->cd ? "not" : "", "desired\n";
    $packet->header->cd(0);

Gets or sets the checking disabled flag.

=cut

sub cd {
	return shift->_dnsflag( 0x0010, @_ );
}


=head2 qdcount, zocount

    print "# of question records: ", $packet->header->qdcount, "\n";

Returns the number of records in the question section of the packet.
In dynamic update packets, this field is known as C<zocount> and refers
to the number of RRs in the zone section.

=cut

our $warned;

sub qdcount {
	my $self = shift;
	return $$self->{count}[0] || scalar @{$$self->{question}} unless scalar @_;
	carp 'packet->header->qdcount attribute is read-only'	  unless $warned++;
	return;
}


=head2 ancount, prcount

    print "# of answer records: ", $packet->header->ancount, "\n";

Returns the number of records in the answer section of the packet
which may, in the case of corrupt packets, differ from the actual
number of records.
In dynamic update packets, this field is known as C<prcount> and refers
to the number of RRs in the prerequisite section.

=cut

sub ancount {
	my $self = shift;
	return $$self->{count}[1] || scalar @{$$self->{answer}} unless scalar @_;
	carp 'packet->header->ancount attribute is read-only'	unless $warned++;
	return;
}


=head2 nscount, upcount

    print "# of authority records: ", $packet->header->nscount, "\n";

Returns the number of records in the authority section of the packet
which may, in the case of corrupt packets, differ from the actual
number of records.
In dynamic update packets, this field is known as C<upcount> and refers
to the number of RRs in the update section.

=cut

sub nscount {
	my $self = shift;
	return $$self->{count}[2] || scalar @{$$self->{authority}} unless scalar @_;
	carp 'packet->header->nscount attribute is read-only'	   unless $warned++;
	return;
}


=head2 arcount, adcount

    print "# of additional records: ", $packet->header->arcount, "\n";

Returns the number of records in the additional section of the packet
which may, in the case of corrupt packets, differ from the actual
number of records.
In dynamic update packets, this field is known as C<adcount>.

=cut

sub arcount {
	my $self = shift;
	return $$self->{count}[3] || scalar @{$$self->{additional}} unless scalar @_;
	carp 'packet->header->arcount attribute is read-only'	    unless $warned++;
	return;
}

sub zocount { return &qdcount; }
sub prcount { return &ancount; }
sub upcount { return &nscount; }
sub adcount { return &arcount; }


=head1 EDNS Protocol Extensions


=head2 do

    print "DNSSEC_OK flag was ", $packet->header->do ? "not" : "", "set\n";
    $packet->header->do(1);

Gets or sets the EDNS DNSSEC OK flag.

=cut

sub do {
	return shift->_ednsflag( 0x8000, @_ );
}


=head2 Extended rcode

EDNS extended rcodes are handled transparently by $packet->header->rcode().


=head2 UDP packet size

    $udp_max = $packet->header->size;
    $udp_max = $packet->edns->size;

EDNS offers a mechanism to advertise the maximum UDP packet size
which can be assembled by the local network stack.

UDP size advertisement can be viewed as either a header extension or
an EDNS feature.  Endless debate is avoided by supporting both views.

=cut

sub size {
	my $self = shift;
	return $$self->edns->size(@_);
}


=head2 edns

    $header  = $packet->header;
    $version = $header->edns->version;
    @options = $header->edns->options;
    $option  = $header->edns->option(n);
    $udp_max = $packet->edns->size;

Auxiliary function which provides access to the EDNS protocol
extension OPT RR.

=cut

sub edns {
	my $self = shift;
	return $$self->edns;
}


########################################

sub _dnsflag {
	my $self = shift;
	my $flag = shift;
	for ( $$self->{status} ) {
		my $set = $_ | $flag;
		$_ = (shift) ? $set : ( $set ^ $flag ) if scalar @_;
		$flag &= $_;
	}
	return $flag ? 1 : 0;
}


sub _ednsflag {
	my $self = shift;
	my $flag = shift;
	my $edns = $$self->edns;
	for ( $edns->flags ) {
		my $set = $_ | $flag;
		$edns->flags( $_ = (shift) ? $set : ( $set ^ $flag ) ) if scalar @_;
		$flag &= $_;
	}
	return $flag ? 1 : 0;
}


1;
__END__


########################################

=head1 COPYRIGHT

Copyright (c)1997 Michael Fuhr.

Portions Copyright (c)2002,2003 Chris Reinhardt.

Portions Copyright (c)2012,2022 Dick Franks.

All rights reserved.


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted, provided
that the original copyright notices appear in all copies and that both
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

L<perl>, L<Net::DNS>, L<Net::DNS::Packet>, L<Net::DNS::RR::OPT>,
L<RFC1035(4.1.1)|https://tools.ietf.org/html/rfc1035>

=cut

