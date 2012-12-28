package Net::DNS::RR::HIP;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Unchanged since 1063

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::HIP - DNS HIP resource record

=cut


use strict;
use integer;

use Carp;
use Net::DNS::DomainName;
use MIME::Base64;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my ( $hitlen, $pklen ) = unpack "\@$offset Cxn", $$data;
	@{$self}{qw(pkalgorithm hitbin keybin)} = unpack "\@$offset xCxx a$hitlen a$pklen", $$data;

	my $limit = $offset + $self->{rdlength};
	$offset += 4 + $hitlen + $pklen;
	$self->{servers} = [];
	while ( $offset < $limit ) {
		my $item;
		( $item, $offset ) = decode Net::DNS::DomainName($data,$offset );
		push @{$self->{servers}}, $item;
	}
	croak('corrupt HIP data') unless $offset == $limit;	# more or less FUBAR
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{hitbin};
	my $hit = $self->hitbin;
	my $key = $self->keybin;
	my $nos = pack 'C2n a* a*', length($hit), $self->pkalgorithm, length($key), $hit, $key;
	join '', $nos, map $_->encode, @{$self->{servers}};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{hitbin};
	my $algorithm = $self->pkalgorithm;
	my $hit	      = $self->hit;
	my $base64    = MIME::Base64::encode $self->keybin, "";
	my @servers   = map $_->string, @{$self->{servers}};
	return "$algorithm $hit (\n$base64\n@servers )";
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(pkalgorithm hit);
	$self->key( grep { $_ !~ /[.]/ } @_ );
	$self->servers( grep { $_ =~ /[.]/ } @_ );
}


sub pkalgorithm {
	my $self = shift;

	$self->{pkalgorithm} = shift if @_;
	return 0 + ( $self->{pkalgorithm} || 0 );
}

sub hit {
	my $self = shift;

	$self->{hitbin} = pack "H*", join( "", map { s/\s+//g; $_ } @_ ) if @_;
	unpack "H*", $self->{hitbin} || "" if defined wantarray;
}

sub hitbin {
	my $self = shift;

	$self->{hitbin} = shift if @_;
	$self->{hitbin} || "";
}

sub key {
	my $self = shift;

	$self->{keybin} = MIME::Base64::decode( join "", @_ ) if @_;
	return MIME::Base64::encode( $self->keybin, "" ) if defined wantarray;
}

sub keybin {
	my $self = shift;

	$self->{keybin} = shift if @_;
	$self->{keybin} || "";
}

sub servers {
	my $self = shift;

	my $servers = $self->{servers} ||= [];
	@$servers = map Net::DNS::DomainName->new($_), @_ if @_;
	return map $_->name, @$servers if defined wantarray;
}

sub pubkey { &key; }						# historical

sub rendezvousservers {						# historical
	my @servers = &servers;
	\@servers;
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN HIP algorithm hit key servers');

=head1 DESCRIPTION

Class for DNS Host Identity Protocol (HIP) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 pkalgorithm

    $pkalgorithm = $rr->pkalgorithm;

The PK algorithm field indicates the public key cryptographic
algorithm and the implied public key field format.
The values are those defined for the IPSECKEY algorithm type [RFC4025].

=head2 hit

    $hit = $rr->hit;

The hexadecimal representation of the host identity tag.

=head2 hitbin

    $hitbin = $rr->hitbin;

The binary representation of the host identity tag.

=head2 key

    $key = $rr->key;

The hexadecimal representation of the public key.

=head2 keybin

    $keybin = $rr->keybin;

The binary representation of the public key.

=head2 servers

    @servers = $rr->servers;

Optional list of domain names of rendezvous servers.


=head1 COPYRIGHT

Copyright (c)2009 Olaf Kolkman, NLnet Labs

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC5205

=cut
