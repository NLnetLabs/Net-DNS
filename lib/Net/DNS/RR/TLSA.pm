package Net::DNS::RR::TLSA;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::TLSA - DNS TLSA resource record

=cut



sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $next = $offset + $self->{rdlength};

	@{$self}{qw(usage selector matchingtype)} = unpack "\@$offset C3", $$data;
	$offset += 3;
	$self->{certbin} = substr $$data, $offset, $next - $offset;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless defined $self->{certbin};
	return pack 'C3 a*', @{$self}{qw(usage selector matchingtype certbin)};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless defined $self->{certbin};

	my $certificate = $self->cert;

	my @list = ( '(', $certificate, ')' );
	@list = ($certificate) unless length($certificate) > 40;

	join ' ', $self->usage, $self->selector, $self->matchingtype, join "\n\t", @list;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->usage(shift);
	$self->selector(shift);
	$self->matchingtype(shift);
	$self->cert(shift);
}


sub usage {
	my $self = shift;

	$self->{usage} = shift if @_;
	return 0 + ( $self->{usage} || 0 );
}

sub selector {
	my $self = shift;

	$self->{selector} = shift if @_;
	return 0 + ( $self->{selector} || 0 );
}

sub matchingtype {
	my $self = shift;

	$self->{matchingtype} = shift if @_;
	return 0 + ( $self->{matchingtype} || 0 );
}

sub cert {
	my $self = shift;

	$self->{certbin} = pack "H*", join( "", map { s/\s+//g; $_ } @_ ) if @_;
	unpack "H*", $self->{certbin} || "" if defined wantarray;
}

sub certificate {&cert}

sub certbin {
	my $self = shift;

	$self->{certbin} = shift if @_;
	$self->{certbin} || "";
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name TLSA usage selector matchingtype certificate');

=head1 DESCRIPTION

The Transport Layer Security Authentication (TLSA) DNS resource record
is used to associate a TLS server certificate or public key with the
domain name where the record is found, forming a "TLSA certificate
association".  The semantics of how the TLSA RR is interpreted are
described in RFC6698.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 usage

    $usage = $rr->usage;

8-bit integer value which specifies the provided association that
will be used to match the certificate presented in the TLS handshake.

=head2 selector

    $selector = $rr->selector;

8-bit integer value which specifies which part of the TLS certificate
presented by the server will be matched against the association data.

=head2 matchingtype

    $matchingtype = $rr->matchingtype;

8-bit integer value  which specifies how the certificate association
is presented.

=head2 cert

    $cert = $rr->cert;

Hexadecimal representation of the certificate data.

=head2 certbin

    $certbin = $rr->certbin;

Binary representation of the certificate data.


=head1 COPYRIGHT

Copyright (c)2012 Willem Toorop, NLnet Labs.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC6698

=cut
