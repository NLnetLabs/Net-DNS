package Net::DNS::RR::SSHFP;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1]; # Unchanged since 1046

use base Net::DNS::RR;

=head1 NAME

Net::DNS::RR::SSHFP - DNS SSHFP resource record

=cut


use strict;
use integer;

use constant BABBLE => eval { require Digest::BubbleBabble; };


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $size = $self->{rdlength} - 2;
	@{$self}{qw(algorithm fptype fpbin)} = unpack "\@$offset C2 a$size", $$data;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{fpbin};
	pack 'C2 a*', @{$self}{qw(algorithm fptype fpbin)};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{fpbin};
	my $babble	= $self->babble;
	my $fingerprint = $self->fp;
	$fingerprint =~ s/(\S{64})/$1\n/g;
	$fingerprint = "(\n$fingerprint )" if length $fingerprint > 40;
	return join ' ', $self->algorithm, $self->fptype, $fingerprint unless $babble;
	return join ' ', $self->algorithm, $self->fptype, $fingerprint, "\n;", $babble;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->$_(shift) for qw(algorithm fptype);
	$self->fp(@_);
}


sub algorithm {
	my $self = shift;

	$self->{algorithm} = shift if @_;
	return 0 + ( $self->{algorithm} || 0 );
}

sub fptype {
	my $self = shift;

	$self->{fptype} = shift if @_;
	return 0 + ( $self->{fptype} || 0 );
}

sub fp {
	my $self = shift;

	$self->{fpbin} = pack "H*", map { s/\s+//g; $_ } join "", @_ if @_;
	unpack "H*", $self->{fpbin} || "" if defined wantarray;
}

sub fpbin {
	my $self = shift;

	$self->{fpbin} = shift if @_;
	$self->{fpbin} || "";
}

sub babble {
	return Digest::BubbleBabble::bubblebabble( Digest => shift->fpbin ) if BABBLE;
	return '';
}


sub fingerprint { &fp; }					# historical

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name SSHFP algorithm fptype fp');

=head1 DESCRIPTION

DNS SSH Fingerprint (SSHFP) resource records - RFC 4255.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 algorithm

    $algorithm = $rr->algorithm;

The 8-bit algorithm number describes the algorithm used to
construct the public key.

=head2 fptype

    $fptype = $rr->fptype;

The 8-bit fingerprint type number describes the message-digest
algorithm used to calculate the fingerprint of the public key.

=head2 fp

    $fp = $rr->fp;

Hexadecimal representation of the fingerprint digest.

=head2 fpbin

    $fpbin = $rr->fpbin;

Returns opaque octet string representing the fingerprint digest.

=head2 babble

    print $rr->babble;

The babble() method returns the 'BabbleBubble' representation of
the fingerprint if the Digest::BubbleBabble package is available,
otherwise an empty string is returned.

Bubble babble represents a message digest as a string of "real"
words, to make the fingerprint easier to remember. The "words"
are not necessarily real words, but they look more like words
than a string of hex characters.

Bubble babble fingerprinting is used by the SSH2 suite (and
consequently by Net::SSH::Perl, the Perl SSH implementation)
to display easy-to-remember key fingerprints.

The 'BubbleBabble' string is appended as a comment to the RDATA
when the string method is called.


=head1 COPYRIGHT

Copyright (c)2007 Olaf Kolkman, NLnet Labs.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4255

=cut
