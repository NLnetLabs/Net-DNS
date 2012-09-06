package Net::DNS::RR::HIP;
use base Net::DNS::RR;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::RR::HIP - DNS HIP resource record

=cut


use strict;
use integer;

use Net::DNS::DomainName;
use MIME::Base64;

use Text::ParseWords;


sub new {					## decode rdata from wire-format octet string
	my $class = shift;
	my $self = bless shift, $class;
	my ( $data, $offset ) = @_;

	my ( $hitlen, $pklen ) = unpack "\@$offset Cxn", $$data;
	@{$self}{qw(pkalgorithm hitbin pubkeybin)} = unpack "\@$offset xCxx a$hitlen a$pklen", $$data;

	my $limit = $offset + $self->{rdlength};
	$offset += 4 + $hitlen + $pklen;
	$self->{svrlist} = [];
	while ( $offset < $limit ) {
		my $item;
		( $item, $offset ) = decode Net::DNS::DomainName($data,$offset );
		push @{$self->{svrlist}}, $item;
	}
	croak('corrupt HIP data') unless $offset == $limit;	# more or less FUBAR

	return $self;
}


sub rr_rdata {					## encode rdata as wire-format octet string
	my $self = shift;
	my $pkt	 = shift;
	$self->encode_rdata(@_);
}

sub encode_rdata {				## encode rdata as wire-format octet string
	my $self = shift;

	my $hit	  = $self->hitbin || return '';
	my $key	  = $self->pubkeybin;
	my @svr	  = $self->servers;
	my $rdata = pack 'C2n a* a*', length($hit), $self->pkalgorithm, length($key), $hit, $key;
	foreach ( @{$self->{svrlist}} ) { $rdata .= $_->encode }
	return $rdata;
}


sub rdatastr {					## format rdata portion of RR string.
	my $self = shift;

	my $algorithm = $self->pkalgorithm || return '';
	my $hit	      = $self->hit;
	my $pubkey    = MIME::Base64::encode( $self->pubkeybin, "\n" );
	my @servers   = map $_->string, @{$self->{svrlist}};
	return "( $algorithm $hit\n$pubkey\t@servers )";
}


sub new_from_string {				## populate RR from rdata string
	my $class = shift;
	my $self  = bless shift, $class;
	my @parse = grep {/[^()]/} quotewords( qw(\s+), 1, shift || "" );
	$self->parse_rdata(@parse) if @parse;
	return $self;
}

sub parse_rdata {				## populate RR from rdata in argument list
	my $self = shift;

	$self->pkalgorithm(shift);
	$self->hit(shift);
	$self->pubkey( grep { $_ !~ /[.]/ } @_ );
	$self->servers( grep { $_ =~ /[.]/ } @_ );
}


sub pkalgorithm {
	my $self = shift;

	$self->{pkalgorithm} = shift if @_;
	return 0 + ( $self->{pkalgorithm} || 0 );
}

sub hit {
	my $self = shift;

	$self->hitbin( pack 'H*', shift ) if @_;
	return unpack 'H*', $self->hitbin if defined wantarray;
}

sub hitbin {
	my $self = shift;

	$self->{hitbin} = pack( "H*", $self->{hit} ) if defined $self->{hit};	 # new from hash
	delete $self->{hit};

	$self->{hitbin} = shift if @_;
	return $self->{hitbin};
}

sub pubkey {
	my $self = shift;

	$self->pubkeybin( MIME::Base64::decode( join '', @_ ) ) if @_;
	return MIME::Base64::encode( $self->pubkeybin, '' ) if defined wantarray;
}

sub pubkeybin {
	my $self = shift;

	$self->{pubkeybin} = MIME::Base64::decode( $self->{pubkey} ) if defined $self->{pubkey};    # new from hash
	delete $self->{pubkey};

	$self->{pubkeybin} = shift if @_;
	return $self->{pubkeybin};
}

sub servers {
	my $self = shift;

	my $svrlist = $self->{svrlist} ||= [];
	my $newlist = $self->{rendezvousservers} || [];		# new from hash
	$newlist = [$self->{servers}] if $self->{servers};	# 100% bug compatible!
	$newlist = $self->{servers}   if ref $self->{servers};
	@$svrlist = map Net::DNS::DomainName->new($_), @$newlist if @$newlist;
	delete @{$self}{qw(rendezvousservers servers)};
	@$svrlist = map Net::DNS::DomainName->new($_), @_ if @_;
	return map $_->name, @$svrlist if defined wantarray;
}

sub rendezvousservers {						# historical
	my @servers = &servers;
	\@servers;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name IN HIP algorithm hit publickey servers');

=head1 DESCRIPTION

Class for DNS Host Identity Protocol (HIP) resource records.

=head1 METHODS

The available methods are those inherited from the base class
augmented by the type-specific methods defined in this package.

Use of undocumented features or direct access to internal data
structures is discouraged and may result in program termination
or unexpected behaviour.


=head2 pkalgorithm

    $pkalgorithm = $object->pkalgorithm;

The PK algorithm field indicates the public key cryptographic
algorithm and the implied public key field format.
The values are those defined for the IPSECKEY algorithm type [RFC4025].

=head2 hit

    $hit = $rr->hit;

The hexadecimal representation of the host identity tag.

=head2 hitbin

    $hitbin = $rr->hitbin;

The binary representation of the host identity tag.

=head2 pubkey

    $publickey = $rr->pubkey;

The base64 representation of the public key.

=head2 pubkeybin

    $pubkeybin = $rr->pubkeybin;

The binary representation of the public key.

=head2 servers

    @servers = $rr->servers;

Optional list of domain names of rendezvous servers.


=head1 COPYRIGHT

Copyright (c)2009 Olaf Kolkman, NLnet Labs

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC5205

=cut
