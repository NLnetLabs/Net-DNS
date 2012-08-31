package Net::DNS::RR::TLSA;
#
# $Id$
#
use strict;
BEGIN {
    eval { require bytes; }
}
use vars qw(@ISA $VERSION);

@ISA     = qw(Net::DNS::RR);
$VERSION = (qw$LastChangedRevision: 932 $)[1];

sub new {
	my ($class, $self, $data, $offset) = @_;

	if ($self->{'rdlength'} > 0) {
		@{$self}{qw(usage selector matchingtype certificate_data)} = unpack("\@$offset C3 H*", $$data);
	}

	return bless $self, $class;
}

sub new_from_string {
	my ($class, $self, $string) = @_;

	if ($string && ($string =~ /^(\d+)\s+(\d+)\s+(\d+)\s+([0-9A-Fa-f]+)$/)) {
		@{$self}{qw(usage selector matchingtype certificate_data)} = ($1, $2, $3, lc ( $4 ));

		$self->{'certificate_data'} =~ s/\s+//g;
	}

	return bless $self, $class;
}

sub rdatastr {
	my $self = shift;
	my $rdatastr;

	if (exists $self->{'certificate_data'}) {
		$rdatastr = join(' ', @{$self}{qw(usage selector matchingtype certificate_data)});
	} else {
		$rdatastr = '';
	}

	return $rdatastr;
}

sub rr_rdata {
	my ($self, $packet, $offset) = @_;
	my $rdata = '';

	if (exists $self->{'certificate_data'}) {
		$rdata .= pack('C3 H*', @{$self}{qw(usage selector matchingtype certificate_data)});
        }

	return $rdata;
}


1;
__END__

=head1 NAME

Net::DNS::RR::TLSA - DNS TLSA resource record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION

Class for DNS DANE TLSA resource records.

=head1 METHODS

=head2 usage

    print "usage = ", $rr->usage, "\n";

Returns the numerical usage field of the record.

=head2 selector

    print "selector = ", $rr->selector, "\n";

Returns the numerical selector field of the record.

=head2 matchingtype

    print "matching type = ", $rr->matchingtype, "\n";

Returns the numerical matching type field of the record.

=head2 certificate_data

    print "certificate data = ", $rr->certificate_data, "\n";

Returns the certificate data associated with the record, as a hexadecimal string.

=head1 COPYRIGHT

Copyright (c) 1997-2002 Michael Fuhr.

Portions Copyright (c) 2002-2004 Chris Reinhardt.

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
draft-ietf-dane-protocol-21

=cut
