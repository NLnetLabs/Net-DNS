package Net::DNS::RR::unkown;
#
# $Id: unknown.pm,v 1.2 2003/12/09 17:40:27 ctriv Exp $
#
use strict;
use vars qw(@ISA $VERSION);

use Socket;
use Net::DNS;

@ISA     = qw(Net::DNS::RR);
$VERSION = (qw$Revision: 1.2 $)[1];

sub new {
	my ($class, $self, $data, $offset) = @_;
	
	my $length = $self->{'rdlength'};
	
	if ($length > 0) {
	    my $hex = unpack('H*', substr($$data, $offset,$length));
	    $self->{'rdata'} = "\\# $length $hex";
	}

	return bless $self, $class;
}


sub rdatastr {
	my $self = shift;
	return defined $self->{'rdata'} ? $self->{'rdata'} : '# NODATA';

}

sub rr_rdata {
	my $self  = shift;
	my $rdata = '';
	return $rdata;
}

1;
__END__

=head1 NAME

Net::DNS::RR::unknown - DNS unkown RR record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION

Class for dealing with unknown RR types (RFC3597)

=head1 METHODS



=head1 COPYRIGHT

Copyright (c) 1997-2002 Michael Fuhr. 

Portions Copyright (c) 2002-2003 Chris Reinhardt.

Portions Copyright (c) 2003  Olaf M. Kolkman, RIPE NCC.

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC 1035 Section 3.4.1

=cut
