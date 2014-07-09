package Net::DNS::RR::TXT;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


use strict;
use base qw(Net::DNS::RR);

=encoding utf8

=head1 NAME

Net::DNS::RR::TXT - DNS TXT resource record

=cut


use integer;

use Carp;
use Net::DNS::Text;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	my $text;
	my $txtdata = $self->{txtdata} = [];
	while ( $offset < $limit ) {
		( $text, $offset ) = decode Net::DNS::Text( $data, $offset );
		push @$txtdata, $text;
	}

	croak('corrupt TXT data') unless $offset == $limit;	# more or less FUBAR
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $txtdata = $self->{txtdata} || [];
	join '', map $_->encode, @$txtdata;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $txtdata = $self->{txtdata} || [];
	my @txtdata = map $_->string, @$txtdata;
	my @line;
	my $size = 32;
	while (@txtdata) {
		my @group;
		while ( $size > 0 && scalar @txtdata ) {
			my $string = shift @txtdata;
			push @group, $string;
			$size -= 1 + length($string);
		}
		push @line, join ' ', @group;
		$size = 64;
	}
	my $rdata = join "\n", @line;
	return $rdata =~ /\n/ ? "( $rdata )" : $rdata;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->{txtdata} = [map Net::DNS::Text->new($_), @_];
}


sub txtdata {
	my $self = shift;

	$self->{txtdata} = [map Net::DNS::Text->new($_), @_] if scalar @_;

	my $txtdata = $self->{txtdata} || [];

	return ( map $_->value, @$txtdata ) if wantarray;

	join ' ', map $_->value, @$txtdata if defined wantarray;
}


sub char_str_list { return (&txtdata); }


sub rdatastr {			## SpamAssassin workaround, per CPAN RT#81760
	my $txtdata = shift->{txtdata} || [];
	join ' ', map $_->quoted_string, @$txtdata;
}

package Net::DNS::Text;

sub quoted_string {
	my $string = shift->string;
	return $string if $string =~ /^"/;			# string already quoted
	$string =~ s/\\([$();@])/$1/g;				# nothing special within quotes
	join '', '"', $string, '"';				# quote previously unquoted string
}

1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR( 'name TXT  txtdata ...' );

    $rr = new Net::DNS::RR( name    => 'name',
			    type    => 'TXT',
			    txtdata => 'single text string'
			    );

    $rr = new Net::DNS::RR( name    => 'name',
			    type    => 'TXT',
			    txtdata => [ 'multiple', 'strings', ... ]
			    );

    use utf8;
    $rr = new Net::DNS::RR( 'jp TXT    古池や　蛙飛込む　水の音' );

=head1 DESCRIPTION

Class for DNS Text (TXT) resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 txtdata

    $string = $rr->txtdata;
    @list   = $rr->txtdata;

    $rr->txtdata( @list );

When invoked in scalar context, txtdata() returns the descriptive text
as a single string, regardless of the number of elements.

In a list context, txtdata() returns a list of the text elements.


=head1 COPYRIGHT

Copyright (c)2011 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 3.3.14, RFC3629

=cut
