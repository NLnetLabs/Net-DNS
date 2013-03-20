package Net::DNS::Text;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::Text - Domain Name System text representation

=head1 SYNOPSIS

    use Net::DNS::Text;

    $object = new Net::DNS::Text('example');
    $string = $object->string;

    $object = decode Net::DNS::Text( \$data, $offset );
    ( $object, $next ) = decode Net::DNS::Text( \$data, $offset );

    $data = $object->encode;
    $text = $object->value;

=head1 DESCRIPTION

The C<Net::DNS::Text> module implements a class of text objects
with associated class and instance methods.

Each text object instance has a fixed identity throughout its
lifetime.

=cut


use strict;
use integer;
use Carp;


use constant ASCII => eval {
	require Encode;
	Encode::find_encoding('ASCII');				# return encoding object
} || 0;

use constant UTF8 => eval {
	die if Encode::decode_utf8( chr(91) ) ne '[';		# not UTF-EBCDIC  [see UTR#16 3.6]
	Encode::find_encoding('UTF8');				# return encoding object
} || 0;


=head1 METHODS

=head2 new

    $object = new Net::DNS::Text('example');

Creates a text object which encapsulates a single character
string component of a resource record.

Arbitrary single-byte characters can be represented by \ followed
by exactly three decimal digits. Such characters are devoid of
any special meaning.

A character preceded by \ represents itself, without any special
interpretation.

=cut

my %unescape;			## precalculated numeric escape table

sub new {
	my $self = bless [], shift;
	croak 'argument undefined' unless defined $_[0];

	local $_ = &_encode_utf8;

	s/^([\042\047])(.*)\1$/$2/;				# strip paired quotes

	s/\134\134/\134\060\071\062/g;				# disguise escaped escape
	s/\134([\060-\071]{3})/$unescape{$1}/eg;		# numeric escape
	s/\134(.)/$1/g;						# character escape

	while ( length $_ > 255 ) {
		my $chunk = substr( $_, 0, 255 );		# carve into chunks
		substr( $chunk, -length($1) ) = '' if $chunk =~ /.([\300-\377][\200-\277]*)$/;
		push @$self, $chunk;
		substr( $_, 0, length $chunk ) = '';
	}
	push @$self, $_;

	return $self;
}


=head2 decode

    $object = decode Net::DNS::Text( \$buffer, $offset );

    ( $object, $next ) = decode Net::DNS::Text( \$buffer, $offset );

Creates a text object which represents the decoded data at the
indicated offset within the data buffer.

The argument list consists of a reference to a scalar containing
the wire-format data and offset of the text data.

The returned offset value indicates the start of the next item in
the data buffer.

=cut

sub decode {
	my $class  = shift;
	my $buffer = shift;					# reference to data buffer
	my $offset = shift || 0;				# offset within buffer

	my $size = unpack "\@$offset C", $$buffer;
	my $next = ++$offset + $size;
	croak 'corrupt wire-format data' if $next > length $$buffer;

	my $self = bless [unpack( "\@$offset a$size", $$buffer )], $class;

	return wantarray ? ( $self, $next ) : $self;
}


=head2 encode

    $data = $object->encode;

Returns the wire-format encoded representation of the text object
suitable for inclusion in a DNS packet buffer.

=cut

sub encode {
	my $self = shift;
	join '', map pack( 'C a*', length $_, $_ ), @$self;
}


=head2 value

    $value = $text->value;

Character string representation of the text object.

=cut

sub value {
	my $self = shift;
	_decode_utf8( join '', @$self );
}


=head2 string

    $string = $text->string;

Conditionally quoted zone file representation of the text object.

=cut

my %escape;			## precalculated ASCII/UTF-8 escape table

my $QQ = _decode_utf8( pack 'C', 34 );

sub string {
	my $self = shift;

	my @s = map split( '', $_ ), @$self;			# escape non-printable
	my $string = _decode_utf8( join '', map $escape{$_}, @s );

	# Note: Script-specific rules determine which Unicode characters match \s
	return $string unless $string =~ /^$|\s|["\$'();@]/;	# unquoted contiguous

	join '', $QQ, $string, $QQ;				# quoted string
}


########################################

use vars qw($AUTOLOAD);

sub AUTOLOAD {			## Default method
	no strict;
	@_ = ("method $AUTOLOAD undefined");
	goto &{'Carp::confess'};
}


sub DESTROY { }			## Avoid tickling AUTOLOAD (in cleanup)


sub _decode_utf8 {
	my $s = shift;

	return pack 'a0 a*', $s, UTF8->decode($s) if UTF8;	# preserve taint

	return pack 'a0 a*', $s, ASCII->decode($s) if ASCII && not UTF8;

	# partial transliteration for non-ASCII character encodings
	$s =~ tr
	[\040-\176\000-\377]
	[ !"#$%&'()*+,-./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~?] unless ASCII;

	return $s;						# native 8-bit code
}


sub _encode_utf8 {
	my $s = shift;

	return pack 'a0 a*', $s, UTF8->encode($s) if UTF8;	# preserve taint

	return pack 'a0 a*', $s, ASCII->encode($s) if ASCII && not UTF8;

	# partial transliteration for non-ASCII character encodings
	$s = pack 'C*', unpack 'U0 C*', $s unless ASCII;	# repackage pre-5.8 Unicode
	$s =~ tr
	[ !"#$%&'()*+,-./0-9:;<=>?@A-Z\[\\\]^_`a-z{|}~]
	[\040-\176] unless ASCII;

	return $s;						# ASCII
}


%escape = eval {			## precalculated ASCII/UTF-8 escape table
	my %table;
	my @C0 = ( 0 .. 31 );					# control characters
	my @NA = UTF8 ? ( 192, 193, 216 .. 223, 245 .. 255 ) : ( 128 .. 255 );

	foreach ( 0 .. 255 ) {					# transparent
		$table{pack( 'C', $_ )} = pack 'C', $_;
	}

	foreach ( 34, 92 ) {					# escape character
		$table{pack( 'C', $_ )} = pack 'C2', 92, $_;
	}

	foreach ( @C0, 127, @NA ) {				# \ddd
		$table{pack( 'C', $_ )} = pack 'C a3', 92, _encode_utf8( sprintf '%03u', $_ );
	}

	return %table;
};


%unescape = eval {			## precalculated numeric escape table
	my %table;

	foreach ( 0 .. 255 ) {
		$table{_encode_utf8 sprintf( '%03u', $_ )} = pack 'C', $_;
	}

	$table{_encode_utf8('092')} = pack 'C2', 92, 92;

	return %table;
};


1;
__END__


########################################

=head1 BUGS

Coding strategy is intended to avoid creating unnecessary argument
lists and stack frames. This improves efficiency at the expense of
code readability.

Platform specific character coding features are conditionally
compiled into the code.


=head1 COPYRIGHT

Copyright (c)2009-2011 Dick Franks.

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, RFC1035, RFC3629,
Unicode Technical Report #16

=cut

