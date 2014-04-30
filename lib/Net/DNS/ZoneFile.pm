package Net::DNS::ZoneFile;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::ZoneFile - DNS zone file

=head1 SYNOPSIS

    use Net::DNS::ZoneFile;

    $zonefile = new Net::DNS::ZoneFile( 'named.example' );

    while ( $rr = $zonefile->read ) {
	$rr->print;
    }

    @zone = $zonefile->read;


=head1 DESCRIPTION

Each Net::DNS::ZoneFile object instance represents a zone file
together with any subordinate files introduced by the $INCLUDE
directive.  Zone file syntax is defined by RFC1035.

A program may have multiple zone file objects, each maintaining
its own independent parser state information.

The parser supports both the $TTL directive defined by RFC2308
and the BIND $GENERATE syntax extension.

All RRs in a zone file must have the same class, which may be
specified for the first RR encountered and is then propagated
automatically to all subsequent records.

=cut


use strict;
use integer;
use Carp;

require FileHandle;

use Net::DNS;

use constant PERLIO => eval { require PerlIO; } || 0;


=head1 METHODS


=head2 new

    $zonefile = new Net::DNS::ZoneFile( 'filename', ['example.com'] );

    $handle   = new FileHandle( 'filename', '<:encoding(ISO8859-7)' );
    $zonefile = new Net::DNS::ZoneFile( $handle, ['example.com'] );

The new() constructor returns a Net::DNS::ZoneFile object which
represents the zone file specified in the argument list.

The specified file or file handle is open for reading and closed when
exhausted or all references to the ZoneFile object cease to exist.

The optional second argument specifies $ORIGIN for the zone file.

Character encoding is specified indirectly by creating a FileHandle
with the desired encoding layer, which is then passed as an argument
to new(). The specified encoding is propagated to files introduced
by $include directives.

=cut

sub new {
	my $self = bless {}, shift;
	my $file = shift;
	$self->_origin(shift);

	if ( ref($file) ) {
		$self->{filename} = $self->{handle} = $file;
		return $self if ref($file) =~ /FileHandle|IO::File|GLOB|Text/;
		croak 'argument not a file handle';
	}

	$self->{handle} = new FileHandle($file) or croak qq(open: "$file" $!);
	$self->{filename} = $file;
	return $self;
}


=head2 read

    $rr = $zonefile->read;
    @rr = $zonefile->read;

When invoked in scalar context, read() returns a Net::DNS::RR object
representing the next resource record encountered in the zone file,
or undefined if end of data has been reached.

When invoked in list context, read() returns the list of Net::DNS::RR
objects in the order that they appear in the zone file.

Comments and blank lines are silently disregarded.

$INCLUDE, $ORIGIN, $TTL and $GENERATE directives are processed
transparently.

=cut

sub read {
	my ($self) = @_;

	return &_read unless ref $self;				# compatibility interface

	if (wantarray) {
		my @zone;					# return entire zone
		eval {
			my $rr;
			push( @zone, $rr ) while $rr = $self->_getRR;
		};
		croak join ' ', $@, ' file', $self->name, 'line', $self->line, "\n " if $@;
		return @zone;
	}

	my $rr = eval { $self->_getRR };			# return single RR
	croak join ' ', $@, ' file', $self->name, 'line', $self->line, "\n " if $@;
	return $rr;
}


=head2 name

    $filename = $zonefile->name;

Returns the name of the zone file from which RRs will be read.
$INCLUDE directives will cause this to differ from the filename
argument supplied when the object was created.

=cut

sub name {
	return shift->{filename} || '<anon>';
}


=head2 line

    $line = $zonefile->line;

Returns the number of the last line read from the current zone file.

=cut

sub line {
	my $self = shift;
	return $self->{eom} if defined $self->{eom};
	return $self->{handle}->input_line_number;
}


=head2 origin

    $origin = $zonefile->origin;

Returns the fully qualified name of the current origin within the
zone file.

=cut

sub origin {
	my $context = shift->{context};
	return &$context( sub { new Net::DNS::Domain('@') } )->string;
}


=head2 ttl

    $ttl = $zonefile->ttl;

Returns the default TTL as specified by the $TTL directive.

=cut

sub ttl {
	my $self = shift;
	my $time = shift;
	return $self->{ttl} || 0 unless defined $time;
	$self->{ttl} = new Net::DNS::RR(". $time IN A")->ttl;
}


=head1 COMPATIBILITY WITH Net::DNS::ZoneFile 1.04

Applications which depended on the defunct Net::DNS::ZoneFile 1.04
CPAN distribution will continue to operate with minimal change using
the compatibility interface described below.

    use Net::DNS::ZoneFile;

    $listref = Net::DNS::ZoneFile->read( $filename, $include_dir );

    $listref = Net::DNS::ZoneFile->readfh( $handle, $include_dir );

    $listref = Net::DNS::ZoneFile->parse(  $string, $include_dir );
    $listref = Net::DNS::ZoneFile->parse( \$string, $include_dir );

    $_->print for @$listref;

The optional second argument specifies the default path for filenames.
The current working directory is used by default.

Although not available in the original implementation, the RR list can
be obtained directly by calling any of these methods in list context.

    @rr = Net::DNS::ZoneFile->read( $filename, $include_dir );


=head2 read

    $listref = Net::DNS::ZoneFile->read( $filename, $include_dir );
    @rr = Net::DNS::ZoneFile->read( $filename, $include_dir );

read() parses the specified zone file and returns a reference to the
list of Net::DNS::RR objects representing the RRs in the file.
The return value is undefined if the zone data can not be parsed.

When called in list context, the partial result is returned if an
error is encountered by the parser.

=cut

use vars qw($include_dir);		## dynamically scoped

sub _filename {				## rebase unqualified filename
	my $name = shift;
	return $name unless $include_dir;
	return $name if ref($name);	## file handle
	require File::Spec;
	return $name if File::Spec->file_name_is_absolute($name);
	return File::Spec->catfile( $include_dir, $name );
}


sub _read {
	my ($arg1) = @_;
	shift unless ref($arg1) || $arg1 ne __PACKAGE__;
	my $file = new Net::DNS::ZoneFile( _filename(shift) );
	local $include_dir = shift;
	my @zone;
	eval {
		my $rr;
		push( @zone, $rr ) while $rr = $file->_getRR;
	};
	return wantarray ? @zone : \@zone unless $@;
	carp join ' ', $@, ' file', $file->name, 'line', $file->line, "\n ";
	return wantarray ? @zone : undef;
}


{

	package Net::DNS::ZoneFile::Text;

	use overload ( '<>' => 'readline' );

	sub new {
		my $self = bless {}, shift;
		my $data = shift;
		$self->{data} = [split /\n/, ref($data) ? $$data : $data];
		no integer;
		return $self unless $] < 5.006;

		require IO::File;	## Plan B: ancient perl unable to overload <>
		my $fh = IO::File->new_tmpfile() or die "Unable to create temporary file: $!";
		while ( my $line = $self->readline ) { print $fh $line, "\n"; }
		seek $fh, 0, 0;
		return $fh;
	}

	sub readline {
		my $self = shift;
		$self->{line}++;
		return shift( @{$self->{data}} );
	}

	sub close {
		shift->{data} = [];
		return 1;
	}

	sub input_line_number {
		return shift->{line};
	}

}


=head2 readfh

    $listref = Net::DNS::ZoneFile->readfh( $handle, $include_dir );

readfh() parses data from the specified file handle and returns a
reference to the list of Net::DNS::RR objects representing the RRs
in the file.

=cut

sub readfh {
	return &_read;
}


=head2 parse

    $listref = Net::DNS::ZoneFile->parse(  $string, $include_dir );
    $listref = Net::DNS::ZoneFile->parse( \$string, $include_dir );

parse() interprets the zone file text in the argument string and
returns a reference to the list of Net::DNS::RR objects representing
the RRs.

=cut

sub parse {
	my ($arg1) = @_;
	shift unless ref($arg1) || $arg1 ne __PACKAGE__;
	return &_read( new Net::DNS::ZoneFile::Text(shift), @_ );
}


########################################

use vars qw($AUTOLOAD);

sub AUTOLOAD {				## Default method
	no strict;
	@_ = ("method $AUTOLOAD undefined");
	goto &{'Carp::confess'};
}


sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)


{

	package Net::DNS::ZoneFile::Generator;

	use overload ( '<>' => 'readline' );

	sub new {
		my $self = bless {}, shift;
		my ( $range, $template, $line ) = @_;

		$template =~ s/\\\$/\\036/g;			# disguise escaped dollar
		$template =~ s/\$\$/\\036/g;			# disguise escaped dollar

		my ( $bound, $step ) = split m#[/]#, $range;	# initial iterator state
		my ( $first, $last ) = split m#[-]#, $bound;
		$step = abs( $step || 1 );			# coerce step to match range
		$step = -$step if $last < $first;
		$self->{count} = int( ( $last - $first ) / $step ) + 1;

		@{$self}{qw(instant step template line)} = ( $first, $step, $template, $line );

		return $self;
	}

	sub readline {
		my $self = shift;
		return undef unless $self->{count}-- > 0;	# EOF

		my $instant = $self->{instant};			# update iterator state
		$self->{instant} += $self->{step};

		local $_ = $self->{template};			# copy template
		while (/\$\{(.*)\}/) {				# interpolate ${...}
			my $s = _format( $instant, split /\,/, $1 );
			s/\$\{$1\}/$s/eg;
		}

		s/\$/$instant/eg;				# interpolate $
		return $_;
	}

	sub close {
		shift->{count} = 0;				# suppress iterator
		return 1;
	}

	sub input_line_number {
		return shift->{line};				# fixed: identifies $GENERATE
	}


	sub _format {			## convert $GENERATE iteration number to specified format
		my $number = shift;				# per ISC BIND 9.7
		my $offset = shift || 0;
		my $length = shift || 0;
		my $format = shift || 'd';

		my $value = $number + $offset;
		my $digit = $length || 1;
		return substr sprintf( "%01.$digit$format", $value ), -$length if $format =~ /[doxX]/;

		my $nibble = join( '.', split //, sprintf ".%32.32lx", $value );
		return lc reverse substr $nibble, -$length if $format =~ /[n]/;
		return uc reverse substr $nibble, -$length if $format =~ /[N]/;
	}

}


sub _generate {				## expand $GENERATE into input stream
	my ( $self, $range, $template ) = @_;

	my $handle = new Net::DNS::ZoneFile::Generator( $range, $template, $self->line );

	delete $self->{latest};					# forbid empty owner field
	$self->{parent} = bless {%$self}, ref($self);		# save state, create link
	no integer;
	return $self->{handle} = $handle unless $] < 5.006;

	require IO::File;		## Plan B: ancient perl unable to overload <>
	my $fh = IO::File->new_tmpfile() or die "Unable to create temporary file: $!";
	while ( my $line = $handle->readline ) { print $fh $line, "\n"; }
	seek $fh, 0, 0;
	return $self->{handle} = $fh;
}


my $LEX_REGEX = q/("[^"]*"|"[^"]*$)|;[^\n]*|([()])|(^\s)|\s/;

sub _getline {				## get line from current source
	my $self = shift;

	my $fh = $self->{handle};
	while (<$fh>) {
		next unless /\S/;				# discard blank line
		next if /^\s*;/;				# discard comment line

		if (/\(/) {					# concatenate multi-line RR
			s/\\\\/\\092/g;				# disguise escaped escape
			s/\\"/\\034/g;				# disguise escaped quote
			s/\\\(/\\040/g;				# disguise escaped bracket
			s/\\\)/\\041/g;				# disguise escaped bracket
			s/\\;/\\059/g;				# disguise escaped semicolon
			my @token = grep defined && length, split /$LEX_REGEX/o;
			if ( grep( $_ eq '(', @token ) && !grep( $_ eq ')', @token ) ) {
				while (<$fh>) {
					s/\\\\/\\092/g;		# disguise escaped escape
					s/\\"/\\034/g;		# disguise escaped quote
					s/\\\(/\\040/g;		# disguise escaped bracket
					s/\\\)/\\041/g;		# disguise escaped bracket
					s/\\;/\\059/g;		# disguise escaped semicolon
					substr( $_, 0, 0 ) = pop @token || '';	  # splice multi-line token
					push @token, grep defined && length, split /$LEX_REGEX/o;
					last if grep $_ eq ')', @token;
				}
				$_ = join ' ', @token;		# reconstitute RR string
			}
		}

		return $_ unless /^\$/;				# RR string

		if (/^\$ORIGIN/) {				# directive
			my ( $keyword, $origin, @etc ) = split;
			die '$ORIGIN incomplete' unless $origin;
			my $context = $self->{context};
			&$context( sub { $self->_origin($origin); } );

		} elsif (/^\$INCLUDE/) {			# directive
			my ( $keyword, @argument ) = split;
			$fh = $self->_include(@argument);

		} elsif (/^\$GENERATE/) {			# directive
			my ( $keyword, $range, @template ) = split;
			die '$GENERATE incomplete' unless $range;
			$fh = $self->_generate( $range, "@template\n" );

		} elsif (/^\$TTL/) {				# directive
			my ( $keyword, $ttl, @etc ) = split;
			die '$TTL incomplete' unless defined $ttl;
			$self->ttl($ttl);

		} else {					# unrecognised
			chomp;
			die "unknown directive: $_";
		}
	}

	$self->{eom} = $self->line;				# end of file
	my $ok = $fh->close;
	die "pipe: process exit status $?" if $?;
	die "close: $!" unless $ok;
	my $link = $self->{parent} || return undef;		# end of zone
	%$self = %$link;					# end $INCLUDE
	return $self->_getline;					# resume input
}


sub _getRR {				## get RR from current source
	my $self = shift;

	my $line = $self->_getline;
	return undef unless defined $line;

	my $noname = $line =~ s/^\s/\@\t/;			# RR name empty

	# construct RR object with context specific dynamically scoped $ORIGIN
	my $context = $self->{context};
	my $rr = &$context( sub { Net::DNS::RR->_new_string($line) } );

	$rr->{owner} = $self->{latest}->{owner} if $noname && $self->{latest};	  # overwrite placeholder

	$rr->class( $self->{class} ||= $rr->class );		# propagate RR class

	$self->{'ttl'} ||= $rr->type eq 'SOA' ? $rr->minimum : undef;	# default TTL
	$rr->ttl( $self->ttl ) unless defined $rr->{'ttl'};

	return $self->{latest} = $rr;
}


sub _include {				## open $INCLUDE file
	my $self = shift;
	my $file = _filename(shift);
	my $root = shift;

	my @discipline = ( join ':', '<', PerlIO::get_layers $self->{handle} ) if PERLIO;
	my $handle = new FileHandle( $file, @discipline ) or croak qq(open: "$file" $!);

	delete $self->{latest};					# forbid empty owner field
	$self->{parent} = bless {%$self}, ref($self);		# save state, create link
	$self->{context} = origin Net::DNS::Domain($root) if $root;
	$self->{filename} = $file;
	return $self->{handle} = $handle;
}


sub _origin {				## change $ORIGIN (scope: current file)
	my $self = shift;
	$self->{context} = origin Net::DNS::Domain(shift);
	delete $self->{latest};					# forbid empty owner field
}


1;
__END__


=head1 ACKNOWLEDGEMENTS

This package is designed as an improved and compatible replacement
for Net::DNS::ZoneFile 1.04 which was created by Luis Munoz in 2002
as a separate CPAN module.

The present implementation is the result of an agreement to merge our
two different approaches into one package integrated into Net::DNS.
The contribution of Luis Munoz is gratefully acknowledged.

Thanks are also due to Willem Toorop for his constructive criticism
of the initial version and invaluable assistance during testing.


=head1 COPYRIGHT

Copyright (c)2011-2012 Dick Franks 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC1035 Section 5.1,
RFC2308, BIND 9 Administrator Reference Manual

=cut
