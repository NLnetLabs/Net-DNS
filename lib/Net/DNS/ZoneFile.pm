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


use integer;
use Carp;
use File::Spec::Functions;

require FileHandle;
require Net::DNS::Domain;
require Net::DNS::RR;

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

Character encoding is specified indirectly using a FileHandle package
and also applies to any files introduced by $include directives.

=cut

use vars qw($DIR);

sub new {
	my $self = bless {}, shift;
	my $file = shift;
	$self->_origin(shift);

	if ( ref($file) ) {					# presumed to be a file handle
		$self->{handle} = $file;
		return $self;
	}

	$file = catfile( $DIR ||= curdir(), $file ) unless file_name_is_absolute($file);
	$self->{handle} = new FileHandle($file) or croak qq(open: $! "$file");
	$self->{name} = $file;

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

	local $SIG{__WARN__} = sub { die @_; };
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
	return shift->{name} || '<anon>';
}


=head2 line

    $line = $zonefile->line;

Returns the number of the last line read from the current zone file.

=cut

sub line {
	my $self = shift;
	return $self->{eof} if defined $self->{eof};
	return $self->{handle}->input_line_number;
}


=head2 origin

    $origin = $zonefile->origin;

Returns the fully qualified name of the current origin within the
zone file.

=cut

sub origin {
	my $context = shift->{context};
	return &$context( sub { new Net::DNS::Domain('@') } )->name;
}


=head2 ttl

    $ttl = $zonefile->ttl;

Returns the default TTL as specified by the $TTL directive.

=cut

sub ttl {
	return shift->{ttl} || 0;
}


=head1 COMPATIBILITY WITH Net::DNS::ZoneFile 1.04

Applications which depended on the Net::DNS::ZoneFile 1.04 package
will continue to operate with minimal change using the compatibility
interface described below.

    use Net::DNS::ZoneFile;

    $listref = Net::DNS::ZoneFile->read( $filename, $include_dir );

    $listref = Net::DNS::ZoneFile->readfh( $handle, $include_dir );

    $listref = Net::DNS::ZoneFile->parse(  $string, $include_dir );
    $listref = Net::DNS::ZoneFile->parse( \$string, $include_dir );

    $_->print for @$listref;

The optional second argument specifies the default path for filenames.
The current working directory is used by default.

Although not available in the original implementation, the RR list
can be obtained directly by calling these methods in list context.

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

sub _read {
	my ($arg1) = @_;
	shift unless ref($arg1) || $arg1 ne __PACKAGE__;
	my $filename = shift;
	local $DIR = shift;
	my $file = new Net::DNS::ZoneFile($filename);
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

	use overload ( '<>' => 'read' );

	sub new {
		my $self = bless {}, shift;
		my $data = shift;
		$self->{data} = [split /\n/, ref($data) ? $$data : $data];
		return $self;
	}

	sub read {
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

	use overload ( '<>' => 'read' );

	sub new {
		my $self = bless {}, shift;
		my $range = shift;
		@{$self}{qw(template line)} = @_;

		my ( $first, $last ) = split m#[-/]#, $range;	# initial iterator state
		my ( $junk,  $step ) = split m#[/]#,  $range;
		$step = abs( $step || 1 );			# coerce step to match range
		$step = ( $last < $first ) ? -$step : $step;
		@{$self}{qw(instant step)} = ( $first, $step );
		$self->{count} = int( ( $last - $first ) / $step ) + 1;

		for ( $self->{template} ) {
			s/\\\$/\\036/g;				# disguise escaped dollar
			s/\$\$/\\036/g;				# disguise escaped dollar
		}
		return $self;
	}

	sub read {
		my $self = shift;
		return undef unless $self->{count};		# EOF

		my $instant = $self->{instant};			# update iterator state
		$self->{instant} += $self->{step};
		$self->{count}--;

		local $_ = $self->{template};			# copy template
		while (/\$\{([^\}]*)\}/) {			# substitute ${...}
			my $s = _format( $instant, split /[,]/, $1 );
			s/\$\{$1\}/$s/eg;
		}
		s/\$/_format($instant)/eg;			# unqualified $
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
		my $number = shift || 0;			# per ISC BIND 9.7
		my $offset = shift || 0;
		my $length = shift || 0;
		my $format = shift || 'd';
		for ($format) {
			my $value = $number + $offset;
			my $digit = $length || 1;
			return substr sprintf( "%01.$digit$format", $value ), -$length if /[doxX]/;
			my $nibble = join( '.', split //, sprintf ".%32.32lx", $value );
			return lc reverse substr $nibble, -$length if /[n]/;
			return uc reverse substr $nibble, -$length if /[N]/;
		}
	}

}


sub _generate {				## expand $GENERATE into input stream
	my ( $self, $range, $template ) = @_;

	my $handle = new Net::DNS::ZoneFile::Generator( $range, $template, $self->line );
	my $generate = new Net::DNS::ZoneFile($handle);

	undef $self->{latest};					# forbid empty owner field
	%$generate = %$self;					# save state, create link
	@{$self}{qw(link handle)} = ( $generate, $handle );
	return $handle;
}


my $LEX_REGEX = qw/("[^"]*")|("[^"]*)$|;[^\n]*|(^\s)|\s/;

sub _getline {				## get line from current source
	my $self = shift;

	my $fh = $self->{handle};
	while (<$fh>) {
		next unless /\S/;				# discard blank line
		next if /^\s*;/;				# discard comment line

		if (/\(/) {					# concatenate multi-line RR
			s/\\\\/\\092/g;				# disguise escaped escape
			s/\\"/\\034/g;				# disguise escaped quote
			s/\\;/\\059/g;				# disguise escaped semicolon
			my @token = grep defined && length, split /$LEX_REGEX/o;
			if ( grep $_ eq '(', @token ) {
				return $_ if grep $_ eq ')', @token;	# question user sanity
				while (<$fh>) {
					s/\\\\/\\092/g;		# disguise escaped escape
					s/\\"/\\034/g;		# disguise escaped quote
					s/\\;/\\059/g;		# disguise escaped semicolon
					substr( $_, 0, 0 ) = join ' ', @token;	  # need to handle multi-line quote
					@token = grep defined && length, split /$LEX_REGEX/o;
					last if grep $_ eq ')', @token;
				}
				$_ = join ' ', @token;		# reconstitute RR string
			}
		}

		return $_ unless /^\$/;				# RR string

		if (/^\$GENERATE/i) {				# directive
			my ( undef, $range, @template ) = split;
			die '$GENERATE incomplete' unless $range;
			$fh = $self->_generate( $range, "@template\n" );

		} elsif (/^\$INCLUDE/i) {			# directive
			my ( undef, $file, $origin ) = split;
			$fh = $self->_include($file);
			my $context = $self->{context};
			&$context( sub { $self->_origin($origin); } ) if $origin;

		} elsif (/^\$ORIGIN/i) {			# directive
			my ( undef, $origin ) = split;
			die '$ORIGIN incomplete' unless $origin;
			my $context = $self->{context};
			&$context( sub { $self->_origin($origin); } );

		} elsif (/^\$TTL/i) {				# directive
			my ( undef, $ttl ) = split;
			die '$TTL incomplete' unless defined $ttl;
			$self->{ttl} = new Net::DNS::RR(". $ttl IN A")->ttl;

		} else {					# unrecognised
			chomp;
			die "unknown directive: $_";
		}
	}

	$self->{eof} = $self->line;				# end of file
	my $ok = $fh->close;
	die "pipe: process exit status $?" if $?;
	die "close: $!" unless $ok;
	my $link = $self->{link} || return undef;		# end of zone
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

	$rr->{owner} = ( $self->{latest} || $rr )->{owner} if $noname;		  # overwrite placeholder

	$rr->class( $self->{class} ||= $rr->class );		# propagate RR class

	$self->{ttl} ||= $rr->type eq 'SOA' ? $rr->minimum : $rr->ttl;		  # default TTL
	$rr->ttl( $self->{ttl} ) unless defined $rr->{ttl};

	return $self->{latest} = $rr;
}


sub _include {				## open $INCLUDE file
	my $self = shift;
	my $file = shift;

	$file = catfile( $DIR ||= curdir(), $file ) unless file_name_is_absolute($file);

	my @discipline = ( join ':', '<', PerlIO::get_layers $self->{handle} ) if PERLIO;
	my $handle = new FileHandle( $file, @discipline ) or croak qq(open: $! "$file");

	undef $self->{latest};					# forbid empty owner field
	my $include = bless {%$self}, ref($self);		# save state, create link
	@{$self}{qw(link handle name)} = ( $include, $handle, $file );
	return $handle;
}


sub _origin {				## change $ORIGIN (scope: current file)
	my $self = shift;
	$self->{context} = origin Net::DNS::Domain(shift);
	undef $self->{latest};					# forbid empty owner field
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
