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

    $zonefile = new Net::DNS::ZoneFile( 'db.example' );

    while ( $rr = $zonefile->read ) {
	$rr->print;
    }

    @zone = $zonefile->read;


=head1 DESCRIPTION

Each Net::DNS::ZoneFile object instance represents a zone file
together with any subordinate files nominated using $INCLUDE
directives.  Zone file syntax is defined by RFC1035.

A program can have multiple zone file objects, each maintaining
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
use FileHandle;

use Net::DNS::Domain;
use Net::DNS::RR;

use constant UTF8 => eval {
	require Encode;
	die if Encode::decode_utf8( chr(91) ) ne '[';		# not UTF-EBCDIC  [see UTR#16 3.6]
	Encode::find_encoding('UTF8');
} || 0;


=head1 METHODS


=head2 new

    $zonefile = new Net::DNS::ZoneFile( 'db.example', ['example.com'] );

Returns a Net::DNS::ZoneFile object which represents the zone
file specified in the argument list.

The file is opened for reading and remains open until exhausted
or all references to the ZoneFile object cease to exist.

The optional second argument specifies $ORIGIN for the zone file.

=cut

use vars qw($DIR);

sub new {
	my $self = bless {}, shift;
	my $file = shift;
	$self->_origin(shift);

	$self->{handle} = $file;
	return $self if ref($file);

	$self->{name} = $file;
	$file = "$DIR/$file" if $DIR && $file !~ m#^[/]#;
	$self->{handle} = new FileHandle( $file, '<' ) unless UTF8;
	$self->{handle} = new FileHandle( $file, '<:encoding(UTF-8)' ) if UTF8;
	croak "Failed to open $file" unless $self->{handle};

	return $self;
}


=head2 read

    $rr = $zonefile->read;

When invoked in scalar context, returns the next RR encountered
in the zone file, or undefined if end of data has been reached.

Comments and blank lines are silently disregarded.

$INCLUDE, $ORIGIN, $TTL and $GENERATE directives are processed
transparently.


    @rr = $zonefile->read;

When invoked in list context, returns the list of all RR objects
in the zone file.

=cut

sub read {
	my ($self) = @_;

	return &_read unless ref $self;				# compatibility interface

	if (wantarray) {
		my @zone;					# return entire zone
		while ( my $rr = $self->read ) { push( @zone, $rr ) }
		return @zone;
	}

	eval {
		eval {
			for ( $self->_getline || return undef ) {
				local $SIG{__WARN__} = sub { die @_; };

				if (/^\s/) {			# replace empty RR name
					my $latest = $self->{latest};
					my ($name) = split /\s+/, $latest->string if $latest;
					substr( $_, 0, 0 ) = $name if defined $name;
				}

				# construct RR object with context specific dynamically scoped $ORIGIN
				my $context = $self->{context};
				my $record = &$context( sub { Net::DNS::RR->new_string($_) } );

				$self->{class} ||= $record->class;    # propagate RR class
				$record->class( $self->{class} );

				$self->{ttl} ||= $record->minimum if $record->type eq 'SOA';	# default TTL
				$record->ttl( $self->{ttl} ) unless defined $record->{ttl};

				return $self->{latest} = $record;
			}

		} or $@ && die;					# ugly construct to relate error to source
	} or $@ && ( $@ =~ s/\.\.\..+$/join( ', line ', $self->name, $self->line )/e, croak $@ );
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

Returns the line number of the last non-continuation line encountered
in the current zone file.

=cut

sub line {
	return shift->{line} || 0;
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
will continue to operate with minimal change using compatibility
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
can be obtained directly by calling in list context.

    @rr = Net::DNS::ZoneFile->read( $filename, $include_dir );


=head2 read

    $listref = Net::DNS::ZoneFile->read( $filename, $include_dir );

read() parses the specified zone file and returns a reference to the
list of Net::DNS::RR objects representing the RRs in the file.
The return value is undefined if the zone data can not be parsed.

=cut

{

	sub _read {
		my ($arg1) = @_;
		shift unless ref($arg1) || $arg1 ne __PACKAGE__;
		my $file = shift;
		local $DIR = shift;
		my $zone = new Net::DNS::ZoneFile($file);
		my @rr = eval { $zone->read; };
		return wantarray ? @rr : \@rr unless $@;
		warn "$@\n";
		return wantarray ? @rr : undef;
	}


	package Net::DNS::ZoneFile::Text;

	use overload ( '<>' => 'read' );

	sub new {
		my $self = bless {}, shift;
		my $data = shift;
		my @line = split /\n/, ref($data) ? $$data : $data;
		$self->{data} = \@line;
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

read() parses data from the specified file handle and returns a
reference to the list of Net::DNS::RR objects representing the RRs
in the file.
The return value is undefined if the zone data can not be parsed.
=cut

sub readfh {
	return &_read;
}


=head2 parse

    $listref = Net::DNS::ZoneFile->parse(  $string, $include_dir );
    $listref = Net::DNS::ZoneFile->parse( \$string, $include_dir );

parse() interprets the argument string and returns a reference to
the list of Net::DNS::RR objects representing the RRs.
The return value is undefined if the zone data can not be parsed.

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
		$self->{instant} = $instant + $self->{step};
		$self->{count}--;

		local $_ = $self->{template};			# copy template
		while (/\$\{([^\}]*)\}/) {			# substitute ${...}
			my $s = _format( $instant, split /[,]/, $1 );
			s/\$\{$1\}/$s/g;
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


	sub _format {				## convert $GENERATE iteration number to specified format
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


{

	sub _generate {				## expand $GENERATE into input stream
		my ( $self, $range, $template ) = @_;

		my $handle = new Net::DNS::ZoneFile::Generator( $range, $template, $self->line );

		my $generate = new Net::DNS::ZoneFile($handle);
		delete $self->{latest};				# forbid empty name
		%$generate = %$self;				# save state, create link
		@{$self}{qw(link handle)} = ( $generate, $handle );
	}


	sub _getline {				## get line from current source
		my $self = shift;

		my $fh = $self->{handle};
		while (<$fh>) {
			$self->{line} = $fh->input_line_number; # number refers to initial line
			next if /^\s*$/;			# discard blank line
			next if /^\s*;/;			# discard comment line

			while (/\(/) {				# concatenate multi-line RR
				s/\\\\/\\092/g;			# disguise escaped escape
				s/\\"/\\034/g;			# disguise escaped double quote
				s/\\;/\\059/g;			# disguise escaped semicolon
				my @token = grep defined && length, split /(^\s)|("[^"]*")|;[^\n]*|([()])|\s+/;
				last unless grep $_ eq '(', @token;
				last if grep $_ eq ')', @token;
				$_ = "@token " . <$fh>;
			}

			if (/^\$INCLUDE/) {			# directive
				my ( undef, $file, $origin ) = split;
				$self->_include($file);
				$fh = $self->{handle};
				next unless $origin;
				my $context = $self->{context};
				&$context( sub { $self->_origin($origin); } );
			} elsif (/^\$ORIGIN/) {			# directive
				my ( undef, $origin ) = split;
				die '$ORIGIN incomplete' unless $origin;
				my $context = $self->{context};
				&$context( sub { $self->_origin($origin); } );
			} elsif (/^\$TTL/) {			# directive
				my ( undef, $ttl ) = split;
				die '$TTL incomplete' unless $ttl;
				$self->{ttl} = Net::DNS::RR::ttl( {}, $ttl );
			} elsif (/^\$GENERATE/) {		# directive
				my ( undef, $range, @template ) = split;
				die '$GENERATE incomplete' unless $range;
				$self->_generate( $range, "@template\n" );
				$fh = $self->{handle};
			} elsif (/^\$/) {			# unrecognised
				chomp;
				die "unknown directive: $_";
			} else {
				chomp;
				return $_;			# RR string
			}
		}

		$fh->close or die "close: $! $?";		# end of file
		my $link = $self->{link} || return undef;	# end of zone
		%$self = %$link;				# end $INCLUDE
		return $self->_getline;				# resume input
	}


	sub _include {				## open $INCLUDE file
		my ( $self, $filename ) = @_;
		my $include = new Net::DNS::ZoneFile($filename);
		my $handle  = $include->{handle};
		delete $self->{latest};				# forbid empty name
		%$include = %$self;				# save state, create link
		@{$self}{qw(link handle name)} = ( $include, $handle, $filename );
	}


	sub _origin {				## change $ORIGIN (scope: current file)
		my $self = shift;
		$self->{context} = origin Net::DNS::Domain(shift);
	}
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

L<perl>, L<Net::DNS>, L<Net::DNS::Domain>, L<Net::DNS::RR>,
RFC1035 Section 5.1, RFC2308, BIND 9 Administrator Reference Manual

=cut
