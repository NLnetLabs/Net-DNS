package Net::DNS::ZoneFile;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::ZoneFile - DNS zone file

=head1 SYNOPSIS

    use Net::DNS;

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
	Encode::decode_utf8( chr(91) ) eq '[';			# specifically not UTF-EBCDIC
};


=head1 METHODS


=head2 new

    $zonefile = new Net::DNS::ZoneFile( 'db.example', ['example.com'] );

Returns a Net::DNS::ZoneFile object which represents the zone
file specified in the argument list.

The file is opened for reading and remains open until exhausted
or all references to the ZoneFile object cease to exist.

The optional second argument specifies $ORIGIN for the zone file.

=cut

use vars qw($SRC);

sub new {
	my $self = bless {}, shift;
	my $file = $self->{handle} = shift;
	$self->_origin(shift);

	$self->{name} = $file;
	return $self if ref($file);

	$file = "$SRC/$file" unless !$SRC or $file =~ /^[^A-Za-z0-9]/;
	$file =~ s(//)(/)g;					# remove duplicate /
	$file =~ s(^./)()g;					# and other decoration
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
	my $self = shift;

	return &_read unless ref $self;				# compatibility interface

	if (wantarray) {
		my @zone;					# return entire zone
		while ( my $rr = $self->read ) { push( @zone, $rr ) }
		return @zone;
	}

	eval {
		eval {
			for ( $self->_getline || return undef ) {
				chomp;
				if (/^\s/) {			# replace empty RR name
					my $latest = $self->{latest};
					my ($name) = split /\s+/, $latest->string if $latest;
					substr( $_, 0, 0 ) = $name if defined $name;
				}

				local $SIG{__WARN__} = sub { die @_; };

				# construct RR object with context specific dynamically scoped $ORIGIN
				my $context = $self->{context};
				my $record = &$context( sub { new_string Net::DNS::RR($_) } );

				$self->{class} ||= $record->class;    # propagate RR class
				$record->class( $self->{class} );

				$self->{ttl} ||= $record->minimum if $record->type eq 'SOA';	# default TTL
				$record->ttl( $self->{ttl} ) unless defined $record->{ttl};

				return $self->{latest} = $record;
			}

		} or $@ && die;					# ugly construct to relate error to source
	} or $@ && ( $@ =~ s/\.\.\.\w.+<\w+>/$self->name/e, croak $@);
}


=head2 name

    $filename = $zonefile->name;

Returns the name of the zone file from which RRs will be read.
$INCLUDE directives will cause this to differ from the filename
argument supplied when the object was created.

=cut

sub name {
	return shift->{name} || '';
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

    $rrset = Net::DNS::ZoneFile->read( $filename [, $include_dir] );

    $rrset = Net::DNS::ZoneFile->readfh( $fh [, $include_dir] );

    $rrset = Net::DNS::ZoneFile->parse( \$zone_text [, $include_dir] );

    print $_->string, "\n" for @$rrset;



=head2 read

    $rrset = Net::DNS::ZoneFile->read( $filename [, $include_dir] );

read() parses the specified zone file and returns a reference to an
array of Net::DNS::RR objects representing the RRs in the file.
The return value is undefined if the zone data can not be parsed.
=cut

{

	sub _read ($;$) {
		my $file = shift;
		local $SRC = shift;
		require Net::DNS;
		my $zone = new Net::DNS::ZoneFile($file);
		my $result = eval { my @rr = $zone->read; \@rr; };
		carp $@ if $@;
		return $result;
	}
}


=head2 readfh

    $rrset = Net::DNS::ZoneFile->readfh( $fh [, $include_dir] );

read() parses data from the specified file handle and returns a
reference to an array of Net::DNS::RR objects representing the RRs
in the file.
The return value is undefined if the zone data can not be parsed.
=cut

sub readfh ($$;$) {
	my $self = shift;
	return &_read;
}


=head2 parse

    $rrset = Net::DNS::ZoneFile->parse( \$zone_text [, $include_dir] );

=cut

sub parse ($$;$) {
	my $self = shift;
	my $data = shift;

	my $pipe = new FileHandle;				# pipe from iterator process
	my $pid = open( $pipe, '-|' );				# spawn iterator process
	die "cannot fork: $!" unless defined $pid;

	unless ($pid) {				## child
		foreach ( split /\n/, $$data ) {
			print;					# pipe to parser
			print "\n";
		}
		exit;						# done

	} else {				## parent
		return $self->readfh( $pipe, @_ );
	}
}

sub _parse { &parse; }


########################################

use vars qw($AUTOLOAD);

sub AUTOLOAD {				## Default method
	no strict;
	@_ = ("method $AUTOLOAD undefined");
	goto &{'Carp::confess'};
}


sub DESTROY { }				## Avoid tickling AUTOLOAD (in cleanup)


{

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


	sub _generate {				## expand $GENERATE into input stream
		my ( $self, $range, $template ) = @_;
		my ( $first, $last ) = split m#[-/]#, $range;
		my ( $junk,  $step ) = split m#[/]#,  $range;
		for ($template) {
			s/\$\$/\\036/g;				# disguise escaped dollar
			s/\\\$/\\036/g;				# disguise escaped dollar
		}

		my $handle = new FileHandle;			# pipe from iterator process
		my $pid = open( $handle, '-|' );		# spawn iterator process
		die "cannot fork: $!" unless defined $pid;

		unless ($pid) {				## child
			my $counter = 1 + ( $last - $first ) / ( $step ||= 1 );
			my $instant = $first;
			while ( $counter-- > 0 ) {
				local $_ = $template;		# copy template
				while (/\$\{([^\}]*)\}/) {	# substitute ${...}
					my $s = _format( $instant, split /[,]/, $1 );
					s/\$\{$1\}/$s/g;
				}
				s/\$/$instant/g;		# unqualified $
				print;				# pipe to parser
				$instant += $step;
			}
			exit;					# done

		} else {				## parent
			my $new = bless {};
			delete $self->{latest};			# forbid empty name after $GENERATE
			%$new = %$self;				# save state
			@{$self}{qw(link handle)} = ( $new, $handle );	  # create link
			$self->{name} .= '.[$GENERATE]';	# report source in failure messages
		}
	}


	sub _getline {				## get next RR line from file
		my $self = shift;

		my $fh = $self->{handle};
		while (<$fh>) {
			my $line = $self->{line} = $fh->input_line_number;
			next if /^\s*$/;			# discard blank line
			next if /^\s*;/;			# discard comment line

			while (/\(/) {				# concatenate multi-line RR
				s/\\\\/\\092/g;			# disguise escaped escape
				s/\\"/\\034/g;			# disguise escaped double quote
				s/\\'/\\039/g;			# disguise escaped single quote
				s/\\;/\\059/g;			# disguise escaped semicolon
				my @parse = grep length($_), split /("[^"]*")|('[^']*')|;.*\n|([()])|\s+/;
				last unless grep { length && /^[(]$/ } @parse;
				last if grep { length && /^[)]$/ } @parse;
				$_ = "@parse " . <$fh>;
			}
			$self->{line} = $line;			# renumber continuation lines

			if (/^\$INCLUDE/) {			# directive
				my ( undef, $file, $origin ) = split;
				$self->_include($file);
				$self->_origin($origin) if $origin;
				$fh = $self->{handle};
				next;
			} elsif (/^\$ORIGIN/) {			# directive
				my ( undef, $origin ) = split;
				$self->_origin( $origin or die '$ORIGIN incomplete' );
				next;
			} elsif (/^\$TTL/) {			# directive
				my ( undef, $ttl ) = split;
				$self->{ttl} = $ttl or die '$TTL incomplete';
				next;
			} elsif (/^\$GENERATE/) {		# directive
				my ( undef, $range, @template ) = split;
				$self->_generate( $range, "@template\n" );
				$fh = $self->{handle};
				next;
			} elsif (/^\$/) {			# unrecognised
				die "unknown directive: $_";
			} else {
				return "$_\n";			# all or part of RR
			}
		}

		close($fh) or die "close: $! $?";		# EOF
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


=head1 ACKNOWLEDGEMENT

This package is designed as an improved and compatible replacement
for Net::DNS::ZoneFile 1.04 which was created by Luis Munoz in 2002
as a separate CPAN module.

The present implementation is the result of an agreement to merge our
two different approaches into one package integrated into Net::DNS.
The contribution of Luis Munoz is gratefully acknowledged.


=head1 COPYRIGHT

Copyright (c)2011-2012 Dick Franks 

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Domain>, L<Net::DNS::RR>,
RFC1035 Section 5.1, RFC2308, BIND 9 Administrator Reference Manual

=cut
