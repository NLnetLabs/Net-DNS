package Net::DNS;

#
# $Id$
#
use vars qw($VERSION $SVNVERSION);
$VERSION    = '0.77_1';
$SVNVERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS - Perl Interface to the Domain Name System

=head1 SYNOPSIS

    use Net::DNS;

=head1 DESCRIPTION

Net::DNS is a collection of Perl modules that act as a Domain Name System
(DNS) resolver. It allows the programmer to perform DNS queries that are
beyond the capabilities of "gethostbyname" and "gethostbyaddr".

The programmer should be somewhat familiar with the format of a DNS packet
and its various sections. See RFC 1035 or DNS and BIND (Albitz & Liu) for
details.

=cut


use 5.004_04;
use strict;
use integer;

use base qw(Exporter);
use vars qw(@EXPORT);
@EXPORT = qw(SEQUENTIAL UNIXTIME YYYYMMDDxx
		yxrrset nxrrset yxdomain nxdomain rr_add rr_del
		mx rrsort);


use vars qw($HAVE_XS);
$HAVE_XS = eval {
	local $SIG{'__DIE__'} = 'DEFAULT';

	my $version = $VERSION;
	$version =~ s/[^0-9.]//g;

	eval {
		require XSLoader;
		XSLoader::load( 'Net::DNS', $version );
		1;
	} or do {
		use vars qw(@ISA);
		require DynaLoader;
		push @ISA, 'DynaLoader';
		bootstrap Net::DNS $version;
		1;
	};

} || 0;


use Net::DNS::RR;
use Net::DNS::Packet;
use Net::DNS::Update;
use Net::DNS::Resolver;


sub version { $VERSION; }


#
# mx()
#
# Usage:
#    my @mxes = mx('example.com', 'IN');
#
sub mx {
	my $res = ref $_[0] ? shift : Net::DNS::Resolver->new;

	my ( $name, $class ) = @_;
	$class ||= 'IN';

	my $ans = $res->query( $name, 'MX', $class ) || return;

	# This construct is best read backwords.
	#
	# First we take the answer secion of the packet.
	# Then we take just the MX records from that list
	# Then we sort the list by preference
	# Then we return it.
	# We do this into an array to force list context.
	my @ret = sort { $a->preference <=> $b->preference }
			grep { $_->type eq 'MX' } $ans->answer;

	return @ret;
}


#
# rrsort()
#
# Usage:
#    @prioritysorted = rrsort( "SRV", "priority", @rr_array );
#
sub rrsort {
	my $rrtype = uc shift;
	my @empty;
	my ( $attribute, @rr_array ) = @_;

	return undef unless defined $attribute;			# attribute not specified
	( @rr_array, $attribute ) = @_ if ref($attribute) =~ /^Net::DNS::RR/;

	my @extracted_rr = grep $_->type eq $rrtype, @rr_array;
	return @empty unless scalar @extracted_rr;
	my $func   = "Net::DNS::RR::$rrtype"->get_rrsort_func($attribute);
	my @sorted = sort $func @extracted_rr;
	return @sorted;
}


#
# Auxiliary functions to support policy-driven zone serial numbering.
#
#	$successor = $soa->serial(SEQUENTIAL);
#	$successor = $soa->serial(UNIXTIME);
#	$successor = $soa->serial(YYYYMMDDxx);
#

sub SEQUENTIAL {undef}

sub UNIXTIME { return CORE::time; }

sub YYYYMMDDxx {
	my ( $dd, $mm, $yy ) = (localtime)[3 .. 5];
	return 1900010000 + sprintf '%d%0.2d%0.2d00', $yy, $mm, $dd;
}


#
# Auxiliary functions to support dynamic update.
#

sub yxrrset {
	my $rr = new Net::DNS::RR(shift);
	$rr->ttl(0);
	$rr->class('ANY') unless $rr->rdata;
	return $rr;
}

sub nxrrset {
	my $rr = new Net::DNS::RR(shift);
	return new Net::DNS::RR(
		name  => $rr->name,
		type  => $rr->type,
		class => 'NONE'
		);
}

sub yxdomain {
	my ($domain) = split /\s+/, shift;
	return new Net::DNS::RR("$domain ANY ANY");
}

sub nxdomain {
	my ($domain) = split /\s+/, shift;
	return new Net::DNS::RR("$domain NONE ANY");
}

sub rr_add {
	my $rr = new Net::DNS::RR(shift);
	$rr->{ttl} ||= 86400;
	return $rr;
}

sub rr_del {
	my ( $head, @tail ) = split /\s+/, shift;
	my $rr = new Net::DNS::RR( scalar @tail ? "$head @tail" : "$head ANY" );
	$rr->ttl(0);
	$rr->class( $rr->rdata ? 'NONE' : 'ANY' );
	return $rr;
}


########################################
#	Net::DNS::SEC 0.17 compatibility
########################################

use constant OLDDNSSEC => Net::DNS::RR->COMPATIBLE;

if (OLDDNSSEC) {
	require Net::DNS::RR::RRSIG;	## pre-load RRs
	foreach my $type (qw(SIG DS DLV DNSKEY KEY NXT NSEC)) {
		new Net::DNS::RR( type => $type );
	}

	eval {
		no warnings 'void';	## suppress "Too late to run INIT block ..."

		sub INIT {		## only needed to satisfy DNSSEC t/00-load.t
			return unless OLDDNSSEC;

			# attempt to pre-load RRs which have circular dependence problems
			foreach my $type (qw(NSEC3 NSEC3PARAM)) {
				new Net::DNS::RR( type => $type );
			}
		}
	};
}


require Carp;
require Net::DNS::Parameters;

my $warned;

sub deprecated {
	Carp::carp "deprecated @_" unless $warned++;
}

sub typesbyname {
	deprecated('typesbyname; use Net::DNS::Parameters::typebyname') unless OLDDNSSEC;

	# preserve historical behaviour for TYPE0	[OMK]
	Net::DNS::Parameters::typebyname(shift) || '00';
}

sub typesbyval {
	deprecated('typesbyval; use Net::DNS::Parameters::typebyval') unless OLDDNSSEC;
	Net::DNS::Parameters::typebyval(shift);
}

if (OLDDNSSEC) {
	use vars qw(%typesbyname %typesbyval);
	%typesbyname = %Net::DNS::Parameters::typebyname;
	%typesbyval  = %Net::DNS::Parameters::typebyval;
}


use vars qw(@EXPORT_OK);
@EXPORT_OK = qw(name2labels presentation2wire wire2presentation stripdot);

#
# name2labels()
#
# Utility function to translate names from presentation format into
# an array of "wire-format" labels.
#
# in: $dname a string with a domain name in presentation format
# (1035 sect 5.1)
# out: an array of labels in wire format.

sub name2labels {
	deprecated('name2labels') unless OLDDNSSEC;
	my $dname = shift;
	my @names;
	my $j = 0;
	while ($dname) {
		( $names[$j], $dname ) = presentation2wire($dname);
		$j++;
	}

	return @names;
}


sub wire2presentation {
	deprecated('wire2presentation') unless OLDDNSSEC;
	my $presentation = shift;				# Really wire...

	# Prepend these with a backslash
	$presentation =~ s/(["$();@.\\])/\\$1/g;

	# Convert < 33 and > 126 to \x<\d\d\d>
	$presentation =~ s/([^\x21-\x7E])/sprintf("\\%03u", ord($1))/eg;

	return $presentation;
}


sub stripdot {
	deprecated('stripdot') unless OLDDNSSEC;

	# Code courtesy of JMEHNLE <JMEHNLE@cpan.org>
	# rt.cpan.org #51009

	# Strips the final non-escaped dot from a domain name.	Note
	# that one could have a label that looks like "foo\\\\\.\.."
	# although not likely one wants to deal with that cracefully.
	# This utilizes 2 functions in the DNS module to deal with
	# thing cracefully.

	return join( '.', map( wire2presentation($_), name2labels(shift) ) );

}


#
#    ($wire,$leftover)=presentation2wire($leftover);
#
# Will parse the input presentation format and return everything before
# the first non-escaped "." in the first element of the return array and
# all that has not been parsed yet in the 2nd argument.

sub presentation2wire {
	deprecated('presentation2wire') unless OLDDNSSEC;
	my $presentation = shift;
	my $wire	 = "";

	while ( $presentation =~ /\G([^.\\]*)([.\\]?)/g ) {
		$wire .= $1 if defined $1;

		if ($2) {
			if ( $2 eq '.' ) {
				return ( $wire, substr( $presentation, pos $presentation ) );
			}

			#backslash found
			if ( $presentation =~ /\G(\d\d\d)/gc ) {
				$wire .= pack( "C", $1 );
			} elsif ( $presentation =~ /\G([@().\\])/gc ) {
				$wire .= $1;
			}
		}
	}

	return $wire;
}

########################################

1;
__END__



=head2 Resolver Objects

A resolver object is an instance of the
L<Net::DNS::Resolver|Net::DNS::Resolver> class. A program can have
multiple resolver objects, each maintaining its own state information
such as the nameservers to be queried, whether recursion is desired,
etc.


=head2 Packet Objects

L<Net::DNS::Resolver|Net::DNS::Resolver> queries return
L<Net::DNS::Packet|Net::DNS::Packet> objects.  Packet objects have five
sections:

=over 3

=item *

The header section, a L<Net::DNS::Header|Net::DNS::Header> object.

=item *

The question section, a list of L<Net::DNS::Question|Net::DNS::Question>
objects.

=item *

The answer section, a list of L<Net::DNS::RR|Net::DNS::RR> objects.

=item *

The authority section, a list of L<Net::DNS::RR|Net::DNS::RR> objects.

=item *

The additional section, a list of L<Net::DNS::RR|Net::DNS::RR> objects.

=back

=head2 Update Objects

The L<Net::DNS::Update|Net::DNS::Update> package is a subclass of
L<Net::DNS::Packet|Net::DNS::Packet> for creating packet objects to be
used in dynamic updates.

=head2 Header Objects

L<Net::DNS::Header|Net::DNS::Header> objects represent the header
section of a DNS packet.

=head2 Question Objects

L<Net::DNS::Question|Net::DNS::Question> objects represent the content
of the question section of a DNS packet.

=head2 RR Objects

L<Net::DNS::RR|Net::DNS::RR> is the base class for DNS resource record
(RR) objects in the answer, authority, and additional sections of a DNS
packet.

Do not assume that RR objects will be of the type you requested -- always
check the type of an RR object before calling any of its methods.


=head1 METHODS

See the manual pages listed above for other class-specific methods.

=head2 version

    print Net::DNS->version, "\n";

Returns the version of Net::DNS.

=head2 mx

    # Use a default resolver -- can't get an error string this way.
    use Net::DNS;
    my @mx = mx("example.com");

    # Use your own resolver object.
    use Net::DNS;
    my $res = Net::DNS::Resolver->new;
    my @mx = mx($res, "example.com");

Returns a list of L<Net::DNS::RR::MX|Net::DNS::RR::MX> objects
representing the MX records for the specified name; the list will be
sorted by preference. Returns an empty list if the query failed or no MX
records were found.

This method does not look up A records -- it only performs MX queries.

See L</EXAMPLES> for a more complete example.



=head1 Dynamic DNS Update Support

The Net::DNS module provides auxiliary functions which support
dynamic DNS update requests.

=head2 yxrrset

Use this method to add an "RRset exists" prerequisite to a dynamic
update packet.	There are two forms, value-independent and
value-dependent:

    # RRset exists (value-independent)
    $update->push(pre => yxrrset("host.example.com A"));

Meaning:  At least one RR with the specified name and type must
exist.

    # RRset exists (value-dependent)
    $packet->push(pre => yxrrset("host.example.com A 10.1.2.3"));

Meaning:  At least one RR with the specified name and type must
exist and must have matching data.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 nxrrset

Use this method to add an "RRset does not exist" prerequisite to
a dynamic update packet.

    $packet->push(pre => nxrrset("host.example.com A"));

Meaning:  No RRs with the specified name and type can exist.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 yxdomain

Use this method to add a "name is in use" prerequisite to a dynamic
update packet.

    $packet->push(pre => yxdomain("host.example.com"));

Meaning:  At least one RR with the specified name must exist.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 nxdomain

Use this method to add a "name is not in use" prerequisite to a
dynamic update packet.

    $packet->push(pre => nxdomain("host.example.com"));

Meaning:  No RR with the specified name can exist.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 rr_add

Use this method to add RRs to a zone.

    $packet->push(update => rr_add("host.example.com A 10.1.2.3"));

Meaning:  Add this RR to the zone.

RR objects created by this method should be added to the "update"
section of a dynamic update packet.  The TTL defaults to 86400
seconds (24 hours) if not specified.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.

=head2 rr_del

Use this method to delete RRs from a zone.  There are three forms:
delete an RRset, delete all RRsets, and delete an RR.

    # Delete an RRset.
    $packet->push(update => rr_del("host.example.com A"));

Meaning:  Delete all RRs having the specified name and type.

    # Delete all RRsets.
    $packet->push(update => rr_del("host.example.com"));

Meaning:  Delete all RRs having the specified name.

    # Delete an RR.
    $packet->push(update => rr_del("host.example.com A 10.1.2.3"));

Meaning:  Delete all RRs having the specified name, type, and data.

RR objects created by this method should be added to the "update"
section of a dynamic update packet.

Returns a C<Net::DNS::RR> object or C<undef> if the object couldn't
be created.



=head1 Zone Serial Number Management

The Net::DNS module provides auxiliary functions which support
policy-driven zone serial numbering regimes.

=head2 Strictly Sequential

    $successor = $soa->serial( SEQUENTIAL );

The existing serial number is incremented modulo 2**32.

=head2 Time Encoded

    $successor = $soa->serial( UNIXTIME );

The Unix time scale will be used as the basis for zone serial
numbering. The serial number will be incremented if the time
elapsed since the previous update is less than one second.

=head2 Date Encoded

    $successor = $soa->serial( YYYYMMDDxx );

The 32 bit value returned by the auxiliary YYYYMMDDxx() function
will be used as the base for the date-coded zone serial number.
Serial number increments must be limited to 100 per day for the
date information to remain useful.



=head1 Sorting of RR arrays

As of version 0.55 there is functionality to help you sort RR arrays.
rrsort() is the function that is available to do the sorting. In most
cases rrsort() will give you the answer that you want but you can specify
your own sorting method by using the Net::DNS::RR::FOO->set_rrsort_func()
class method. See Net::DNS::RR for details.

=head2 rrsort()

    use Net::DNS qw(rrsort);

    @sorted = rrsort( $rrtype, $attribute, @rr_array );

rrsort() selects all RRs from the input array that are of the type defined
by the first argument. Those RRs are sorted based on the attribute that is
specified as second argument.

There are a number of RRs for which the sorting function is defined in the
code. The function can be overidden using the set_rrsort_func() method.

For instance:

    @prioritysorted = rrsort( "SRV", "priority", @rr_array );

returns the SRV records sorted from lowest to highest priority and for
equal priorities from highest to lowest weight.

If the function does not exist then a numerical sort on the attribute
value is performed.

    @portsorted = rrsort( "SRV", "port", @rr_array );

If the attribute is not defined then either the default_sort() function or
"canonical sorting" (as defined by DNSSEC) will be used.

rrsort() returns a sorted array containing only elements of the specified
RR type or undef.

rrsort() returns undef when arguments are incorrect.


=head1 EXAMPLES

The following examples show how to use the C<Net::DNS> modules.
See the other manual pages and the demo scripts included with the
source code for additional examples.

See the C<Net::DNS::Update> manual page for an example of performing
dynamic updates.


=head2 Look up a host's addresses.

    use Net::DNS;
    my $res   = Net::DNS::Resolver->new;
    my $reply = $res->search("host.example.com");

    if ($reply) {
	foreach my $rr ($reply->answer) {
	    next unless $rr->type eq "A";
	    print $rr->address, "\n";
	}
    } else {
	warn "query failed: ", $res->errorstring, "\n";
    }


=head2 Find the nameservers for a domain.

    use Net::DNS;
    my $res   = Net::DNS::Resolver->new;
    my $reply = $res->query("example.com", "NS");

    if ($reply) {
	foreach $rr (grep { $_->type eq 'NS' } $reply->answer) {
	    print $rr->nsdname, "\n";
	}
    }
    else {
	warn "query failed: ", $res->errorstring, "\n";
    }


=head2 Find the MX records for a domain.

    use Net::DNS;
    my $name = "example.com";
    my $res  = Net::DNS::Resolver->new;
    my @mx   = mx($res, $name);

    if (@mx) {
	foreach $rr (@mx) {
	    print $rr->preference, " ", $rr->exchange, "\n";
	}
    } else {
	warn "Can't find MX records for $name: ", $res->errorstring, "\n";
    }


=head2 Print a domain's SOA record in zone file format.

    use Net::DNS;
    my $res   = Net::DNS::Resolver->new;
    my $reply = $res->query("example.com", "SOA");

    if ($reply) {
	($reply->answer)[0]->print;
    } else {
	print "query failed: ", $res->errorstring, "\n";
    }


=head2 Perform a zone transfer and print all the records.

    use Net::DNS;
    my $res  = Net::DNS::Resolver->new;
    $res->nameservers("ns.example.com");

    my @zone = $res->axfr("example.com");

    foreach $rr (@zone) {
	$rr->print;
    }


=head2 Perform a background query for the answer.

    use Net::DNS;
    my $res    = Net::DNS::Resolver->new;
    my $socket = $res->bgsend("host.example.com");

    until ($res->bgisready($socket)) {
	# do some work here while waiting for the answer
	# ...and some more here
    }

    my $packet = $res->bgread($socket);
    $packet->print;


=head2 Send a background query using select to detect completion

    use Net::DNS;
    use IO::Select;

    my $timeout = 5;
    my $res	= Net::DNS::Resolver->new;
    my $bgsock	= $res->bgsend("host.example.com");
    my $sel	= IO::Select->new($bgsock);

    # Add more sockets to $sel if desired.
    my @ready = $sel->can_read($timeout);
    if (@ready) {
	foreach my $sock (@ready) {
	    if ($sock == $bgsock) {
		my $packet = $res->bgread($bgsock);
		$packet->print;
		$bgsock = undef;
	    }
	    # Check for the other sockets.
	    $sel->remove($sock);
	    $sock = undef;
	}
    } else {
	warn "timed out after $timeout seconds\n";
    }


=head1 BUGS

C<Net::DNS> is slow.

For other items to be fixed, or if you discover a bug in this
distribution please use the CPAN bug reporting system.


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr.

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2005 Olaf Kolkman (RIPE NCC)

Portions Copyright (c)2006 Olaf Kolkman (NLnet Labs)

Portions Copyright (c)2014 Dick Franks

All rights reserved.


=head1 LICENSE

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 AUTHOR INFORMATION

Net::DNS is maintained at NLnet Labs (www.nlnetlabs.nl) by
	Olaf Kolkman.

Between 2002 and 2004 Net::DNS was maintained by Chris Reinhardt.

Net::DNS was created by Michael Fuhr.


For more information see:
    http://www.net-dns.org/

Stay tuned and syndicate:
    http://www.net-dns.org/blog/

=head1 SEE ALSO

L<perl>, I<DNS and BIND> by Paul Albitz & Cricket Liu, RFC1035,
L<Net::DNS::Resolver>, L<Net::DNS::Packet>, L<Net::DNS::Update>,
L<Net::DNS::Question>, L<Net::DNS::RR>

=cut

