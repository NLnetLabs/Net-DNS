package Net::DNS::RR;

use strict;
use vars qw($VERSION $AUTOLOAD);

use Carp;
use Net::DNS;

# $Id: RR.pm,v 1.11 2002/06/30 14:41:19 ctriv Exp $
$VERSION = $Net::DNS::VERSION;

=head1 NAME

Net::DNS::RR - DNS Resource Record class

=head1 SYNOPSIS

C<use Net::DNS::RR>

=head1 DESCRIPTION

C<Net::DNS::RR> is the base class for DNS Resource Record (RR) objects.
See also the manual pages for each RR type.

=head1 METHODS

B<WARNING!!!>  Don't assume the RR objects you receive from a query
are of a particular type -- always check an object's type before calling
any of its methods.  If you call an unknown method, you'll get a nasty
warning message and C<Net::DNS::RR> will return C<undef> to the caller.

=cut
#'

# %RR needs to be available within the scope of the BEGIN block.
use vars qw( %RR );

# Need to figure out a good way to autoload these.
use Net::DNS::RR::A;		$RR{"A"}	= 1;
use Net::DNS::RR::AAAA;		$RR{"AAAA"}	= 1;
use Net::DNS::RR::AFSDB;	$RR{"AFSDB"}	= 1;
use Net::DNS::RR::CNAME;	$RR{"CNAME"}	= 1;
use Net::DNS::RR::DNAME;	$RR{"DNAME"}	= 1;
use Net::DNS::RR::EID;		$RR{"EID"}	= 1;
use Net::DNS::RR::HINFO;	$RR{"HINFO"}	= 1;
use Net::DNS::RR::ISDN;		$RR{"ISDN"}	= 1;
use Net::DNS::RR::LOC;		$RR{"LOC"}	= 1;
use Net::DNS::RR::MB;		$RR{"MB"}	= 1;
use Net::DNS::RR::MG;		$RR{"MG"}	= 1;
use Net::DNS::RR::MINFO;	$RR{"MINFO"}	= 1;
use Net::DNS::RR::MR;		$RR{"MR"}	= 1;
use Net::DNS::RR::MX;		$RR{"MX"}	= 1;
use Net::DNS::RR::NAPTR;	$RR{"NAPTR"}	= 1;
use Net::DNS::RR::NIMLOC;	$RR{"NIMLOC"}	= 1;
use Net::DNS::RR::NS;		$RR{"NS"}	= 1;
use Net::DNS::RR::NSAP;		$RR{"NSAP"}	= 1;
use Net::DNS::RR::NULL;		$RR{"NULL"}	= 1;
use Net::DNS::RR::PTR;		$RR{"PTR"}	= 1;
use Net::DNS::RR::PX;		$RR{"PX"}	= 1;
use Net::DNS::RR::RP;		$RR{"RP"}	= 1;
use Net::DNS::RR::RT;		$RR{"RT"}	= 1;
use Net::DNS::RR::SOA;		$RR{"SOA"}	= 1;
use Net::DNS::RR::SRV;		$RR{"SRV"}	= 1;
use Net::DNS::RR::TSIG;		$RR{"TSIG"}	= 1;
use Net::DNS::RR::TXT;		$RR{"TXT"}	= 1;
use Net::DNS::RR::X25;		$RR{"X25"}	= 1;
use Net::DNS::RR::OPT;		$RR{"OPT"}	= 1;

#  Only load DNSSEC if available
# 
BEGIN {
	eval { require Net::DNS::RR::SIG; };

	unless ($@) {
		$RR{"SIG"} = 1;
	
		eval { require Net::DNS::RR::NXT; };
		
		unless ($@) {
		    $RR{"NXT"}	= 1;
		} else {
		    die $@;
		}
		
		eval { require Net::DNS::RR::KEY; };
		
		unless ($@) {
		    $RR{"KEY"} = 1;
		} else {
		    die $@;
		}

	 	eval { require Net::DNS::RR::DS; };
	 	
	 	unless ($@) {
		    $RR{"DS"} = 1;
		} else {
		    die $@;
		}
    }
}


=head2 new (from string)

    $a = Net::DNS::RR->new("foo.example.com. 86400 A 10.1.2.3");
    $mx = Net::DNS::RR->new("example.com. 7200 MX 10 mailhost.example.com.");
    $cname = Net::DNS::RR->new("www.example.com 300 IN CNAME www1.example.com");
    $txt = Net::DNS::RR->new("baz.example.com 3600 HS TXT 'text record'");

Returns a C<Net::DNS::RR> object of the appropriate type and
initialized from the string passed by the user.  The format of the
string is that used in zone files, and is compatible with the string
returned by C<Net::DNS::RR>->C<string>.

The name and RR type are required; all other information is optional.
If omitted, the TTL defaults to 0 and the RR class defaults to IN.
Omitting the optional fields is useful for creating the empty RDATA
sections required for certain dynamic update operations.  See the
C<Net::DNS::Update> manual page for additional examples.

All names must be fully qualified.  The trailing dot (.) is optional.

=head2 new (from hash)

    $rr = Net::DNS::RR->new(
	Name    => "foo.example.com",
	TTL     => 86400,
	Class   => "IN",
        Type    => "A",
	Address => "10.1.2.3",
    );

    $rr = Net::DNS::RR->new(
	Name    => "foo.example.com",
        Type    => "A",
    );

Returns an RR object of the appropriate type, or a C<Net::DNS::RR>
object if the type isn't implemented.  See the manual pages for
each RR type to see what fields the type requires.

The C<Name> and C<Type> fields are required; all others are optional.
If omitted, C<TTL> defaults to 0 and C<Class> defaults to IN.  Omitting
the optional fields is useful for creating the empty RDATA sections
required for certain dynamic update operations.

The fields are case-insensitive, but starting each with uppercase
is recommended.

=cut

#' Stupid Emacs


sub new {
	my $retval;

	if (@_ == 8 && ref $_[6]) {
		$retval = new_from_data(@_);
	}
	elsif (@_ == 2 || @_ == 3) {
		$retval = new_from_string(@_);
	}
	else {
		$retval = new_from_hash(@_);
	}

	return $retval;
}

sub new_from_data {
	my $class = shift;
	my ($name, $rrtype, $rrclass, $ttl, $rdlength, $data, $offset) = @_;
	my (%self, $retval);

	%self = (
		"name"		=> $name,
		"type"		=> $rrtype,
		"class"		=> $rrclass,
		"ttl"		=> $ttl,
		"rdlength"	=> $rdlength,
		"rdata"		=> substr($$data, $offset, $rdlength),
	);


	if ($RR{$rrtype}) {
		my $subclass = $class . "::" . $rrtype;
		$retval = $subclass->new(\%self, $data, $offset);
	}
	else {
		$retval = bless \%self, $class;
	}

	return $retval;
}

sub new_from_string {
	my ($class, $rrstring, $update_type) = @_;
	my ($s, %self, $retval);

	my $name     = undef;
	my $ttl      = 0;
	my $rrclass  = "";
	my $rrtype   = "";
	my $rdata    = "";

	while ($rrstring =~ /\s*(\S+)\s*/g) {
		$s = $1;

		if (!defined($name)) {
			#($name = $s) =~ s/\.+$//;
			$name = $s;
			$name =~ s/^\.+//;
			$name =~ s/\.+$//;
		}
		elsif ($s =~ /^\d+$/) {
			$ttl = $s;
		}
		elsif (!$rrclass && exists $Net::DNS::classesbyname{uc($s)}) {
			$rrclass = uc($s);
			$rdata = $';  # in case this is really type=ANY
		}
		elsif (exists $Net::DNS::typesbyname{uc($s)}) {
			$rrtype = uc($s);
			$rdata = $';
			last;
		}
		else {
			last;
		}
	}

	$rdata =~ s/\s+$// if $rdata;

	if (!$rrtype && $rrclass && $rrclass eq "ANY") {
		$rrtype = $rrclass;
		$rrclass = "IN";
	}
	elsif (!$rrclass) {
		$rrclass = "IN";
	}

	if (!$rrtype) {
		$rrtype = "ANY";
	}

	if ($update_type) {
		$update_type = lc $update_type;
		
		if ($update_type eq "yxrrset") {
			$ttl = 0;
			$rrclass = "ANY" unless $rdata;
		} elsif ($update_type eq "nxrrset") {
			$ttl = 0;
			$rrclass = "NONE";
			$rdata = "";
		} elsif ($update_type eq "yxdomain") {
			$ttl = 0;
			$rrclass = "ANY";
			$rrtype = "ANY";
			$rdata = "";
		} elsif ($update_type eq "nxdomain") {
			$ttl = 0;
			$rrclass = "NONE";
			$rrtype = "ANY";
			$rdata = "";
		} elsif ($update_type =~ /^(rr_)?add$/) {
			$ttl = 86400 unless $ttl;
		} elsif ($update_type =~ /^(rr_)?del(ete)?$/) {
			$ttl = 0;
			$rrclass = $rdata ? "NONE" : "ANY";
		}
	}

	if ($rrtype) {
		%self = (
			"name"		=> $name,
			"type"		=> $rrtype,
			"class"		=> $rrclass,
			"ttl"		=> $ttl,
			"rdlength"      => 0,
			"rdata"         => "",
		);

		my $subclass = $class . "::" . $rrtype;

		if ($RR{$rrtype}) {
			my $subclass = $class . "::" . $rrtype;
			$retval = $subclass->new_from_string(\%self, $rdata);
		} else {
			$retval = bless \%self, $class;
		}
	} else {
		$retval = undef;
	}

	return $retval;
}

sub new_from_hash {
	my $class = shift;
	my %tempself = @_;
	my (%self, $retval);
	my ($key, $val);

	while (($key, $val) = each %tempself) {
		$self{lc($key)} = $val;
	}

	Carp::croak("RR name not specified")
		unless exists $self{"name"};
	Carp::croak("RR type not specified")
		unless exists $self{"type"};

	$self{"ttl"}   = 0    unless exists $self{"ttl"};
	$self{"class"} = "IN" unless exists $self{"class"};

	$self{"rdlength"} = length $self{"rdata"}
		if exists $self{"rdata"};

	if ($RR{$self{"type"}}) {
		my $subclass = $class . "::" . $self{"type"};
	    if (uc $self{"type"} ne "OPT"){
			$retval = bless \%self, $subclass;
	    } else {  
			# Special processing of OPT. Since TTL and CLASS are
			# set by other variables. See Net::DNS::RR::OPT 
			# documentation
			$retval = $subclass->new_from_hash(\%self);
	    }
	}
	else {
		$retval = bless \%self, $class;
	}

	return $retval;
}

#
# Some people have reported that Net::DNS dies because AUTOLOAD picks up
# calls to DESTROY.
#
sub DESTROY {}

=head2 print

    $rr->print;

Prints the record to the standard output.  Calls the
B<string> method to get the RR's string representation.

=cut
#'
sub print {
	my $self = shift;
	print $self->string, "\n";
}

=head2 string

    print $rr->string, "\n";

Returns a string representation of the RR.  Calls the
B<rdatastr> method to get the RR-specific data.

=cut

sub string {
	my $self = shift;

	return $self->{"name"}  . ".\t" .
	       $self->{"ttl"}   . "\t"  .
	       $self->{"class"} . "\t"  .
	       $self->{"type"}  . "\t"  .
	       $self->rdatastr;
}

=head2 rdatastr

    $s = $rr->rdatastr;

Returns a string containing RR-specific data.  Subclasses will need
to implement this method.

=cut

sub rdatastr {
	my $self = shift;
	return exists $self->{"rdlength"}
	       ? "; rdlength = " . $self->{"rdlength"}
	       : "; no data";
}

=head2 name

    $name = $rr->name;

Returns the record's domain name.

=head2 type

    $type = $rr->type;

Returns the record's type.

=head2 class

    $class = $rr->class;

Returns the record's class.

=cut

# Used to AUTOLOAD this, but apparently some versions of Perl (specifically
# 5.003_07, included with some Linux distributions) would return the
# class the object was blessed into, instead of the RR's class.

sub class {
	my $self = shift;

	if (@_) {
		$self->{"class"} = shift;
	} elsif (!exists $self->{"class"}) {
		Carp::carp("class: no such method");
		return undef;
	}
	return $self->{"class"};
}
	

=head2 ttl

    $ttl = $rr->ttl;

Returns the record's time-to-live (TTL).

=head2 rdlength

    $rdlength = $rr->rdlength;

Returns the length of the record's data section.

=head2 rdata

    $rdata = $rr->rdata

Returns the record's data section as binary data.

=cut
#'
sub rdata {
	my $self = shift;
	my $retval = undef;

	if (@_ == 2) {
		my ($packet, $offset) = @_;
		$retval = $self->rr_rdata($packet, $offset);
	}
	elsif (exists $self->{"rdata"}) {
		$retval = $self->{"rdata"};
	}

	return $retval;
}

sub rr_rdata {
	my $self = shift;
	return exists $self->{"rdata"} ? $self->{"rdata"} : "";
}

#------------------------------------------------------------------------------
# sub data
#
# This method is called by Net::DNS::Packet->data to get the binary
# representation of an RR.
#------------------------------------------------------------------------------

sub data {
	my ($self, $packet, $offset) = @_;
	my $data;


	# Don't compress TSIG names and don't mess with EDNS0 packets
	if (uc($self->{"type"}) eq "TSIG") {
		my $tmp_packet = Net::DNS::Packet->new("");
		$data = $tmp_packet->dn_comp($self->{"name"}, 0);
	}elsif (uc($self->{"type"}) eq "OPT") {
		my $tmp_packet = Net::DNS::Packet->new("");
		$data = $tmp_packet->dn_comp("", 0);
	}else {
	        $data  = $packet->dn_comp($self->{"name"}, $offset);
	}

	my $qtype = uc($self->{"type"});
	my $qtype_val = ($qtype =~ /^\d+$/) ? $qtype : $Net::DNS::typesbyname{$qtype};
	$qtype_val = 0 if !defined($qtype_val);

	my $qclass = uc($self->{"class"});
	my $qclass_val = ($qclass =~ /^\d+$/) ? $qclass : $Net::DNS::classesbyname{$qclass};
	$qclass_val = 0 if !defined($qclass_val);
	$data .= pack("n", $qtype_val);
	# If the type is OPT then class will need to contain a decimal number
	# containing the UDP payload size. (RFC2671 section 4.3)

	if (uc($self->{"type"}) ne "OPT"){
	    $data .= pack("n", $qclass_val);
	} else
	{
	    $data .= pack("n", $self->{"class"});
	}
	$data .= pack("N", $self->{"ttl"});

	$offset += length($data) + &Net::DNS::INT16SZ;	# allow for rdlength

	my $rdata = $self->rdata($packet, $offset);

	$data .= pack("n", length $rdata);
	$data .= $rdata;

	return $data;
}





#------------------------------------------------------------------------------
#  This method is called by SIG objects verify method. 
#  It is almost the same as data but needed to get an representation of the
#  packets in wire format withoud domain name compression.
#  It is essential to DNSSEC RFC 2535 section 8
#------------------------------------------------------------------------------

sub _canonicaldata {
    my $self = shift;
    my $data="";
    {   my @dname= split /\./,lc($self->{"name"});
	for (my $i=0;$i<@dname;$i++){
	    $data .= pack ("C",length $dname[$i] );
	    $data .= $dname[$i] ;
	}
	$data .= pack ("C","0");
    }
    $data .= pack("n", $Net::DNS::typesbyname{uc($self->{"type"})});
    $data .= pack("n", $Net::DNS::classesbyname{uc($self->{"class"})});
    $data .= pack("N", $self->{"ttl"});
    
    
    my $rdata = $self->_canonicalRdata;

    $data .= pack("n", length $rdata);
    $data .= $rdata;
    return $data;


}

# These are methods that are used in the DNSSEC context...  Some RR
# have domain names in them. Verification works only on RRs with
# uncompressed domain names. (Canonical format as in sect 8 of
# RFC2535) _canonicalRdata is overwritten in those RR objects that
# have domain names in the RDATA and _name2label is used to convert a
# domain name to "wire format"

sub _canonicalRdata {
    my $self = shift;
    my $rdata = $self->rr_rdata;
    return $rdata;
}



sub _name2wire   {   
    my ($self,$name)=@_;

    my $rdata="";
    my @dname= split /\./,lc($name);
    for (my $i=0;$i<@dname;$i++){
	$rdata .= pack ("C",length $dname[$i] );
	$rdata .= $dname[$i] ;
    }
    $rdata .= pack ("C","0");
    return $rdata;
}

sub AUTOLOAD {
	my $self = shift;
	my $name = $AUTOLOAD;
	$name =~ s/.*://;

	if (@_) {
		$self->{$name} = shift;
	} elsif (!exists $self->{$name}) {
		my $rr_string = $self->string;
		Carp::carp(<<"AMEN");

***
***  WARNING!!!  The program has attempted to call the method
***  "$name" for the following RR object:
***
***  $rr_string
***
***  This object doesn't have a method "$name".  THIS IS A BUG
***  IN THE CALLING SOFTWARE, which has incorrectly assumed that
***  the object would be of a particular type.  The calling
***  software should check the type of each RR object before
***  calling any of its methods.
***
***  Net::DNS has returned undef to the caller.
***
AMEN
		warn "\n";
		return undef;
	}

	return $self->{$name};
}

=head1 BUGS

This version of C<Net::DNS::RR> does little sanity checking on user-created
RR objects.

=head1 COPYRIGHT

Copyright (c) 1997-2002 Michael Fuhr.  All rights reserved.  This
program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself. 

EDNS0 extensions by Olaf Kolkman.
=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Update>, L<Net::DNS::Header>, L<Net::DNS::Question>,
RFC 1035 Section 4.1.3

=cut

1;
