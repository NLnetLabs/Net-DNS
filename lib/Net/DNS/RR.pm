package Net::DNS::RR;
#
# $Id: RR.pm,v 1.29 2003/08/10 15:20:24 ctriv Exp $
#
use strict;
use vars qw($VERSION $AUTOLOAD);

use Carp;
use Net::DNS;

$VERSION = (qw$Revision: 1.29 $)[1];

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
#' Stupid Emacs (I Don't even USE emacs!) '


# %RR needs to be available within the scope of the BEGIN block.
# $RR_REGEX is a global just to be on the safe side.  
# %_LOADED is used internally for autoloading the RR subclasses.
use vars qw(%RR %_LOADED $RR_REGEX);

BEGIN {

	%RR = map { $_ => 1 } qw(
		A
		AAAA
		AFSDB
		CNAME
		CERT
		DNAME
		EID
		HINFO
		ISDN
		LOC
		MB
		MG
		MINFO
		MR
		MX
		NAPTR
		NIMLOC
		NS
		NSAP
		NULL
		PTR
		PX
		RP
		RT
		SOA
		SRV
		TKEY
		TSIG
		TXT
		X25
		OPT
	);

	#  Only load DNSSEC if available
	# 

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

sub build_regex {
	my $classes = join('|', keys %Net::DNS::classesbyname);
		
	# Longest ones go first, so the regex engine will match AAAA before A.
	my $types   = join('|', sort { length $b <=> length $a } keys %Net::DNS::typesbyname);
				
	$RR_REGEX   = " ^ 
					\\s*
    	            (\\S+) # name anything non-space will do 
    	            \\s*                
    	            (\\d+)?           
    	            \\s*
    	            ($classes)?
    	            \\s*
    	            ($types)?
    	            \\s*
    	            (.*)
    	            \$";



	#print STDERR "Regex: $RR_REGEX\n";
}


=head2 new (from string)

    $a = Net::DNS::RR->new("foo.example.com. 86400 A 10.1.2.3");
    $mx = Net::DNS::RR->new("example.com. 7200 MX 10 mailhost.example.com.");
    $cname = Net::DNS::RR->new("www.example.com 300 IN CNAME www1.example.com");
    $txt = Net::DNS::RR->new("baz.example.com 3600 HS TXT 'text record'");

Returns a C<Net::DNS::RR> object of the appropriate type and
initialized from the string passed by the user.  The format of the
string is that used in zone files, and is compatible with the string
returned by C<<Net::DNS::RR->string>>.

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
	if (@_ == 8 && ref $_[6]) {
		return new_from_data(@_);
	}
	
	if (@_ == 2 || @_ == 3) {
		return new_from_string(@_);
	}
	
	return new_from_hash(@_);
}


sub new_from_data {
	my $class = shift;
	my ($name, $rrtype, $rrclass, $ttl, $rdlength, $data, $offset) = @_;

	my $self = {
		"name"		=> $name,
		"type"		=> $rrtype,
		"class"		=> $rrclass,
		"ttl"		=> $ttl,
		"rdlength"	=> $rdlength,
		"rdata"		=> substr($$data, $offset, $rdlength),
	};


	if ($RR{$rrtype}) {
		my $subclass = $class->_get_subclass($rrtype);
		
		return $subclass->new($self, $data, $offset);
	} else {
		bless $self, $class;
		
		return $self
	}

}

sub new_from_string {
	my ($class, $rrstring, $update_type) = @_;
	
	build_regex() unless $RR_REGEX;
	
	# strip out comments
	$rrstring   =~ s/;.*//g;
	
	($rrstring =~ m/$RR_REGEX/xso) || 
		confess qq|qInternal Error: "$rrstring" did not match RR pat.\nPlease report this to the author!\n|;

	my $name    = $1;
	my $ttl     = $2 || 0;
	my $rrclass = $3 || '';
	my $rrtype  = $4 || '';
	my $rdata   = $5 || '';

	$rdata =~ s/\s+$// if $rdata;
	$name  =~ s/\.$//  if $name;

	if (!$rrtype && $rrclass && $rrclass eq 'ANY') {
		$rrtype  = 'ANY';
		$rrclass = 'IN';
	} elsif (!$rrclass) {
		$rrclass = "IN";
	}

	$rrtype ||= 'ANY';
	

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

	# We used to check if $rrtype was defined at this point.  However,
	# we just defaulted it to ANY earlier....

	my $self = {
		"name"		=> $name,
		"type"		=> $rrtype,
		"class"		=> $rrclass,
		"ttl"		=> $ttl,
		"rdlength"      => 0,
		"rdata"         => "",
	};

	

	if ($RR{$rrtype}) {
		my $subclass = $class->_get_subclass($rrtype);
			
		return $subclass->new_from_string($self, $rdata);
	} else {
		bless $self, $class;
		return $self;
	}
}

sub new_from_hash {
	my $class    = shift;
	my %tempself = @_;
	my $self     = {};
	
	my ($key, $val);

	while (($key, $val) = each %tempself) {
		$self->{lc($key)} = $val;
	}

	Carp::croak('RR name not specified')
		unless exists $self->{'name'};
	Carp::croak('RR type not specified')
		unless exists $self->{'type'};

	$self->{'ttl'}   ||= 0;
	$self->{'class'} ||= 'IN';

	$self->{'rdlength'} = length $self->{'rdata'}
		if $self->{'rdata'};

	if ($RR{$self->{'type'}}) {
		my $subclass = $class->_get_subclass($self->{'type'});
	   
	    if (uc $self->{'type'} ne 'OPT') {
			bless $self, $subclass;
			
			return $self;
	    } else {  
			# Special processing of OPT. Since TTL and CLASS are
			# set by other variables. See Net::DNS::RR::OPT 
			# documentation
			return $subclass->new_from_hash($self);
	    }
	} else {
	 	bless $self, $class;
	 	return $self;
	}
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
#' someone said that emacs gets screwy here.  Who am I to claim otherwise...

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


	# Don't compress TSIG or TKEY names and don't mess with EDNS0 packets
	if (uc($self->{"type"}) eq "TSIG" || uc($self->{"type"}) eq "TKEY") {
		my $tmp_packet = Net::DNS::Packet->new("");
		$data = $tmp_packet->dn_comp($self->{"name"}, 0);
	} elsif (uc($self->{"type"}) eq "OPT") {
		my $tmp_packet = Net::DNS::Packet->new("");
		$data = $tmp_packet->dn_comp("", 0);
	} else {
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
	if (uc($self->{"type"}) ne "OPT") {
	    $data .= pack("n", $qclass_val);
	} else {
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

    my $rdata = '';
    my @dname = split(m/\./, lc $name);
    
    for (@dname) {
		$rdata .= pack('C', length $_);
		$rdata .= $_ ;
    }
    
    $rdata .= pack('C', '0');
    
    return $rdata;
}

sub AUTOLOAD {
	my ($self) = @_;  # If we do shift here, it will mess up the goto below.
	
	my ($name) = $AUTOLOAD =~ m/^.*::(.*)$/;
	
	# XXX -- We should test that we do in fact carp on unknown methods.	
	unless (exists $self->{$name}) {
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
		return;
	}
	
	no strict q/refs/;
	
	# Build a method in the class.
	*{$AUTOLOAD} = sub {
		my ($self, $new_val) = @_;
				
		if (defined $new_val) {
			$self->{$name} = $new_val;
		}
		
		return $self->{$name};
	};
	
	# And jump over to it.
	goto &{$AUTOLOAD};
}


#
#  Net::DNS::RR->_get_subclass($type)
#
# Return a subclass, after loading a subclass (if needed)
#
sub _get_subclass {
	my ($class, $type) = @_;
	
	return unless $type and $RR{$type};
	
	my $subclass = join('::', $class, $type);
	
	unless ($_LOADED{$subclass}) {
		eval "require $subclass";
		die $@ if $@;
		$_LOADED{$subclass}++;
	}
	
	return $subclass;
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
