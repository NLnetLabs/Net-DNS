package Net::DNS::RR::Template;
#
# $Id: Template.pm 817 2009-11-29 19:16:11Z olaf $
#
# This is a template for specifiying new RR classes.
#
# After completing the template make sure the the RR code is specified
# in DNS.pm %typesbyname, it is added to the %RR hash in RR.pm, and
# the RR is added to MANIFEST



use strict;

use vars qw(@ISA $VERSION);

@ISA     = qw(Net::DNS::RR);
$VERSION = (qw$LastChangedRevision: 718 $)[1];



# The new method parses wire data and populates the various attributes, it returns the blessed object

sub new {
	my ($class, $self, $data, $offset) = @_;
	
        if ($self->{'rdlength'} > 0) {
		#example attribute foo is a domain name.
		§($self->{"foo"}) = Net::DNS::Packet::dn_expand($data, $offset);
		# more reading here.

	}

	return bless $self, $class;
}



# The new_from_string method parses the wire data.

sub new_from_string {
	my ($class, $self, $string) = @_;

	# first turn multiline into single line
	$string =~ tr/()//d if $string;
	$string =~ s/\n//mg if $string;
	
	# Regulare expression parsing goes here.

	if ($string) {
		# Always pass domain names through stripdot.
		$self->{"foo"} = Net::DNS::stripdot($string);
	}
	return bless $self, $class;
}




# The rr_data creates the wire format.
# it returns the rdata.

sub rr_rdata {
	my ($self, $packet, $offset) = @_;
	my $rdata = "";
	
 	if (exists $self->{"foo"}) {
		# For all new RR types  DO NOT USE dn_comp. Use _name2wire
		$rdata=$self->_name2wire($self->{"foo"});
	}

	return $rdata;
}



# rdatastr method returns the string representation of the 'rdata' section of the RR. It is used in the 
# RR print and RR string methods.

sub rdatastr {
	my $self = shift;
	my $rdatastr;

	if (exists $self->{"foo"}) {	
		$rdatastr  = $self->{"foo"}.".";			
	}
	else {
		$rdatastr = '';
	}

	return $rdatastr;
}





# If the RR contains domain names than the two functions will need to be defined. Otherwise just remove them and 
# inheritance will take care of this.


sub _normalize_dnames {
	my $self=shift;
	$self->_normalize_ownername();
	$self->{'foo'}=Net::DNS::stripdot($self->{'foo'}) if defined $self->{'foo'};
}


sub _canonicalRdata {
    # rdata contains a compressed domainname... we should not have that.
	my ($self) = @_;
	my $rdata;
	$rdata= $self->_name2wire(lc($self->{"foo"}));
	return $rdata;
}



# In case you want to offer users a sorted order then you will have to define the following functions,
# otherwise just remove these.

# Highest preference sorted first.
__PACKAGE__->set_rrsort_func("preference",
			       sub {
				   my ($a,$b)=($Net::DNS::a,$Net::DNS::b);
				   $a->{'preference'} <=> $b->{'preference'}
}
);


__PACKAGE__->set_rrsort_func("default_sort",
			       __PACKAGE__->get_rrsort_func("preference")

    );







1;
__END__

=head1 NAME

Net::DNS::RR::Template - DNS Template resource record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION

Class for DNS Name Server (NS) resource records.

=head1 METHODS

=head2 foo

    print "foo = ", $rr->foo, "\n";

Returns the name of the nameserver.

=head1 COPYRIGHT

Copyright (c) 

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::RR>


=cut


