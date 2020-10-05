#!/usr/bin/perl -Wall
#
# Script that finds zonecuts in a domain name, reports the parent and
# child nameservers.  Uses the the undocumented utility functions
# wire2presentation and name2labels from Net::DNS
#
# FOR DEMONSTRATION PURPOSES ONLY, NO WARRANTY, NO SUPPORT
#
# Copyright (c) 2008 Olaf Kolkman (NLnet Labs)

# All rights reserved.  This program is free software; you may
# redistribute it and/or modify it under the same terms as Perl
# itself.




use strict;
use warnings;
use Net::DNS qw (wire2presentation name2labels);


my @labels=name2labels(shift);


my $resolver=Net::DNS::Resolver->new;
my $parental_lookup="";

while (@labels) {
	my $name=compose_name(@labels);

	if ($parental_lookup){
		my $pckt=$resolver->send($parental_lookup,"NS");
		
		if ($pckt->header->ancount){
			print_ns_a("Parent", $pckt->answer);
			$parental_lookup=0;
		}
	}
	
	my $pckt=$resolver->send($name,"SOA");
	if ($pckt->header->ancount){
		
		print "-----\nFOUND SOA @ $name" if ($pckt->answer)[0]->type eq "SOA";
		undef($pckt);
	        $pckt=$resolver->send($name,"NS");
		
		if ($pckt->header->ancount){
			print_ns_a("Child ", $pckt->answer);
			$parental_lookup=$name;
		}
	}
	
	shift @labels;
	
}

sub compose_name {
	my $name;
	foreach my $label (@_){
		$name .= wire2presentation($label) . ".";
	}
	return $name;
}
	

sub print_ns_a {
	my $caption=shift;
	foreach my $ns (@_){
		next unless $ns->type eq "NS";
		my $apckt=$resolver->send($ns->nsdname,"A");
		if ($apckt->header->ancount){
			foreach my $a ($apckt->answer){
				print $caption." NS ".$ns->nsdname. " : ".$a->address;
			}
		}else{
			print "No A RRs found for ". $ns->nsdname;
		}
		
	}
	return;
}



