# $Id: 04-pkt-safe-push.t,v 1.2 2002/12/05 07:07:03 ctriv Exp $

use Test::More tests => 73;
use strict;

BEGIN { use_ok('Net::DNS'); }     #1

my $domain = 'example.com';

my @tests = (
	[ 
		1,
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
	],
	[
		2,
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('bar.example.com 60 IN A 10.0.0.1'),
	],
	[ 
		2,
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('foo.example.com 90 IN A 10.0.0.1'),
	],
	[ 
		3,
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.2'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.3'),
	],
	[ 
		3,
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.2'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.3'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
	],
	[ 
		3,
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.2'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.1'),
		Net::DNS::RR->new_from_string('foo.example.com 60 IN A 10.0.0.4'),
	],
);

my %sections = (
	answer     => 'ancount',
	authority  => 'nscount',
	additional => 'arcount',
);
	


foreach my $try (@tests) {
	my ($count, @rrs) = @$try;
	
	while (my ($section, $count_meth) = each %sections) {
	
		my $packet = Net::DNS::Packet->new($domain);
		
		$packet->safe_push($section, @rrs);
	
		is($packet->header->$count_meth(), $count, "$section right");
	
		# Now we test the parsing in new.
		my $packet2 = Net::DNS::Packet->new(\($packet->data));
		$packet2->safe_push($section, @rrs);
		
		is($packet2->header->$count_meth(), $count, "$section right");
	}
	
	#
	# Now do it again calling safe_push() for each RR.
	# 
	while (my ($section, $count_meth) = each %sections) {
	
		my $packet = Net::DNS::Packet->new($domain);
		
		foreach (@rrs) {
			$packet->safe_push($section, $_);
		}
	
		is($packet->header->$count_meth(), $count, "$section right");
	
		# Now we test the parsing in new.
		my $packet2 = Net::DNS::Packet->new(\($packet->data));
		foreach (@rrs) {
			$packet2->safe_push($section, $_);
		}
		
		is($packet2->header->$count_meth(), $count, "$section right");
	}

}

