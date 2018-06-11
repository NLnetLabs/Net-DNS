# $Id$	-*-perl-*-
#

use strict;
use Test::More;
use Net::DNS::RR;

my @prerequisite = qw(
		Digest::SHA
		Net::DNS::RR::NSEC3
		);

foreach my $package (@prerequisite) {
	next if eval "use $package; 1;";
	plan skip_all => "$package not installed";
	exit;
}

plan tests => 3;


## Based on examples from RFC5155, Appendix B

my @nsec3;

push @nsec3, new Net::DNS::RR("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. NSEC3 1 1 12 aabbccdd (
	2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG )");


push @nsec3, new Net::DNS::RR("b4um86eghhds6nea196smvmlo4ors995.example. NSEC3 1 1 12 aabbccdd (
	gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG )");


push @nsec3, new Net::DNS::RR("35mthgpgcu1qg68fab165klnsnk3dpvl.example. NSEC3 1 1 12 aabbccdd (
	b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG )");


my $encloser;
my $nextcloser;
foreach my $nsec3 (@nsec3) {
	for ( $nsec3->encloser('a.c.x.w.example') ) {
		next unless length() > length($encloser);
		$encloser = $_;
		$nextcloser = $nsec3->nextcloser;
	}
}

is( $encloser,	 'x.w.example',	  'closest (provable) encloser' );
is( $nextcloser, 'c.x.w.example', 'next closer name' );

is( $nsec3[0]->encloser('a.n.other'), undef, 'reject name out of zone' );

exit;

__END__

