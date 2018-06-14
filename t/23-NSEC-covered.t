# $Id$	-*-perl-*-
#

use strict;
use Test::More;
use Net::DNS;

my @prerequisite = qw(
		Net::DNS::RR::NSEC
		);

foreach my $package (@prerequisite) {
	next if eval "use $package; 1;";
	plan skip_all => "$package not installed";
	exit;
}

plan tests => 27;


my @cover = (

	# testing owner vv argument comparison
	[qw(	.			example.		zzzzzz.example. )],
	[qw( example.			a.example.		zzzzzz.example. )],
	[qw( a.example.			yljkjljk.a.example.	zzzzzz.example. )],
	[qw( yljkjljk.a.example.	Z.a.example.		zzzzzz.example. )],
	[qw( Z.a.example.		zABC.a.example.		zzzzzz.example. )],
	[qw( zABC.a.EXAMPLE.		z.example.		zzzzzz.example. )],
	[qw( z.example.			\001.z.example.		zzzzzz.example. )],
	[qw( \001.z.example.		*.z.example.		zzzzzz.example. )],
	[qw( *.z.example.		\200.z.example.		zzzzzz.example. )],

	# testing nxtdname vv argument comparison
	[qw( example.			a.example.		yljkjljk.a.example. )],
	[qw( example.			yljkjljk.a.example.	Z.a.example. )],
	[qw( example.			Z.a.example.		zABC.a.example. )],
	[qw( example.			zABC.a.EXAMPLE.		z.example. )],
	[qw( example.			z.example.		\001.z.example. )],
	[qw( example.			\001.z.example.		*.z.example. )],
	[qw( example.			*.z.example.		\200.z.example. )],
	[qw( example.			\200.z.example.		zzzzzz.example. )],

	# testing zone boundary conditions
	[qw( example.			orphan.example.		example. )],	       # empty zone
	[qw( aft.example.		after.example.		example. )],
	);


my @nocover = (
	[qw(	example.	example.	z.example. )],
	[qw(	example.	z.example.	z.example. )],
	[qw(	example.	zz.example.	z.example. )],
	[qw(	example.	other.tld.	z.example. )],
	[qw(	z.example.	other.tld.	example. )],
	[qw(	.		tld.		tld.	)],				     # no labels in owner name
	[qw(	tld.		.		tld.	)],				     # no labels in argument
	[qw(	tld.		tld.		.	)],				     # no labels in nxtdname
	);


foreach my $vector (@cover) {
	my ( $owner, $argument, $nxtdname ) = @$vector;
	my $test = join ' ', pad($owner), 'NSEC (', pad($nxtdname), 'A )';
	my $nsec = new Net::DNS::RR($test);
	ok( $nsec->covered($argument), "$test\t covered('$argument')" );
}


foreach my $vector (@nocover) {
	my ( $owner, $argument, $nxtdname ) = @$vector;
	my $test = join ' ', pad($owner), 'NSEC (', pad($nxtdname), 'A )';
	my $nsec = new Net::DNS::RR($test);
	ok( !$nsec->covered($argument), "$test\t!covered('$argument')" );
}


sub pad {
	sprintf '%20s', shift;
}


exit;

__END__

