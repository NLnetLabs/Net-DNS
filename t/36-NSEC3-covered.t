# $Id$	-*-perl-*-

use strict;

BEGIN {
	use Test::More;
	use Net::DNS;

	my @prerequisite = qw(
			Digest::SHA
			MIME::Base32
			Net::DNS::RR::NSEC3;
			);

	foreach my $package (@prerequisite) {
		plan skip_all => "$package not installed"
				unless eval "require $package";
	}

	plan tests => 14;
}


## IMPORTANT:	Do not modify names or hash parameters in any way.
##		These are crafted to provide known hash relationships.
my $algorithm = 1;
my $flags     = 0;
my $iteration = 12;
my $salt      = 'aabbccdd';
my $saltbin   = pack 'H*', $salt;
my @param     = ( $algorithm, $flags, $iteration, $salt );

my @name = qw(
		domain.parent.example
		d.domain.parent.example
		n.domain.parent.example
		p.domain.parent.example
		q.domain.parent.example
		*.domain.parent.example
		);

my %hash;
foreach my $name (@name) {
	$hash{$name} = Net::DNS::RR::NSEC3::name2hash( $algorithm, $name, $iteration, $saltbin );
}

my %name = reverse %hash;
foreach ( sort keys %name ) {
	print join "\t", $_, $name{$_}, "\n";
}


my $hzone = $hash{'domain.parent.example'};
my $cover = $hash{'n.domain.parent.example'};
my $hnext = $hash{'d.domain.parent.example'};
my $bfore = $hash{'p.domain.parent.example'};
my $after = $hash{'q.domain.parent.example'};
my $nsec3 = new Net::DNS::RR("$hzone.$name{$hzone}. NSEC3 @param $hnext");

foreach my $name ($name{$hzone}) {
	ok( !$nsec3->covered($name), "NSEC3 owner name not covered\t($name)" );
}

foreach my $name ($name{$cover}) {
	ok( $nsec3->covered($name), "NSEC3 covers enclosed name\t($name)" );
}

foreach my $name ($name{$hnext}) {
	ok( !$nsec3->covered($name), "NSEC3 next name not covered\t($name)" );
}

foreach my $name ( $name{$bfore}, $name{$after} ) {
	ok( !$nsec3->covered($name), "NSEC3 does not cover other name\t($name)" );
}


my $last = new Net::DNS::RR("$hnext.$name{$hzone}. NSEC3 @param $hzone");
foreach my $name ($name{$hnext}) {
	ok( !$last->covered($name), "last NSEC3 owner not covered\t($name)" );
}

foreach my $name ($name{$hzone}) {
	ok( !$last->covered($name), "last NSEC3 next not covered\t($name)" );
}

foreach my $name ( $name{$bfore}, $name{$after} ) {
	ok( $last->covered($name), "last NSEC3 covers other name\t($name)" );
}


my @domain = qw(
		sibling.parent.example
		parent.example
		uncle.example
		cousin.uncle.example
		domain.unrelated
		);

foreach my $name (@domain) {
	ok( !$nsec3->covered($name), "other domain not covered\t($name)" );
}


exit;

