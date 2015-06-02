# $Id$


use strict;
use Test::More;

my %prerequisite = qw(
		Test::Pod 1.45
		);

while ( my ( $package, $rev ) = each %prerequisite ) {
	next if eval "use $package $rev";
	plan skip_all => "$package $rev required for testing POD";
	exit;
}


my @poddirs = qw( blib demo );
my @allpods = all_pod_files(@poddirs);
all_pod_files_ok(@allpods);

