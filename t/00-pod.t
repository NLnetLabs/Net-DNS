# $Id$

use strict;
use Test::More;

my $rev = '1.45';
eval "use Test::Pod $rev";
plan skip_all => "Test::Pod $rev required for testing POD" if $@;

my @poddirs = qw( blib demo );
my @allpods = all_pod_files(@poddirs);
all_pod_files_ok(@allpods);

