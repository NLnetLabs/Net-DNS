# $Id: 00-version.t,v 2.101 2003/12/13 01:43:30 ctriv Exp $

use Test::More;
use File::Spec;
use File::Find;
use ExtUtils::MakeMaker;
use strict;

my @files;
my $blib = File::Spec->catfile(qw(blib lib));
	
find( sub { push(@files, $File::Find::name) if /\.pm$/}, $blib);

my $can = eval { MM->can('parse_version') };

if (!$@ and $can) {
	plan tests => scalar @files;
} else {
	plan skip_all => ' Not sure how to parse versions.';
}

foreach my $file (@files) {
	my $version = MM->parse_version($file);
	diag("$file\t=>\t$version") if $ENV{'NET_DNS_DEBUG'};
	isnt("$file: $version", "$file: undef", "$file has a version");
}



