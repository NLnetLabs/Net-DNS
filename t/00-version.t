# $Id: 00-version.t,v 1.1 2003/08/26 23:58:10 ctriv Exp $

use Test::More;
use File::Spec;
use File::Find;
use ExtUtils::MakeMaker;
use strict;

eval "use Test::Pod 0.95";

my @files;
my $blib = File::Spec->catfile(qw(blib lib));
	
find( sub { push(@files, $File::Find::name) if /\.pm$/}, $blib);

plan tests => scalar @files;

foreach my $file (@files) {
	my $version = ExtUtils::MM->parse_version($file);
	isnt("$file: $version", "$file: undef", "$file has a version");
}



