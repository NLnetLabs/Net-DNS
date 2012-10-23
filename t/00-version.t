# $Id$ -*-perl-*-

use Test::More;
use File::Spec;
use File::Find;
use ExtUtils::MakeMaker;
use strict;

my @files;
my $blib = File::Spec->catfile(qw(blib lib));
	
find( sub { push(@files, $File::Find::name) if /\.pm$/}, $blib);

plan skip_all => 'No versions from git checkouts' if -e '.git';

plan skip_all => 'Not sure how to parse versions.' unless eval { MM->can('parse_version') };


foreach my $file ( sort @files ) {
	next if $file =~ /Template/;
	my $version = MM->parse_version($file);
	diag("$file\t=>\t$version") if $ENV{'NET_DNS_DEBUG'};
	ok( $version =~ /[\d.]{3}/, "file version: $version\t$file" );
}

done_testing();

