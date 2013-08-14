# $Id$

use Test::More;
use File::Spec;
use File::Find;
use strict;

eval 'use 5.6.2; use Test::Pod 0.95';

if ($@) {
	plan skip_all => 'test requires Perl 5.6.2 and Test::Pod 0.95';
} else {
	Test::Pod->import;

	my @files;
	my $blib = File::Spec->catfile(qw(blib lib));

	find( sub { push( @files, $File::Find::name ) if /\.(pl|pm|pod)$/ }, $blib );

	plan tests => scalar @files;

	foreach my $file (@files) {
		pod_file_ok($file);
	}
}

