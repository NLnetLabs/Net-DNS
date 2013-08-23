# $Id$

use Test::More;
use File::Spec;
use File::Find;
use strict;

eval 'require Encode; use Test::Pod 0.95';

if ($@) {
	plan skip_all => 'test requires Test::Pod 0.95 and POD "=encoding" support';
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

