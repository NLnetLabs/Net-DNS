# $Id$ -*-perl-*-

use strict;
use Test::More;
use File::Spec;
use File::Find;
use ExtUtils::MakeMaker;

my @files;
my $blib = File::Spec->catfile(qw(blib lib));

find( sub { push( @files, $File::Find::name ) if /\.pm$/ && !/Template/ }, $blib );

my %manifest;
open MANIFEST, 'MANIFEST' or plan skip_all => "MANIFEST: $!";
while (<MANIFEST>) {
	chomp;
	my ( $volume, $directory, $name ) = File::Spec->splitpath($_);
	$manifest{lc $name}++ if $name;
}
close MANIFEST;

plan skip_all => 'No versions from git checkouts' if -e '.git';

plan skip_all => 'Not sure how to parse versions.' unless eval { MM->can('parse_version') };

plan tests => scalar @files;

foreach my $file ( sort @files ) {
	my $version = MM->parse_version($file);
	diag("$file\t=>\t$version") if $ENV{'NET_DNS_DEBUG'};
	ok( $version =~ /[\d.]{3}/, "file version: $version\t$file" );
	my ( $volume, $directory, $name ) = File::Spec->splitpath($file);
	diag("File not in MANIFEST: $file") unless $manifest{lc $name};
}


END {
	eval 'local @INC = grep $_ !~ m/blib/i, @INC; require Net::DNS';
	my @installed = grep $_ =~ m/DNS.pm$/i, values %INC;

	warn <<AMEN if scalar(@installed) && ( $Net::DNS::VERSION < 1.00 );

##
##	The installation path for this version of Net::DNS may differ
##	from the existing version $Net::DNS::VERSION in your perl library.
##
##	Please be aware that this upgrade may appear to fail because
##	version $Net::DNS::VERSION will usually occur earlier in the search path.
##	In most cases, deleting the old version resolves the problem.
##
##	@installed
##
AMEN

}

__END__

