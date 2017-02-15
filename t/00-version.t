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

foreach my $file ( sort @files ) {				# reconcile files with MANIFEST
	my $version = MM->parse_version($file);
	diag("$file\t=>\t$version") if $ENV{'NET_DNS_DEBUG'};
	ok( $version =~ /[\d.]{3}/, "file version: $version\t$file" );
	my ( $volume, $directory, $name ) = File::Spec->splitpath($file);
	diag("File not in MANIFEST: $file") unless $manifest{lc $name};
}


END {
	my %macro;						# extract Makefile macros
	open MAKEFILE, 'Makefile' or die $!;
	while (<MAKEFILE>) {
		next if /^#/;
		next unless /^([A-Z_]+)\s+=\s+(.*)$/;
		$macro{$1} = $2;
	}
	close MAKEFILE;

	my %install_type = qw(perl INSTALLPRIVLIB site INSTALLSITELIB vendor INSTALLVENDORLIB);
	my $install_site = join '', '$(DESTDIR)$(', $install_type{$macro{INSTALLDIRS}}, ')';
	for ($install_site) {
		s/\$\(([A-Z_]+)\)/$macro{$1}/g while /\$\(/;	# expand Makefile macros
		s|([/])[/]+|$1|g;				# remove gratuitous //s
	}

	eval { local @INC = grep $_ !~ m/\Wblib\W/i, @INC; require Net::DNS };
	my @installed = grep $_ =~ m/\WNet\WDNS.pm$/i, values %INC;
	my %noinstall;

	foreach my $existing (@installed) {			# mark hidden directories
		my $x;
		foreach my $path (@INC) {
			$noinstall{$path} ||= $existing =~ /^$path/ ? $x++ : $x;
		}
	}

	warn <<"AMEN" if $noinstall{$install_site};

##
##	The install location for this version of Net::DNS differs
##	from the existing version $Net::DNS::VERSION in your perl library.
##	@installed
##
##	The installation will be rendered ineffective because Net::DNS
##	will be found on the library search path before the proposed
##	location  $install_site
##
##	Makefile has been generated to support build and test only.
##
AMEN

}


__END__

