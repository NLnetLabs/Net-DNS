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

plan skip_all => ' Not sure how to parse versions.' unless eval { MM->can('parse_version') };

plan tests => scalar @files + 1;

my $resolver_file = '';
my $win32version;

foreach my $file ( sort @files ) {
	my $version = MM->parse_version($file);
	diag("$file\t=>\t$version") if $ENV{'NET_DNS_DEBUG'};
	ok( $version =~ /[\d.]{3}/, "file version: $version\t$file" );
	if ( $file =~ /\bNet[^\w]DNS[^\w]Resolver[^\w]Win32\.pm$/ ) {
	    $win32version = $version;
	} elsif ( $file =~ /\bNet[^\w]DNS[^\w]Resolver.pm$/ ) {
	    $resolver_file = $file;
	}
}

SKIP : {
    skip 'No files processed', 1 unless ( @files );
    skip 'Cygwin that does not use Win32::IPHelper', 1 
	if ( $^O eq 'cygwin' && ! defined($win32version) );

    open(my $fh, '<', $resolver_file) 
	or die "Could not open '$resolver_file': $!";

    while (<$fh>) {
	chomp;
	if ( m/[^\d](\d+)\s*;?\s*#\s*WIN32VERSION\b/ ) {
	    ok($1 <= $win32version, 'win32version in Resolver.pm <= '
				  . '$Net::DNS::Resolver::Win32::VERSION' );
	    last;
	}
    }
    close $fh;
}

