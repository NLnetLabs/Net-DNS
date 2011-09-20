
# $Id$ -*-perl-*-

use strict;
$^W = 1;

use ExtUtils::MakeMaker qw(WriteMakefile prompt);
use IO::Socket ();
use Config qw(%Config);
use Getopt::Long  qw(GetOptions);

sub DEBUG { 0; }

# An existing makefile can confuse the CC test.
unlink('Makefile');
# clean up the online testing flag file.
unlink("t/online.enabled"); 
unlink("t/online.disabled"); 
# clean up the IPv6 testing flag file.
unlink("t/IPv6.enabled");
unlink("t/IPv6.disabled");

warn <<AMEN if $] < 5.005;

This version of Net::DNS has not been tested against perl v$]
The author is confident that this package will function 
properly with older perls such as yours, but bugs may lurk. 


AMEN


#
# Get the command line args
#
my ($use_xs, $online_tests, $IPv6_tests);

my $help = 0;
my $online_tests = 2; # 2 = non-fatal, 1 is on, 0 if off

unless (GetOptions(
	'xs!'           => \$use_xs,
	'pm'            => sub { 
		warn qq/\n\tWARNING: Use of "--pm" is deprecated.  Use "--noxs" instead.\n\n/;
		$use_xs = 0;
	},
	'online-tests!' => \$online_tests,
	'non-fatal-online-tests' => sub {
		$online_tests = 2;
	},
	'IPv6-tests!'   => \$IPv6_tests,
	'help|?'        => \$help,
)) {
	print "Error: Unrecognized option.\n"; print "Try perl Makefile.PL --help for more information\n";
	exit 1;	
};

if ($help) {
	print <<EOT;

Usage: perl Makefile.PL [OPTION...]

Prepare Makefile for building and installing Net::DNS

  --xs | --noxs			Enable or disable linkage to the libresolv 
				library Default the libresolv library is 
				linked when a compiler is found.

  --online-tests		Perform tests by communicating with the
				outside world.  Beware that their success is
				also dependent on outside influences.

  --noonline-tests		Skip online tests completely.

  --non-fatal-online-tests	Perform online test, but do let failures 
				negatively affect the outcome of running
				make test.  This is the default.

EOT

	exit 0;
};


#
# Get our makefile started...
#
my %Makefile = (
	NAME          => 'Net::DNS',
	VERSION_FROM  => 'lib/Net/DNS.pm',
	PREREQ_PM     => {
		'Test::More'       => 0.18,
		'IO::Socket'       => 0,
		'MIME::Base64'     => 2.11,
		'Digest::MD5'      => 2.12,
		'Digest::SHA'      => 5.23,
		'Digest::HMAC_MD5' => 1.00,
	},
	XS            => {},
	C             => [],
	clean         => { FILES => 't/IPv6.enabled t/online.enabled compile.* DNS.o DNS.c DNS.bs' },


);



if ($^O eq 'MSWin32' || $^O eq 'cygwin') {
    unless(    eval {require WIN32::API; }	   ){
	warn <<AMEN; 
I can not find WIN32::API version 0.55 or higher.

I will add WIN32::API to the list of prerequisites.
AMEN


if ( $^O eq "MSWin32" ){ 
    warn <<AMEN2;
Note that, WIN32::API is included in recent versions
of ActivePerl (5.10 since build 1003) and recent
versions of Strawberry perl (at least in the October
version of 5.10.0.3) and the module has not be 
tested with other versions. In case of failure please
consider upgrading.
AMEN2
}else{
    warn <<AMEN3;
When using cygwin missing dependencies can be installed using CPAN.
AMEN3

}


    }
    $Makefile{'PREREQ_PM'}->{'enum'} = 1.0;  # Dependency for Win32::IPHelper
    $Makefile{'PREREQ_PM'}->{'Win32::IPHelper'} = 0.05;
    $Makefile{'PREREQ_PM'}->{'Win32::API'} = 0.55;
    $Makefile{'PREREQ_PM'}->{'Win32::Registry'} = 0;
}


# Not relevant with netdnslib.
#if ($^O eq 'darwin' and $Config{'osvers'} =~ m/^[78]\./) {
#	$Makefile{'DEFINE'} = '-DBIND_8_COMPAT';
#}

if ($] >= 5.005) {
	$Makefile{'AUTHOR'}   = 'Olaf Kolkman <olaf@net-dns.org>';
	$Makefile{'ABSTRACT'} = 'Perl DNS resolver module';
}

#
# Check if we have a C compiler

unless (defined $use_xs) {
	if (test_cc()) {
		print "You have a working compiler.\n";
		$use_xs = 1;
		$Makefile{'MYEXTLIB'}    = 'netdns$(LIB_EXT)';
	} else {
		$use_xs = 0;
		print <<END;
	
I cannot determine if you have a C compiler. I will install the 
perl-only implementation.
	
You can force installation of the XS version with:

	perl Makefile.PL --xs
END
	$Makefile{'MYEXTLIB'}    = '',		

	}
}








if ($use_xs) {
	# turn the XS bits on.
        print "Activating XS Magic...\n" if DEBUG; 
	$Makefile{'LIBS'} = '-lresolv' if($^O =~ /solaris|sunos/i);
	$Makefile{'OBJECT'} = '$(O_FILES)';
	delete $Makefile{'XS'};
	delete $Makefile{'C'};
}

#
# Check if we have internet connection
# (I lifted this code from LWP... )
#

if ($online_tests) {
	my $s = IO::Socket::INET->new(
		PeerAddr => "www.google.com:80",
		Timeout  => 10,
	);
	
	unless ($s) {
		print <<EOT;
	
You appear not to be directly connected to the Internet.
Disabling online tests altogether...
	
EOT

		$online_tests = 0;
	} else {
		close($s);
	}

}
if ($online_tests) {
	if ($online_tests == 2) {
		print "\nActivating Non Fatal Online Tests...\n\n";
	} else {
		print "\nActivating Online Tests...\n\n";
	}
	print <<EOT;
Warning!
========
Online tests depend on conditions out of the control of Net::DNS. The tests 
check for the expected results when both Net::DNS and the outside world are
functioning properly. In case of failure it is often undecidable if the error
lies with Net::DNS or elsewhere.

EOT
	open(ENABLED, ">t/online.enabled") || die "Can't touch ./t/online.enabled $!";
	close(ENABLED)                     || die "Can't touch ./t/online.enabled $!";
	if ($online_tests == 2) {
		open(NONFATAL, ">t/online.nonfatal") || die "Can't touch ./t/online.nonfatal $!";
		close(NONFATAL)                     || die "Can't touch ./t/online.nonfatal $!";
	}
}


#
# Test to see if IPv6 is available, unless IPv6 testing has been declined.
#    
if (!defined $IPv6_tests || $IPv6_tests == 1) {
	unless(    eval {require IO::Socket::INET6; IO::Socket::INET6->VERSION("2.01");}	   ) {
		print <<V6WARNING;

The libraries needed to support IPv6 transport have not been found. 
You will need recent versions of the IO::Socket::INET6 and Socket6 
libraries (from CPAN). 

V6WARNING
		if ($IPv6_tests) {
			$IPv6_tests = prompt('Are you sure you wish to enable IPv6 tests?', 'y') =~ /^y/i ? 1 : 0;
		}
	}
	if ($IPv6_tests) {
		print "\nActivating IPv6 Tests...\n"; 
		open(ENABLED, '>t/IPv6.enabled') || die "Can't touch ./t/IPv6.enabled $!";
		close(ENABLED)                   || die "Can't touch ./t/IPv6.enabled $!";
	}
}


WriteMakefile(%Makefile);





sub test_cc {
	#
	# The perl/C checking voodoo is stolen from Graham Barr's
	# Scalar-List-Utils distribution.
	#
	print "Testing if you have a C compiler and the needed header files....\n";

	unless (open(F, ">compile.c")) {
	    warn "Cannot write compile.c, skipping test compilation and installing pure Perl version.\n";
		return;
	}

	print F <<'EOF';
#include "netdns.h"
int main() { return 0; }
EOF
	
	close(F) or return;

	my $ret = system("$Config{'cc'}  -c compile.c -o compile$Config{obj_ext}");
	
	foreach my $file (glob('compile*')) {
		unlink($file) || warn "Could not delete $file: $!\n";
	}

	return ($ret == 0);
}
		
package MY;

sub metafile {
	my $self    = shift;
	my $meta    = $self->SUPER::metafile_target(@_); 
	my ($extra) = $self->echo('license: perl', 'META.yml', 1);
	return "$meta\t$extra\n";
}


use Config qw(%Config);
sub postamble {
    my $content;

    $content.='
test_cover : pure_all
	cover -delete
	HARNESS_PERL_SWITCHES=-MDevel::Cover $(MAKE) test
	cover

netdns$(LIB_EXT): netdns$(OBJ_EXT)
	$(AR) '.($^O eq 'MSWin32' && $Config{'cc'} eq 'cl'?'/OUT:':'cr ').
	  'netdns$(LIB_EXT) netdns$(OBJ_EXT)

';
#    print "$content";
    return $content;

}



sub MY::libscan {
    my $path = $_[1];
    return '' if $path =~ /\B\.svn\b/;
    return $path;
}
