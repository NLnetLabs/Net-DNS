# $Id: Makefile.PL,v 1.21 2003/05/28 22:15:58 ctriv Exp $

use ExtUtils::MakeMaker qw(WriteMakefile prompt);
use IO::Socket ();
use Config qw(%Config);

# An existing makefile can confuse the CC test.
unlink('Makefile');

warn <<AMEN if $] < 5.005;

This verion of Net::DNS has not been tested against perl v$]
The author is confident that this package will function 
properly with older perls such as yours, but bugs may lurk. 


AMEN

#
# Get our makefile started...
#
my %Makefile = (
	NAME          => 'Net::DNS',
	VERSION_FROM  => 'lib/Net/DNS.pm',
	PREREQ_PM     => {
		Test::More       => 0.18,
		IO::Socket		 => 0,
		MIME::Base64	 => 2.11,
		Digest::MD5		 => 2.12,
		Digest::HMAC_MD5 => 1.00,
	},
	XS            => {},
	C             => [],
	clean         => { FILES => 't/online.enabled test.* DNS.o DNS.c DNS.bs' },
);

if ($^O eq 'Win32') {
	$Makefile{'PREREQ_PM'}->{'Win32::Registry'} = 0;
}

if ($] >= 5.005) {
	$Makefile{'AUTHOR'}   = 'Chris Reinhardt <ctriv@net-dns.org>';
	$Makefile{'ABSTRACT'} = 'Perl DNS resolver module';
}

#
# Check if we have a C compiler

my $use_xs;
for (@ARGV) {
	/^--pm/ and $use_xs = 0;
	/^--xs/ and $use_xs = 1;
}

unless (defined $use_xs) {
	if (test_cc()) {
		print "You have a working compiler.\n";
		$use_xs = 1;
	} else {
		$use_xs = 0;
		print <<END;
	
I cannot determine if you have a C compiler. I will install a 
perl-only implementation.
	
You can force installation of the XS version with:

	perl Makefile.PL --xs
END
	}
}

if ($use_xs) {
	# turn the XS bits on.
	delete $Makefile{'XS'};
	delete $Makefile{'C'};
	$Makefile{'LIBS'} = ['-lresolv'];
}


#
# Check if we have internet connection
# (I lifted this code from LWP... )
#
my $s = IO::Socket::INET->new(
	PeerAddr => "www.google.com:80",
	Timeout  => 10,
);

if ($s) {
	close($s);

	print <<EOT;

You appear to be directly connected to the Internet.  I have some tests
that try to query live nameservers.

EOT

	if (prompt("Do you want to enable these tests?", "y") =~ /^y/i) {
		open(ENABLED, ">t/online.enabled") || die "Can't touch ./t/online.enabled $!";
		close(ENABLED);
	} else {
		unlink("t/online.enabled"); # just to be shure...
	}
}


WriteMakefile(%Makefile);

sub test_cc {
	#
	# The perl/C checking voodoo is stolen from Graham Barr's
	# Scalar-List-Utils distribution.
	#
	print "Testing if you have a C compiler and the needed header files....\n";

	unless (open(F, ">test.c")) {
	    warn "Cannot write test.c, skipping test compilation and installing pure Perl version.\n";
		return;
	}

	print F <<'EOF';
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h> 

int main() { return 0; }
EOF
	
	close(F) or return;

	my $ret = system("$Config{'make'} test$Config{obj_ext}");
	
	foreach my $file (glob('test*')) {
		unlink($file) || warn "Could not delete $file: $!\n";
	}

	return 1;
}
		

