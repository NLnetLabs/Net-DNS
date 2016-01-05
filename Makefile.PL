#
# $Id$	-*-perl-*-
#


BEGIN {
	die <<RIP if $] < 5.004_04;

This version of Net::DNS will not function correctly with perl $]

RIP

	warn <<AMEN if $] < 5.006;

This version of Net::DNS has not been tested against perl $]
because Test::More requires version 5.6 or later.

The author is confident that this package will function 
properly with older perls such as yours, but bugs may lurk. 

AMEN

	warn <<AMEN unless eval "use Net::DNS 1.00";

##
##	The installation path for this version of Net::DNS differs
##	from the existing version found in your perl library.
##	Please remove the old version.
##

AMEN

	sleep(5);
}


use ExtUtils::MakeMaker;
use Getopt::Long;
use IO::Socket;


# See perldoc ExtUtils::MakeMaker for details of how to influence
# the contents of the Makefile that is written.

my %metadata = (
	NAME		 => 'Net::DNS',
	VERSION_FROM	 => 'lib/Net/DNS.pm',
	ABSTRACT_FROM	 => 'lib/Net/DNS.pm',
	AUTHOR		 => 'Olaf Kolkman <olaf@net-dns.org>',
	LICENSE		 => 'mit',
	MIN_PERL_VERSION => 5.004_04,
	);


my %prerequisite = (
	Digest::HMAC => 1.03,
	Digest::MD5  => 2.13,
	Digest::SHA  => 5.23,
	File::Spec   => 0.86,
	IO::Socket   => 1.16,
	MIME::Base64 => 2.11,
	Time::Local  => 1.19,
	Test::More   => 0.52,
	);


my %optional = (
	Net::DNS::SEC	     => 1.01,
	Digest::BubbleBabble => 0.01,
	Digest::GOST	     => 0.06,
	IO::Socket::INET     => 1.25,
	IO::Socket::INET6    => 2.01,
	IO::Socket::IP	     => 0.29,
	Net::LibIDN	     => 0.12,
	);


my %platform = (
	MSWin32 => {
		Win32::IPHelper	   => 0.07,
		Win32::API	   => 0.55,
		Win32::TieRegistry => 0.24,
		} );


my @debris = qw(
		t/IPv6.enabled
		t/online.enabled t/online.nonfatal
		zone[0-9].txt zone[0-9][0-9].txt
		);


sub DEBUG { 0; }


# clean up existing makefile
unlink('Makefile');

# clean up the online testing flag file.
unlink("t/online.enabled");
unlink("t/online.disabled");

# clean up the IPv6 testing flag file.
unlink("t/IPv6.enabled");
unlink("t/IPv6.disabled");


#
# Get the command line args
#

my $help = 0;
my $IPv6_tests;
my $online_tests = 2;			##  2 = non-fatal, 1 = on, 0 = off  ##

my @options = (
	'online-tests!'		 => \$online_tests,
	'non-fatal-online-tests' => sub { $online_tests = 2; },
	'IPv6-tests!'		 => \$IPv6_tests,
	'help!'			 => \$help
	);


unless ( GetOptions(@options) ) {
	print "Error: Unrecognized option.\n";
	print "Try perl Makefile.PL --help for more information\n";
	exit 1;
}


if ($help) {
	print <<EOT;

Usage: perl Makefile.PL [OPTION...]

Prepare Makefile for building and installing Net::DNS

  --online-tests		Perform tests by communicating with the
				outside world.	Beware that their success is
				also dependent on outside influences.

  --noonline-tests		Skip online tests completely.

  --IPv6-tests			Perform IPv6 specific online tests. Default is
				the same as regular online tests.

  --noIPv6-tests		Skip IPv6 specific online test

  --non-fatal-online-tests	Perform online test, but do not let failures 
				negatively affect the outcome of running
				make test.  This is the default.

EOT
	exit 0;
}


for my $module ( keys %optional ) {	## check optional module availability
	delete $optional{$module} unless eval "require $module";
}

my $platform = $platform{$^O} || {};	## platform-specific dependencies


WriteMakefile(				## version check & end-user metadata
	NO_META	  => 1,
	PREREQ_PM => {%prerequisite, %optional, %$platform},
	%metadata
	);


local $SIG{__WARN__} = sub { };		## suppress repeated warnings

WriteMakefile(				## Makefile & distribution metadata
	NO_MYMETA => 1,
	PREREQ_PM => {%prerequisite},
	clean	  => {FILES => "@debris"},
	%metadata
	);


#
# Check if we have internet connection	(code lifted from LWP)
#
if ($online_tests) {
	my $socket = IO::Socket::INET->new(
		PeerAddr => "www.google.com:80",
		Timeout	 => 10
		);

	if ($socket) {
		close($socket);
	} else {
		$online_tests = 0;
		print <<EOT;

You appear not to be directly connected to the Internet.
Disabling online tests altogether...

EOT
	}
}


if ($online_tests) {
	my $enable = 't/online.enabled';
	open( ENABLED, ">$enable" ) || die "Can't touch $enable $!";
	close(ENABLED) || die "Can't touch $enable $!";

	if ( $online_tests == 2 ) {
		my $nonfatal = 't/online.nonfatal';
		open( NONFATAL, ">$nonfatal" ) || die "Can't touch $nonfatal $!";
		close(NONFATAL) || die "Can't touch $nonfatal $!";
		print "\nActivating Non Fatal Online Tests...\n";
	} else {
		print "\nActivating Online Tests...\n";
	}

	$IPv6_tests = 1 unless defined $IPv6_tests;
	if ( $optional{IO::Socket::IP} || $optional{IO::Socket::INET6} ) {
		if ($IPv6_tests) {
			my $enable = 't/IPv6.enabled';
			print "\nActivating IPv6 Tests...\n";
			open( ENABLED, ">$enable" ) || die "Can't touch $enable $!";
			close(ENABLED) || die "Can't touch $enable $!";
		}
	}

	print <<EOT;

Warning!
========
Online tests depend on conditions beyond the control of Net::DNS. The tests 
check for the expected results when both Net::DNS and the outside world are
functioning properly. In case of failure it is often undecidable if the error
lies within Net::DNS or elsewhere.

EOT
}


sub MY::postamble {

	return <<'END';
test_cover : pure_all
	cover -delete
	HARNESS_PERL_SWITCHES=-MDevel::Cover $(MAKE) test
	cover -summary
END

}


sub MY::libscan {
	my $path = $_[1];
	return '' if $path =~ /\B\.svn\b/;
	return $path;
}


__END__

