# $Id: Makefile.PL,v 1.14 2002/11/15 10:43:08 ctriv Exp $

use ExtUtils::MakeMaker qw(WriteMakefile prompt);

warn <<AMEN if $] < 5.005;

This verion of Net::DNS has not been tested against perl v$]
The author is confident that this package will function 
properly with older perls such as yours, but bugs may lurk. 


AMEN

# Check if we have internet connection
# (I lifted this code from LWP... many thanks for this and more!)
require IO::Socket;
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


WriteMakefile(
	'NAME'			=> 'Net::DNS',
	'VERSION_FROM'	=> 'lib/Net/DNS.pm',
	'PREREQ_PM'		=> {
		Test::More       => 0.18,
		IO::Socket		 => 0,
		MIME::Base64	 => 2.11,
		Digest::MD5		 => 2.12,
		Digest::HMAC_MD5 => 1.00,
	},
	'clean'			=> { FILES => 't/online.enabled' },

   ($] >= 5.005 ?    
	('AUTHOR'		=> 'Chris Reinhardt <ctriv@net-dns.org>',
	'ABSTRACT'		=> 'Perl DNS resolver module', ) : ()),
);

package MY;

sub processPL {
  my $self = shift;
  my $block = $self->SUPER::processPL(@_);
  # "Version:" in spec needs to match
  # "$VERSION" from VERSION_FROM
  $block =~ s%(spec.PL\s*)$%$1 \$\(VERSION_FROM\)%m;
  $block;
}
