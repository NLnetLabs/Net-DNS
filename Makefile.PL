# $Id: Makefile.PL,v 1.7 2002/05/15 00:10:18 ctriv Exp $

eval { require 5.6.0; };

die <<SHUCKS if $@;
Net::DNS requires perl 5.6.0 or greater.  
The latest version of perl can always be found at:
			   
		 http://www.cpan.org/src/latest.tar.gz
SHUCKS

use ExtUtils::MakeMaker;


WriteMakefile(
	'NAME'			=> 'Net::DNS',
	'VERSION_FROM'	=> 'lib/Net/DNS.pm',
	'PREREQ_PM'		=> {
		Test::More		 => 0.18,
		IO::Socket		 => 1.15,
		MIME::Base64	 => 2.11,
		Digest::MD5		 => 2.12,
		Digest::HMAC_MD5 => 1.00,
	},
	'AUTHOR'		=> 'Chris Reinhardt <ctriv@net-dns.org>',
	'ABSTRACT'		=> 'Perl DNS resolver module',
);


