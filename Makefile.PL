# $Id: Makefile.PL,v 1.10 2002/06/03 21:12:22 ctriv Exp $

use ExtUtils::MakeMaker;

warn <<AMEN if $] < 5.005;

This verion of Net::DNS has not been tested against perl v$]
The author is confident that this package will function 
properly with older perls such as yours, but bugs may lurk. 


AMEN

WriteMakefile(
	'NAME'			=> 'Net::DNS',
	'VERSION_FROM'	=> 'lib/Net/DNS.pm',
	'PREREQ_PM'		=> {
		Test::More		 => 0.18,
		IO::Socket		 => 0,
		MIME::Base64	 => 2.11,
		Digest::MD5		 => 2.12,
		Digest::HMAC_MD5 => 1.00,
	},
	
   ($] >= 5.005 ?    
	('AUTHOR'		=> 'Chris Reinhardt <ctriv@net-dns.org>',
	'ABSTRACT'		=> 'Perl DNS resolver module', ) : ()),
);


