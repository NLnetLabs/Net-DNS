# $Id$	-*-perl-*-

use strict;
use Test::More tests => 1;


local @INC = grep $_ !~ m/blib/i, @INC;

my $version = eval "use Net::DNS; &Net::DNS::version";


ok( !$version || ( $version > 1.00 ), 'compatible' ) || diag join "\n", <<"END", @INC;
#
#	The installation path for this version of Net::DNS differs
#	from the existing version $version found in your perl library.
#
#	Please be aware that this upgrade may appear to fail because
#	version $version will usually occur earlier in the search path.
#	In most cases, deleting the old version resolves the problem.
#
END


exit;

