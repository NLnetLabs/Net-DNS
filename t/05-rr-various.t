# $Id$   -*-perl-*-
# Contains a number of additional test for RR related functionality


use Test::More;
use strict;
use Net::DNS;
use vars qw( $HAS_DNSSEC $HAS_DLV $HAS_NSEC3 $HAS_NSEC3PARAM);


plan tests => 2;


is ( Net::DNS::stripdot ('foo\\\\\..'),'foo\\\\\.', "Stripdot does its magic in precense of escapes test 1");
is ( Net::DNS::stripdot ('foo\\\\\.'),'foo\\\\\.', "Stripdot does its magic in precense of escapes test 2");





#--------------
#
# Some test that test on appropriate normalization of internal storage
# when using new_from_hash



