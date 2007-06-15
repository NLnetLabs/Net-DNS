# $Id$   -*-perl-*-
# build DNS packet which has an endless loop in compression
# check it against XS and PP implementation of dn_expand
# both should return (undef,undef) as a sign that the packet
# is invalid

use Test::More tests => 2;
use strict;
use Net::DNS;

# simple query packet
my $pkt = Net::DNS::Packet->new( 'www.example.com','a' )->data;

# replace 'com' with pointer to 'example', thus causing
# endless loop for compressed string:
# www.example.example.example.example...
my $pos = pack( 'C', index( $pkt,"\007example" ));
$pkt =~s{\003com}{\xc0$pos\001x};

# start at 'www'
my $start_offset = index( $pkt,"\003www" );

# fail in case the implementation is buggy and loops forever
$SIG{ ALRM } = sub { BAIL_OUT( "endless loop?" ) };
alarm(15);


my ($name,$offset);
# XS implementation
SKIP: {
     skip("No dn_expand_xs available",1) if ! $Net::DNS::HAVE_XS; 
     my ($name,$offset) = Net::DNS::Packet::dn_expand( \$pkt,$start_offset );
     ok( !defined($name) && !defined($offset), 'XS detected invalid packet' );
 }
$Net::DNS::HAVE_XS = 0;
undef $name; undef $offset;
($name,$offset) = Net::DNS::Packet::dn_expand( \$pkt,$start_offset );
ok( !defined($name) && !defined($offset), 'PP detected invalid packet' );
