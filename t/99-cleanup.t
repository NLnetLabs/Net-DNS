#!/usr/bin/perl
# $Id$ -*-perl-*-
#

use strict;
use warnings;

use Test::More;
plan tests => 1;

diag("Cleaning");

unlink("t/online.disabled") if ( -e "t/online.disabled" );
unlink("t/IPv6.disabled")   if ( -e "t/IPv6.disabled" );

ok( 1, "Dummy" );


# survey platform-specific cpp behaviour
exit if $^O =~ /linux/i;
use Config;

diag( "$_: \t$Config{$_}" ) for (qw(osname osvers cpprun cpplast cppstdin cppminus cppflags echo perl));

my $file = 'stdio.h';
my @echo = `$Config{echo} "#include <$file>"`;
diag scalar(@echo);
diag "@echo\n";

my $echo = qq[perl -e 'print "\@ARGV\n"'];
@echo = `$echo "#include <$file>"`;
diag scalar(@echo);
diag "@echo\n";

exit unless scalar(@echo);

my $cpp = qq[$Config{cppstdin} $Config{cppminus} -o -];
my ($ok) = grep {/$file/} `$echo "#include <$file>" | $cpp`;
diag $ok, "\n";

diag `$echo "#include <bogus.h>" | $cpp`;

exit;
