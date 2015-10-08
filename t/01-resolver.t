# $Id$	-*-perl-*-

use strict;
use Test::More tests => 4;

use Net::DNS;

my $resolver = Net::DNS::Resolver->new( prefer_v4 => 1 );

for (@Net::DNS::Resolver::ISA) {
	diag $_ unless /[:]UNIX$/;
}

ok( $resolver->isa('Net::DNS::Resolver'), 'new() created object' );

ok( $resolver->print, '$resolver->print' );

{
	my $warning;
	local $SIG{__WARN__} = sub { $warning = shift; chomp $warning };

	$resolver->make_query_packet('example.com');
	ok( $warning, "warning:\t[$warning]" );
}

ok( !$resolver->DESTROY, '$resolver->DESTROY' );


exit;

__END__

