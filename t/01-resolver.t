# $Id$	-*-perl-*-

use strict;
use Test::More tests => 14;

use Net::DNS;

my $resolver = Net::DNS::Resolver->new( prefer_v4 => 1 );
my $class = ref($resolver);

for (@Net::DNS::Resolver::ISA) {
	diag $_ unless /[:]UNIX$/;
}

ok( $resolver->isa('Net::DNS::Resolver'), 'new() created object' );

ok( $resolver->print, '$resolver->print' );

ok( $class->new( debug => 1 )->_diag(@Net::DNS::Resolver::ISA), 'debug message' );

{					## check class methods
	my $value = '1.2.3.4';
	$class->srcaddr($value);
	is( $class->new->srcaddr(), $value, 'class method changes defaults' );
	ok( $class->domain('example.com'),     'class->domain' );
	ok( $class->searchlist('example.com'), 'class->searchlist' );
	$class->nameservers(qw(127.0.0.1 ::1));
	ok( $class->nameserver(), 'class->nameserver' );
	ok( $class->string(),	  'class->string' );
}


{					## check instance methods
	ok( $resolver->domain('example.com'),	  'resolver->domain' );
	ok( $resolver->searchlist('example.com'), 'resolver->searchlist' );
	$resolver->nameservers(qw(127.0.0.1 ::1 ::1.2.3.4));
	ok( $resolver->nameservers(), 'resolver->nameservers' );
}


{					## check for exception on bogus AUTOLOAD method
	eval { $resolver->bogus(); };
	my $exception = $1 if $@ =~ /^(.+)\n/;
	ok( $exception ||= '', "unknown method:\t[$exception]" );

	is( $resolver->DESTROY, undef, 'DESTROY() exists to defeat pre-5.18 AUTOLOAD' );
}


{					## check that warning raised for make_query_packet()
	my $warnings;
	local $SIG{__WARN__} = sub { $warnings++ };

	$resolver->make_query_packet('example.com');
	$resolver->make_query_packet('example.com');
	is( $warnings, 1, 'deprecation warning not repeated' );
}


exit;

__END__

