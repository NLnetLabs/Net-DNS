# $Id$	-*-perl-*-

# Test::More calls functions from Test::Builder. Those functions all eventually
# call Test::Builder::ok (on a builder instance) for reporting the status.
# Here we define a new builder inherited from Test::Builder, with a overloaded
# oks method that always reports the test to have completed successful.
#
# The functions NonFatalBegin and NonFatalEnd re-bless the builder in use by
# Test::More (Test::More->builder) to be of type Test::NonFatal and
# Test::Builder respectively. Tests that are between those functions will thus
# appear to always succeed, however, failure is reported.
#
# Note that the builder is only re-blessed when the file 't/online.nonfatal' 
# exists.
#
# This is just a quick hack to allow for non-fatal unit tests. It has many
# problems such as for example that blocks marked by the NonFatalBegin and
# NonFatalEnd subroutines may not be nested.
#
{
	package Test::NonFatal;

	use base 'Test::Builder';

	sub ok {
		my ($self, $test, $name) = @_;

		$name = "NOT OK, but tolerating failure, $name" unless $test;
		
		$self->SUPER::ok(1, $name);

		return $test ? 1 : 0;
	}
}

use Test::More;

sub NonFatalBegin {
	bless Test::More->builder, Test::NonFatal if -e 't/online.nonfatal';
}

sub NonFatalEnd {
	bless Test::More->builder, Test::Builder  if -e 't/online.nonfatal';
}

1;
