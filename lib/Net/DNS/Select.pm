package Net::DNS::Select;

use Net::DNS;
use IO::Select;
use Carp;

use strict;
use vars qw($VERSION);

# $Id: Select.pm,v 1.1 2002/02/13 04:29:58 ctriv Exp $
$VERSION = $Net::DNS::Version;

sub new {
	my ($class, $os, @socks) = @_;

	if ($os eq "microsoft") {
		return bless \@socks, $class;
	}
	else {
		return IO::Select->new(@socks);
	}
}

sub add {
	my ($self, @handles) = @_;
	push @$self, @handles;
}

sub remove {
	# not implemented
}

sub handles {
	my $self = shift;
	return @$self;
}

sub can_read {
	my $self = shift;
	return @$self;
}

1;
