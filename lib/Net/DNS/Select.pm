package Net::DNS::Select;
#
# $Id: Select.pm,v 1.3 2003/06/21 07:47:38 ctriv Exp $
#

use IO::Select;
use Carp;

use strict;
use vars qw($VERSION);

$VERSION = (qw$Revision: 1.3 $)[1];

sub new {
	my ($class, @socks) = @_;

	if ($^O eq 'MSWin32') {
		return bless \@socks, $class;
	} else {
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
