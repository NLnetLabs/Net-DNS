package Net::DNS::Resolver::UNIX;
#
# $Id: UNIX.pm,v 1.2 2003/08/26 23:58:10 ctriv Exp $
#

use strict;
use vars qw(@ISA $VERSION);

use Net::DNS::Resolver::Base ();

@ISA     = qw(Net::DNS::Resolver::Base);
$VERSION = (qw$Revision: 1.2 $)[1];

my $resolv_conf = '/etc/resolv.conf';
my $dotfile     = '.resolv.conf';

my @config_path;
push(@config_path, $ENV{'HOME'}) if exists $ENV{'HOME'};
push(@config_path, '.');

sub init {
	my ($class) = @_;
	
	$class->read_config_file($resolv_conf) if -f $resolv_conf && -r _; 
	
	foreach my $dir (@config_path) {
		my $file = "$dir/$dotfile";
		$class->read_config_file($file) if -f $file && -r _ && -o _;
	}
	
	$class->read_env;
	
	my $defaults = $class->defaults;
	
	if (!$defaults->{'domain'} && @{$defaults->{'searchlist'}}) {
		$defaults->{'domain'} = $defaults->{'searchlist'}[0];
	} elsif (!@{$defaults->{'searchlist'}} && $defaults->{'domain'}) {
		$defaults->{'searchlist'} = [ $defaults->{'domain'} ];
	}
}
	
1;
__END__