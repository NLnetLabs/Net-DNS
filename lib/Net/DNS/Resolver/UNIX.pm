package Net::DNS::Resolver::UNIX;
#
# $Id: UNIX.pm,v 1.1 2003/06/11 09:56:13 ctriv Exp $
#

use strict;
use vars qw(@ISA);

use Net::DNS::Resolver::Base ();

@ISA = qw(Net::DNS::Resolver::Base);

my $resolv_conf = '/etc/resolv.conf';
my $dotfile     = '.resolv.conf';

my @config_path;
push(@config_path, $ENV{'HOME'}) if exists $ENV{'HOME'};
push(@config_path, '.');

sub init {
	my ($class) = @_;
	
	$class->read_config_file($resolv_conf) if -f $resolv_conf && -r $resolv_conf; 
	
	foreach my $dir (@config_path) {
		my $file = "$dir/$dotfile";
		$class->read_config_file($file) if -f $file && -r $file && -o $file;
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