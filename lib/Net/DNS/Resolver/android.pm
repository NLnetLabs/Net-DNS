package Net::DNS::Resolver::android;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];


=head1 NAME

Net::DNS::Resolver::android - Android Resolver Class

=cut


use strict;
use base qw(Net::DNS::Resolver::Base);


my $origin	= $ENV{ANDROID_ROOT} || '/system';
my $resolv_conf = "$origin/etc/resolv.conf";
my $dotfile	= '.resolv.conf';

my @config_path;
push( @config_path, $ENV{HOME} ) if exists $ENV{HOME};
push( @config_path, '.' );


sub _untaint { map defined && /^(.+)$/ ? $1 : (), @_; }


sub init {
	my @nameservers;
	for ( 1 .. 4 ) {
		my $ret = `getprop net.dns$_` || next;
		chomp $ret;
		push @nameservers, $ret || next;
	}

	my $defaults = shift->defaults;

	$defaults->read_config_file($resolv_conf) if -f $resolv_conf && -r _;

	$defaults->domain( _untaint $defaults->domain );	# untaint config values
	$defaults->searchlist( _untaint $defaults->searchlist );
	$defaults->nameservers( _untaint @nameservers, $defaults->nameservers );

	foreach my $dir (@config_path) {
		my $file = "$dir/$dotfile";
		$defaults->read_config_file($file) if -f $file && -r _ && -o _;
	}

	$defaults->read_env;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS::Resolver;

=head1 DESCRIPTION

This class implements the OS specific portions of C<Net::DNS::Resolver>.

No user serviceable parts inside, see L<Net::DNS::Resolver|Net::DNS::Resolver>
for all your resolving needs.

=head1 COPYRIGHT

Copyright (c)2014 Dick Franks.

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::Resolver>

=cut
