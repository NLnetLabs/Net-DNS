package DNSHash::MX;
#
# This module is Copyright (c) 1997 Dave Hayes. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 1, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

=head1 NAME

DNSHash::MX - Put DNS MX queries in a hash lookup format

=head1 SYNOPSIS

require DNSHash;

tie %DNS, "DNSHash::MX", <preload>, <cachedb>, <usettl>

$mxhostname = $DNS{"host.do.main"};

=head1 DESCRIPTION

This implements DNS MX lookups as a tied hash. It takes the first
answer at the lowest priority (like sendmail would to). 

If the file <preload> is defined, the hash is preloaded with the
hostname/mxhostname pairs found in this file. Format is

    mxhostname   hostname

Assignments to this hash are added to the preload lookup. 
You can delete preload lookups by delete()ing the entry.

Lookups are cached once done if <cachedb> is defined.

Cache entries are held for <usettl> seconds unless <usettl> 
undefined, in which case the TTL of the record is used
in each case.

You can clear the cache by removing <cachedb>. If you want
to clear a particular lookup in the cache, use delete().

each() on these hashes only walks the preload.

=cut

BEGIN { @ISA = qw(DNSHash); }

sub doLookup {
    my ($self,$res,$key) = @_;

    my $packet = $res->search("$key","MX");
    if (!defined($packet)) {
	warn "DNS query failed: ", $res->errorstring, "\n";
	return (undef,undef);
    }

    my ($value,$ttl,$minpref); 
    foreach $answer ($packet->answer) {
	my $type = $answer->type;
	if ($type eq "MX") {
	    my $pref = $answer->preference;
	    if (!defined($minpref) || $minpref > $pref) {
		$value = $answer->exchange;
		$ttl = $answer->ttl;
		$minpref = $pref;
	    }
	}
    }
    ($value,$ttl);
}

package DNSHash;

=head1 NAME

DNSHash - Put DNS hostname/ip queries in a hash lookup format

=head1 SYNOPSIS

require DNSHash;

tie %DNS, "DNSHash", <preload>, <cachedb>, <usettl>

$hostname = $DNS{"a.b.c.d"};
$ip = $DNS{"host.do.main"};

$DNS{"host.do.main"} = $realip;

=head1 DESCRIPTION

This implements DNS A and PTR record lookup as a tied hash. 

If the file <preload> is defined, the hash is preloaded with the
hostname/ip pairs found in the file (format is like /etc/hosts).

Assignments to this hash are added to the preload lookup. 
You can delete preload lookups by delete()ing the entry.

Lookups are cached once done if <cachedb> is defined.

Cache entries are held for <usettl> seconds unless <usettl> 
undefined, in which case the TTL of the record is used
in each case.

You can clear the cache by removing <cachedb>. If you want
to clear a particular lookup in the cache, use delete().

each() on these hashes only walks the preload.

=cut
#################
#
#!$Id: DNSHash.pm,v 1.3 1997/08/15 04:26:10 dave Exp dave $
#!$Log: DNSHash.pm,v $
#!Revision 1.3  1997/08/15 04:26:10  dave
#!Fixed bug in Cache loading if cache was not present or you couldn't create the cache file
#!
#!Revision 1.2  1997/07/18 00:49:50  dave
#!Added DNSHash::MX functionality.
#!
#!Revision 1.1  1997/06/24 03:48:23  dave
#!Initial revision
#!
#
################
#
use strict;

use vars       qw($VERSION @ISA $MyQuery);

require Tie::Hash;

BEGIN { @AnyDBM_File::ISA = qw(DB_File GDBM_File NDBM_File SDBM_File); }
require AnyDBM_File;

use Fcntl qw(O_WRONLY O_RDWR O_CREAT O_EXCL);

require Net::DNS;

use Carp;

BEGIN {
    $VERSION = do { my @r = (q$Revision: 1.3 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r }; #
    @ISA         = qw(Tie::Hash);
}

# Constructor
sub TIEHASH {
    my $type = shift;
    my ($preload,$cache,$usettl) = @_;
    my ($cache_hash,$dnshash); 

    if (defined($cache)) {
	$cache_hash = AnyDBM_File->new($cache, O_CREAT|O_RDWR, 0600);
	if (!defined($cache_hash)) {
	    carp "Cannot open DNS cache file '$cache': $!\nDefaulting to in memory cache.\n";
	    $cache_hash = AnyDBM_File->new(undef, O_CREAT|O_RDWR, 0600);
	    croak "Cannot even make an in memory cache, '$!',  dying...\n" if (!defined($cache_hash));
	}
    }

    $dnshash = {
	'preload_file' => $preload,
	'preload' => undef,
	'cache' => $cache,
	'cache_hash' => $cache_hash,
	'usettl' => $usettl,
	'resolver' => Net::DNS::Resolver->new(),
    };

    load_preload($dnshash);
    bless $dnshash, $type;
}

sub load_preload {
    my ($hash) = @_;

    my $preload = $hash->{"preload_file"};
    if (-e "$preload") {
	if (open(PRE,"<$preload")) {
	    my $preload_data = {};
	    while(<PRE>) {
		next if (/^\s*$/ || /^\#/);
		my ($ip,$hostname) = split(/\s+/);
		$preload_data->{"$hostname"} = $ip;
		$preload_data->{"$ip"} = $hostname;
	    }
	    close(PRE);
	    $hash->{"preload"} = $preload_data;
	} else {
	    carp "Cannot open DNS preload file '$preload': $!\n";
	}
    }
    1;
}

sub cache_check {
    my ($hash) = @_;
    my $cache = $hash->{"cache"};
    my $chash = $hash->{"cache_hash"};

    if (! -e "$cache") {
	# Whoops, clear the cache
	$chash->DESTROY;
	$chash = AnyDBM_File->new($cache, O_CREAT|O_RDWR, 0600);
	carp "Cannot open DNS cache file '$cache': $!\n";
	$hash->{"cache_hash"} = $chash;
    } 
    return $chash;
}

# FETCH - Get a single unit of data via key
sub FETCH {
    my ($self,$key) = @_;

#    warn "--\tFETCH\n";
    # Try the preloaded first
    my $preload = $self->{"preload"};
    if (defined($preload)) {
#	warn "--\t Preload\n";
	my $value = $preload->{"$key"};
	return $value if (defined($value));
    }
    
    # Ok, now do a cache lookup
    my $chash = cache_check($self);
    my $lookup = $chash->FETCH($key);
    if (defined($lookup)) {
#	warn "--\t Ow!\n";
	# The Cache Hit. ;-)
	my ($expire,$value) = split(/:/,$lookup);
	return $value if (time < $expire);
    }
    
    # Well, gotta do a DNS lookup.
    # So i can subclass effectively, this is done in another subroutine
#    warn "--\t Lookup!\n";
    my $res = $self->{"resolver"};
    my $usettl = $self->{"usettl"};
    my ($value,$ttl) = $self->doLookup($res,$key);
    $ttl = $usettl if (defined($usettl));

    # Cache value and go
    if (defined($value)) {
	my $expire = $ttl + time;
	$chash->STORE("$key","$expire:$value");
#	warn "--\tStored: $key => $ttl:$value\n";
    }
    return $value;
}

sub doLookup {
    my ($self,$res,$key) = @_;

    my $packet = $res->search("$key");
    if (!defined($packet)) {
	warn "DNS query failed: ", $res->errorstring, "\n";
	return (undef,undef);
    }

    my ($value,$ttl); 
    foreach my $answer ($packet->answer) {
	my $type = $answer->type;
	$ttl = $answer->ttl;
	if ($type eq "A") {
	    $value = $answer->address;
	} elsif ($type eq "PTR") {
	    $value = $answer->ptrdname;
	}
	last if (defined($value));
    }
    ($value,$ttl);
}


# STORE - Store data, in this case in the preload
sub STORE {
    my ($self,$key,$value) = @_;

#    warn "--\tSTORE\n";    
    my $preload = $self->{"preload"};
    if (!defined($preload)) {
	$self->{"preload"} = {};
	$preload = $self->{"preload"};
    }
    $preload->{"$key"} = $value;
    1;
}

# DELETE - Delete data, first from preload, then from cache
sub DELETE {
    my ($self,$key) = @_;

#    warn "--\tDELETE\n";
    my $preload = $self->{"preload"};
    if (defined($preload)) {
#	warn "--\tDeleting preload\n";
	delete($preload->{"$key"});
	return undef;
    }
#    warn "--\tNo preload\n";
    my $chash = cache_check($self);
    $chash->DELETE("$key");
    return undef;
}

# CLEAR - Clears the cache and resets the preload.
sub CLEAR {
    my $self = shift;

#    warn "--\tCLEAR\n";
    my $preload = $self->{"preload"};
    if (defined($preload)) {
	$self->{"preload"} = undef;
	load_preload($self);
    }
    my $chash = cache_check($self);
    $chash->CLEAR();
    1;
}

# EXISTS - Does this key exist?
sub EXISTS {
    my ($self,$key) = @_;

#    warn "--\tEXISTS\n";
    # Try the preloaded first
    my $preload = $self->{"preload"};
    return exists($preload->{"$key"}) if (defined($preload));
    
    # Ok, now do a cache lookup
    my $chash = cache_check($self);
    return $chash->EXISTS($key);
}

# FIRSTKEY - First in iteration.
sub FIRSTKEY {
    my ($self) = @_;

#   warn "--\tFIRSTKEY\n";

    my $preload = $self->{"preload"};

    # Reset the scan
    my $trash = keys %$preload; 

    return each (%{$preload});
}

# NEXTKEY - Next in iteration
sub NEXTKEY {
    my ($self,$key) = @_;
    
#    warn "--\tNEXTKEY\n";
    my $preload = $self->{"preload"};
    return each(%{$preload});
}    

# End of Package
1;


