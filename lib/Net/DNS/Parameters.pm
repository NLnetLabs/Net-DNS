package Net::DNS::Parameters;

#
# $Id$
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision$)[1];

use strict;
use integer;
use Carp;

########
#
#	Domain Name System (DNS) Parameters
#
#	(last updated 2012-11-12)
#


# Registry Name: DNS CLASSes
use vars qw( %classbyname %classbyval );
%classbyname = (
        IN   => 1,                                              # [RFC1035]
        CH   => 3,                                              # [Moon1981]
        HS   => 4,                                              # [Dyer1987]
        NONE => 254,                                            # [RFC2136]
        ANY  => 255,                                            # [RFC1035]
        );
%classbyval = reverse %classbyname;


# Registry Name: Resource Record (RR) TYPEs
use vars qw( %typebyname %typebyval );
%typebyname = (
        A          => 1,                                        # [RFC1035]
        NS         => 2,                                        # [RFC1035]
        MD         => 3,                                        # [RFC1035]
        MF         => 4,                                        # [RFC1035]
        CNAME      => 5,                                        # [RFC1035]
        SOA        => 6,                                        # [RFC1035]
        MB         => 7,                                        # [RFC1035]
        MG         => 8,                                        # [RFC1035]
        MR         => 9,                                        # [RFC1035]
        NULL       => 10,                                       # [RFC1035]
        WKS        => 11,                                       # [RFC1035]
        PTR        => 12,                                       # [RFC1035]
        HINFO      => 13,                                       # [RFC1035]
        MINFO      => 14,                                       # [RFC1035]
        MX         => 15,                                       # [RFC1035]
        TXT        => 16,                                       # [RFC1035]
        RP         => 17,                                       # [RFC1183]
        AFSDB      => 18,                                       # [RFC1183][RFC5864]
        X25        => 19,                                       # [RFC1183]
        ISDN       => 20,                                       # [RFC1183]
        RT         => 21,                                       # [RFC1183]
        NSAP       => 22,                                       # [RFC1706]
        'NSAP-PTR' => 23,                                       # [RFC1348][RFC1637][RFC1706]
        SIG        => 24,                                       # [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]
        KEY        => 25,                                       # [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]
        PX         => 26,                                       # [RFC2163]
        GPOS       => 27,                                       # [RFC1712]
        AAAA       => 28,                                       # [RFC3596]
        LOC        => 29,                                       # [RFC1876]
        NXT        => 30,                                       # [RFC3755][RFC2535]
        EID        => 31,                                       # [Patton][Patton1995]
        NIMLOC     => 32,                                       # [Patton][Patton1995]
        SRV        => 33,                                       # [RFC2782]
        ATMA       => 34,                                       # [ATMDOC]
        NAPTR      => 35,                                       # [RFC2915][RFC2168][RFC3403]
        KX         => 36,                                       # [RFC2230]
        CERT       => 37,                                       # [RFC4398]
        A6         => 38,                                       # [RFC3226][RFC2874][RFC6563]
        DNAME      => 39,                                       # [RFC6672]
        SINK       => 40,                                       # [Eastlake][Eastlake2002]
        OPT        => 41,                                       # [RFC2671][RFC3225]
        APL        => 42,                                       # [RFC3123]
        DS         => 43,                                       # [RFC4034][RFC3658]
        SSHFP      => 44,                                       # [RFC4255]
        IPSECKEY   => 45,                                       # [RFC4025]
        RRSIG      => 46,                                       # [RFC4034][RFC3755]
        NSEC       => 47,                                       # [RFC4034][RFC3755]
        DNSKEY     => 48,                                       # [RFC4034][RFC3755]
        DHCID      => 49,                                       # [RFC4701]
        NSEC3      => 50,                                       # [RFC5155]
        NSEC3PARAM => 51,                                       # [RFC5155]
        TLSA       => 52,                                       # [RFC6698]
        HIP        => 55,                                       # [RFC5205]
        NINFO      => 56,                                       # [Reid]
        RKEY       => 57,                                       # [Reid]
        TALINK     => 58,                                       # [Wijngaards]
        CDS        => 59,                                       # [Barwood]
        SPF        => 99,                                       # [RFC4408]
        NID        => 104,                                      # [RFC6742]
        L32        => 105,                                      # [RFC6742]
        L64        => 106,                                      # [RFC6742]
        LP         => 107,                                      # [RFC6742]
        TKEY       => 249,                                      # [RFC2930]
        TSIG       => 250,                                      # [RFC2845]
        IXFR       => 251,                                      # [RFC1995]
        AXFR       => 252,                                      # [RFC1035][RFC5936]
        MAILB      => 253,                                      # [RFC1035]
        MAILA      => 254,                                      # [RFC1035]
        '*'        => 255,                                      # [RFC1035]
        ANY        => 255,                                      # [RFC1035]
        URI        => 256,                                      # [Faltstrom]
        CAA        => 257,                                      # [Hallam-Baker]
        TA         => 32768,                                    # [Weiler]           2005-12-13
        DLV        => 32769,                                    # [RFC4431]
        );
%typebyval = reverse( ANY => 255, %typebyname );


# Registry Name: DNS OpCodes
use vars qw( %opcodebyname %opcodebyval );
%opcodebyname = (
        QUERY  => 0,                                            # [RFC1035]
        IQUERY => 1,                                            # [RFC3425]
        STATUS => 2,                                            # [RFC1035]
        NOTIFY => 4,                                            # [RFC1996]
        UPDATE => 5,                                            # [RFC2136]
        );
%opcodebyval = reverse %opcodebyname;


# Registry Name: DNS RCODEs
use vars qw( %rcodebyname %rcodebyval );
%rcodebyname = (
        NOERROR  => 0,                                          # [RFC1035]
        FORMERR  => 1,                                          # [RFC1035]
        SERVFAIL => 2,                                          # [RFC1035]
        NXDOMAIN => 3,                                          # [RFC1035]
        NOTIMP   => 4,                                          # [RFC1035]
        REFUSED  => 5,                                          # [RFC1035]
        YXDOMAIN => 6,                                          # [RFC2136]
        YXRRSET  => 7,                                          # [RFC2136]
        NXRRSET  => 8,                                          # [RFC2136]
        NOTAUTH  => 9,                                          # [RFC2136]
        NOTZONE  => 10,                                         # [RFC2136]
        BADVERS  => 16,                                         # [RFC2671]
        BADSIG   => 16,                                         # [RFC2845]
        BADKEY   => 17,                                         # [RFC2845]
        BADTIME  => 18,                                         # [RFC2845]
        BADMODE  => 19,                                         # [RFC2930]
        BADNAME  => 20,                                         # [RFC2930]
        BADALG   => 21,                                         # [RFC2930]
        BADTRUNC => 22,                                         # [RFC4635]
        );
%rcodebyval = reverse( BADSIG => 16, %rcodebyname );


# Registry Name: DNS EDNS0 Options
use vars qw( %ednsoptionbyname %ednsoptionbyval );
%ednsoptionbyname = (
        LLQ  => 1,                                              # [http://files.dns-sd.org/draft-sekar-dns-llq.txt]
        UL   => 2,                                              # [http://files.dns-sd.org/draft-sekar-dns-ul.txt]
        NSID => 3,                                              # [RFC5001]
        );
%ednsoptionbyval = reverse %ednsoptionbyname;


# Registry Name: DNS Header Flags
use vars qw( %dnsflagbyname );
%dnsflagbyname = (
        AA => 0x0400,                                           # [RFC1035]
        TC => 0x0200,                                           # [RFC1035]
        RD => 0x0100,                                           # [RFC1035]
        RA => 0x0080,                                           # [RFC1035]
        AD => 0x0020,                                           # [RFC4035]
        CD => 0x0010,                                           # [RFC4035]
        );


# Registry Name: EDNS Header Flags (16 bits)
use vars qw( %ednsflagbyname );
%ednsflagbyname = (
        DO => 0x8000,                                           # [RFC4035][RFC3225]
        );


########


use Exporter 'import';
use vars qw(@EXPORT);
@EXPORT = qw(
                classbyname classbyval %classbyname
                typebyname typebyval %typebyname
                opcodebyname opcodebyval
                rcodebyname rcodebyval
                ednsoptionbyname ednsoptionbyval
                );


# The following functions are wrappers around similarly named hashes.

sub classbyname {
        my $name = uc shift;

        return $classbyname{$name} if defined $classbyname{$name};

        confess "unknown class $name" unless $name =~ m/CLASS(\d+)/;

        my $val = 0 + $1;
        return $val unless $val > 0xffff;

        confess "classbyname( $name ) out of range";
}

sub classbyval {
        my $val = shift;

        return $classbyval{$val} if defined $classbyval{$val};

        $val += 0;
        confess "classbyval( $val ) out of range" if $val > 0xffff;

        return "CLASS$val";
}


sub typebyname {
        my $name = uc shift;

        return $typebyname{$name} if defined $typebyname{$name};

        confess "unknown type $name" unless $name =~ m/TYPE(\d+)/;

        my $val = 0 + $1;
        confess "typebyname( $name ) out of range" if $val > 0xffff;

        return $val ? $val : '00'; ## preserve historical behaviour for TYPE0 [OMK] ##
}

sub typebyval {
        my $val = shift;

        return $typebyval{$val} if defined $typebyval{$val};

        $val += 0;
        confess "typebyval( $val ) out of range" if $val > 0xffff;

        return "TYPE$val";
}


sub opcodebyname {
        my $name = uc shift;
        return $opcodebyname{$name} if defined $opcodebyname{$name};
        confess "unknown opcode $name";
}

sub opcodebyval {
        my $arg = shift;
        return $opcodebyval{$arg} || 0 + $arg;
}


sub rcodebyname {
        my $arg = uc shift;
        return $rcodebyname{$arg} if defined $rcodebyname{$arg};
        return 0 + $arg if $arg =~ /^\d/;
        confess "unknown rcode $arg";
}

sub rcodebyval {
        my $arg = shift;
        return $rcodebyval{$arg} || 0 + $arg;
}


sub ednsoptionbyname {
        my $arg = uc shift;
        return $ednsoptionbyname{$arg} if defined $ednsoptionbyname{$arg};
        return 0 + $arg if $arg =~ /^\d/;
        confess "unknown option $arg";
}

sub ednsoptionbyval {
        my $arg = shift;
        return $ednsoptionbyval{$arg} || 0 + $arg;
}


1;
__END__



=head1 NAME

    Net::DNS::Parameters - DNS parameter assignments


=head1 SYNOPSIS

    use Net::DNS::Parameters;


=head1 DESCRIPTION

Net::DNS::Parameters is a Perl package representing the DNS parameter
allocation (key,value) tables as recorded in the definitive registry
file maintained and published by IANA.


=head1 COPYRIGHT

Copyright (c)1997-2002 Michael Fuhr. 

Portions Copyright (c)2002-2004 Chris Reinhardt.

Portions Copyright (c)2012 Dick Franks

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.


=head1 SEE ALSO
 
L<perl>, L<Net::DNS>, L<IANA dns-parameters|www.ietf.org/assignments/dns-parameters>

