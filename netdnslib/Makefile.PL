use ExtUtils::MakeMaker qw(WriteMakefile prompt);

use ExtUtils::MakeMaker;

$Verbose=1;
WriteMakefile(
    NAME => 'Net::DNS::netdns',
    clean => {'FILES' => 'netdns$(LIB_EXT)'},
);



sub MY::top_targets {
		'
all :: static

	
pure_all :: static

static ::       netdns$(LIB_EXT)


netdns$(LIB_EXT): $(O_FILES)
	$(AR) cr netdns$(LIB_EXT) $(O_FILES)
	$(RANLIB) netdns$(LIB_EXT)
';
	}





sub MY::metafile {
	my $self    = shift;
	my ($extra) = $self->echo('license: perl', 'META.yml', 1);
	
	return "$extra\n";
}
