# $Id: Makefile.PL,v 1.1 2000/12/05 17:43:50 dberk Exp root $

use ExtUtils::MakeMaker;

sub MY::libscan {
	my($self,$path) = @_;
	return '' if $path =~ /RCS/;
	$path;
}

WriteMakefile(
	'NAME'		=> 'Apache::AuthenSecurID',
	'VERSION_FROM'	=> 'AuthenSecurID.pm', 
	'PREREQ_PM'	=> { Authen::ACE => 0.90 },
	'dist'		=> { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
);
