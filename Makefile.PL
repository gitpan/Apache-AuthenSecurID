# $Id: Makefile.PL,v 1.1 2001/01/18 20:50:27 root Exp $

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
