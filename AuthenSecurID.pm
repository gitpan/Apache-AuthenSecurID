# $Id: AuthenSecurID.pm,v 1.1 2000/12/05 17:43:50 dberk Exp root $

package Apache::AuthenSecurID;

use strict;
use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use Authen::ACE;
use vars qw($VERSION);

$VERSION = '0.1';

sub handler {
	my $r = shift;
	
	# Continue only if the first request.
	return OK unless $r->is_initial_req;

	my $reqs_arr = $r->requires;
	return OK unless $reqs_arr;

	# Grab the password, or return if HTTP_UNAUTHORIZED
	my($res,$pass) = $r->get_basic_auth_pw;
	return $res if $res;

	# Get the user name.
	my $user = $r->connection->user;

	# SecurID Config Directory 
	my $VAR_ACE    = $r->dir_config("Auth_SecurID_VAR_ACE") || "/var/ace";

	# Sanity for usernames 
	if (length $user > 64 or $user =~ /[^A-Za-z0-9]/) {
		$r->log_reason("Apache::AuthenSecurID username too long or"
			."contains illegal characters", $r->uri);
		$r->note_basic_auth_failure;
		return AUTH_REQUIRED;
	}

	if ( ! $pass ) {
		$r->log_reason("Apache::AuthenSecurID passcode empty",$r->uri);
		$r->note_basic_auth_failure;
		return AUTH_REQUIRED;
	}

	if (length $pass > 256) {
		$r->log_reason("Apache::AuthenSecurID password too long",$r->uri);
		$r->note_basic_auth_failure;
		return AUTH_REQUIRED;
	}

	# Create the radius connection.
	my $ace = Authen::ACE->new(
		config => $VAR_ACE 
	);

	# Error if we can't connect.
	if (!defined $ace) {
		$r->log_reason("Apache::AuthenSecurID failed to"
			."init",$r->uri);
		return SERVER_ERROR;
	}
	
	# Do the actual check.
	my ( $result, $info ) = $ace->Check ( $pass, $user );
	if ($result == ACM_OK) {
		return OK;
	} else {
		$r->log_reason("Apache::AuthenSecurID failed for user $user",
			$r->uri);
		$r->note_basic_auth_failure;
		return AUTH_REQUIRED;
	}
}

1;

__END__

=head1 NAME

Apache::AuthenSecurID - Authentication via a SecurID server

=head1 SYNOPSIS

 # Configuration in httpd.conf

 PerlModule Apache::AuthenSecurID

 # Authentication in .htaccess

 AuthName SecurID
 AuthType Basic

 # authenticate via SecurID
 PerlAuthenHandler Apache::AuthenSecurID

 PerlSetVar Auth_SecurID_VAR_ACE /ace/config/directory 

 require valid-user

=head1 DESCRIPTION

This module allows authentication against a SecurID server.

=head1 LIST OF TOKENS

=item *
Auth_SecurID_VAR_ACE

The location of the of the F<sdconf.rec> file.  It defaults to the
directory F</var/ace> if this variable is not set.

=head1 CONFIGURATION

The module should be loaded upon startup of the Apache daemon.
Add the following line to your httpd.conf:

 PerlModule Apache::AuthenSecurID

=head1 PREREQUISITES

For AuthenSecurID you need to enable the appropriate call-back hook 
when making mod_perl: 

  perl Makefile.PL PERL_AUTHEN=1

=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<Authen::SecurID>

=head1 AUTHORS

=item *
mod_perl by Doug MacEachern <dougm@osf.org>

=item *
Authen::ACE by Dave Carrigan <Dave.Carrigan@iplenergy.com>

=item *
Apache::AuthenSecurID by David Berk <dberk@lump.org>

=head1 COPYRIGHT

The Apache::AuthenSecurID module is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut
