# $Id: AuthenSecurID.pm,v 1.1 2001/01/18 20:50:27 root Exp $

package Apache::AuthenSecurID;

use strict;
use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED REDIRECT SERVER_ERROR);
use Authen::ACE;
use Digest::MD5;
use vars qw($VERSION);

$VERSION = '0.2';

sub handler {
	my $r = shift;
	
	# Continue only if the first request.
	return OK unless $r->is_initial_req;

	my $reqs_arr = $r->requires;
	return OK unless $reqs_arr;

	# Grab the password, or return if HTTP_UNAUTHORIZED
	my($res,$pass) = $r->get_basic_auth_pw;
	$r->log_reason("$res $pass", $r->uri);
	return $res if $res != OK;

	# Handle Cookie 
	my $auth_cookie = $r->dir_config("AuthCookie") || "SecurID";
	my $cookie_path = $r->dir_config("AuthCookiePath") || "/";

	my ( $session_key ) = ( ($r->header_in("Cookie") || "") =~ 
		/${auth_cookie}=([^;]+)/);

	# Get the user name.
	my $user = $r->connection->user;

	my $time = int ( time () / 86400 );

	my $ctx = new Digest::MD5;
	$ctx->add( "$user:$time" );
	my $digest_key = $ctx->b64digest;

	if ( $session_key eq $digest_key ) {
			return OK; 
	}


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

	# Create the SecurID connection.
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
		 $r->err_header_out("Set-Cookie" => $auth_cookie . "=" .
			$digest_key . "; path=" . $cookie_path); 
		$r->no_cache(1);
                $r->err_header_out("Pragma", "no-cache");
                $r->header_out("Location" => $r->uri);
		return OK;
		#return REDIRECT;
	} else {
		$r->log_reason("Apache::AuthenSecurID failed for user $user $res $VAR_ACE",
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
 PerlSetVar AuthCookie Name_of_Authentication_Cookie 
 PerlSetVar AuthCookiePath /path/of/authentication/cookie

 require valid-user

=head1 DESCRIPTION

This module allows authentication against a SecurID server.  If 
authentication is successful it sets a cookie with a MD5 hash
token.  The token expires at midnight local time.

=head1 LIST OF TOKENS

=item *
Auth_SecurID_VAR_ACE

The location of the F<sdconf.rec> file.  It defaults to the
directory F</var/ace> if this variable is not set.

=item *
AuthCookie

The name of the of cookie to be set for the authenticaion token.  
It defaults to the F<SecurID> if this variable is not set.

=item *
AuthCookiePath

The path of the of cookie to be set for the authenticaion token.  
It defaults to F</> if this variable is not set.

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
