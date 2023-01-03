<?php

namespace Innocode\Cognito\Integrations\GoogleAuthenticator;

use Innocode\Cognito\Interfaces\IntegrationInterface;
use Innocode\Cognito\Plugin;
use Innocode\Cognito\User;
use WP_User;

class Integration implements IntegrationInterface {

	/**
	 * @param Plugin $plugin
	 * @return void
	 */
	public function run( Plugin $plugin ) : void {
		add_filter( 'get_user_option_googleauthenticator_enabled', [ $this, 'force_disabled' ], 10, 3 );
		add_filter( 'google_authenticator_needs_setup', [ $this, 'disable_setup' ], 10, 2 );
	}

	/**
	 * @param mixed   $result
	 * @param string  $option
	 * @param WP_User $user
	 * @return string
	 */
	public function force_disabled( $result, string $option, WP_User $user ) : string {
		return $result === 'enabled' && User::is_inncognito( $user->ID ) ? 'disabled' : $result;
	}

	/**
	 * @param bool    $must_signup
	 * @param WP_User $user
	 * @return bool
	 */
	public function disable_setup( bool $must_signup, WP_User $user ) : bool {
		return $must_signup && User::is_inncognito( $user->ID ) ? false : $must_signup;
	}
}
