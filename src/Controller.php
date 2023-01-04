<?php

namespace Innocode\Cognito;

use Exception;

final class Controller {

	/**
	 * @param Plugin $plugin
	 * @return void
	 */
	public function index( Plugin $plugin ) : void {
		$query = $plugin->get_query();
		$scope = null;

		if ( $query->is_root() ) {
			if ( is_user_logged_in() ) {
				wp_redirect( User::admin_url( get_current_user_id() ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
				exit;
			}

			nocache_headers();

			$scope = 'openid email profile';
		} elseif ( $query->is_token() ) {
			if ( ! is_user_logged_in() || ! User::is_inncognito( get_current_user_id() ) ) {
				return;
			}

			$scope = 'aws.cognito.signin.user.admin';
		}

		$state = new State();
		$state->set_action( $query->value() );

		$redirect_to = $query->get_var( 'redirect_to' );

		if ( null !== $redirect_to ) {
			$state->set_redirect_to( $redirect_to );
		}

		$key = $plugin->get_session()->start( $state );

		if ( null === $key ) {
			return;
		}

		wp_redirect( $plugin->api_url( $key, $scope ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	/**
	 * @param Plugin $plugin
	 * @param array  $body
	 * @param State  $state
	 * @return void
	 */
	public function login( Plugin $plugin, array $body, State $state ) : void {
		if ( is_user_logged_in() ) {
			wp_redirect( User::admin_url( get_current_user_id() ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			exit;
		}

		nocache_headers();

		try {
			$jwt = $plugin->retrieve_jwt( $body, 'id' );
		} catch ( Exception $exception ) {
			error_log( $exception->getMessage() );

			return;
		}

		$user_id = email_exists( $jwt['email'] );

		if ( $user_id ) {
			if ( ! User::is_inncognito( $user_id ) ) {
				User::inncognitize( $user_id );
			}

			if ( isset( $jwt['cognito:username'] ) ) {
				User::innconnect( $user_id, $jwt['cognito:username'] );
			}
		} elseif ( $plugin->allow_registration() ) {
			$user_id = User::create_from_jwt( $jwt );

			if ( is_wp_error( $user_id ) ) {
				Helpers::log_wp_error( $user_id );

				return;
			}
		} else {
			Helpers::error_die( __( 'Registration is disabled.', 'inncognito' ) );
		}

		$is_forced = $plugin->use_force_cognito( false );
		$user      = User::no_password_sign_in( $jwt['email'] );
		$plugin->use_force_cognito( $is_forced );

		if ( is_wp_error( $user ) ) {
			Helpers::log_wp_error( $user );

			return;
		}

		$this->redirect( $user->ID, $state );
	}

	/**
	 * @param Plugin $plugin
	 * @param array  $body
	 * @param State  $state
	 * @return void
	 */
	public function token( Plugin $plugin, array $body, State $state ) : void {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id = get_current_user_id();

		if ( ! User::is_inncognito( $user_id ) ) {
			return;
		}

		try {
			$jwt = $plugin->retrieve_jwt( $body, 'access' );
		} catch ( Exception $exception ) {
			error_log( $exception->getMessage() );

			return;
		}

		if ( $jwt['username'] !== User::get_innconnection( $user_id ) ) {
			Helpers::error_die( __( 'Invalid user. Please check username as it does not match.', 'inncognito' ) );
		}

		User::update_token( $user_id, $body['access_token'], $jwt['exp'] );

		$this->redirect( $user_id, $state );
	}

	/**
	 * @param int   $user_id
	 * @param State $state
	 * @return void
	 */
	private function redirect( int $user_id, State $state ) : void {
		$redirect_to = $state->get_redirect_to();

		if (
			null !== $redirect_to &&
			! in_array(
				$redirect_to,
				[
					'wp-admin/',
					admin_url(),
				],
				true
			)
		) {
			wp_safe_redirect( $redirect_to );
			exit;
		}

		wp_redirect( User::admin_url( $user_id ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}
}
