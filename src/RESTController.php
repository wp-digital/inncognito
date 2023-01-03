<?php

namespace Innocode\Cognito;

use Endroid\QrCode;
use Exception;
use WP_Error;
use WP_Http;
use WP_REST_Controller;

class RESTController extends WP_REST_Controller {

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->namespace = 'innocode/v1';
		$this->rest_base = 'cognito';
	}

	/**
	 * Registers REST routes to save rendered HTML from AWS Lambda.
	 *
	 * @return void
	 */
	public function register_routes() : void {
		register_rest_route(
			$this->namespace,
			"$this->rest_base/me",
			[
				'callback'            => [ $this, 'get_item' ],
				'permission_callback' => [ $this, 'get_item_permissions_check' ],
			]
		);

		register_rest_route(
			$this->namespace,
			"$this->rest_base/mfa/secret",
			[
				'callback'            => [ $this, 'get_mfa_secret' ],
				'permission_callback' => [ $this, 'get_item_permissions_check' ],
			]
		);
	}

	/**
	 * @param \WP_REST_Request $request
	 * @return bool|WP_Error
	 */
	public function get_item_permissions_check( $request ) {
		if ( ! is_user_logged_in() ) {
			return new WP_Error(
				'rest_inncognito_not_logged_in',
				__( 'You are not currently logged in.' ),
				[ 'status' => WP_Http::UNAUTHORIZED ]
			);
		}

		$user_id = get_current_user_id();

		if ( ! User::is_inncognito( $user_id ) ) {
			return new WP_Error(
				'rest_inncognito_no_cognito',
				__( 'You need to be authenticated through Cognito at least once.', 'inncognito' ),
				[ 'status' => WP_Http::FORBIDDEN ]
			);
		}

		$token = User::get_token( $user_id );

		if ( ! $token ) {
			return new WP_Error(
				'rest_inncognito_no_token',
				__( 'You need to obtain a new access token from Cognito.', 'inncognito' ),
				[ 'status' => WP_Http::FORBIDDEN ]
			);
		}

		return true;
	}

	/**
	 * @param \WP_REST_Request $request
	 * @return \WP_REST_Response|WP_Error
	 */
	public function get_item( $request ) {
		try {
			$result = inncognito()
				->get_cognito_identity_provider_client()
				->getUser(
					[
						'AccessToken' => User::get_token( get_current_user_id() ),
					]
				);
		} catch ( Exception $exception ) {
			return new WP_Error(
				'rest_inncognito_profile_error',
				$exception->getMessage(),
				[ 'status' => WP_Http::INTERNAL_SERVER_ERROR ]
			);
		}

		return rest_ensure_response(
			[
				'username'   => $result->get( 'Username' ),
				'attributes' => array_reduce(
					$result->get( 'UserAttributes' ),
					function ( array $attributes, array $attribute ) {
						if (
							! isset( $attribute['Name'] ) ||
							! isset( $attribute['Value'] ) ||
							$attribute['Name'] === 'sub'
						) {
							return $attributes;
						}

						if ( $attribute['Name'] === 'email_verified' ) {
							$attributes[ $attribute['Name'] ] = $attribute['Value'] === 'true';
						} else {
							$attributes[ $attribute['Name'] ] = $attribute['Value'];
						}

						return $attributes;
					},
					[]
				),
				'mfa'        => $result->get( 'UserMFASettingList' ),
			]
		);
	}

	/**
	 * @return WP_Error|\WP_REST_Response
	 */
	public function get_mfa_secret() {
		try {
			$result = inncognito()
				->get_cognito_identity_provider_client()
				->associateSoftwareToken(
					[
						'AccessToken' => User::get_token( get_current_user_id() ),
					]
				);
		} catch ( Exception $exception ) {
			return new WP_Error(
				'rest_inncognito_mfa_error',
				$exception->getMessage(),
				[ 'status' => WP_Http::INTERNAL_SERVER_ERROR ]
			);
		}

		$secret_code     = $result->get( 'SecretCode' );
		$secret_code_uri = sprintf(
			'otpauth://totp/%1$s:%2$s?secret=%3$s&issuer=%1$s',
			__( 'Inncognito', 'inncognito' ),
			wp_get_current_user()->user_login,
			$secret_code
		);

		return rest_ensure_response(
			[
				'value' => $secret_code,
				'uri'   => $secret_code_uri,
				'qr'    => QrCode\Builder\Builder::create()
					->data( $secret_code_uri )
					->size( 200 )
					->margin( 0 )
					->build()
					->getDataUri(),
			]
		);
	}
}
