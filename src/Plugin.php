<?php

namespace Innocode\Cognito;

use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use WP_Error;
use WP_User;

final class Plugin
{
    const DOMAIN_MASK = 'https://%s.auth.%s.amazoncognito.com';

    /**
     * @var API
     */
    private $api;
    /**
     * @var Query
     */
    private $query;
    /**
     * @var JWKS
     */
    private $jwks;
    /**
     * @var Session
     */
    private $session;
    /**
     * @var bool
     */
    private $force_cognito = false;
    /**
     * @var bool
     */
    private $registration_allowed = true;

    /**
     * @param string $domain
     * @param string $client_id
     * @param string $client_secret
     * @param string $region
     * @param string $user_pool_id
     */
    public function __construct(
        string $domain,
        string $client_id,
        string $client_secret,
        string $region,
        string $user_pool_id
    )
    {
        if ( ! preg_match( '/^https?:\/\//i', $domain ) ) {
            $domain = sprintf( Plugin::DOMAIN_MASK, $domain, $region );
        }

        $this->api = new API( $domain, $client_id, $client_secret );
        $this->query = new Query();
        $this->jwks = new JWKS( $region, $user_pool_id );
        $this->session = new Session();
    }

    /**
     * @return API
     */
    public function get_api() : API
    {
        return $this->api;
    }

    /**
     * @return Query
     */
    public function get_query() : Query
    {
        return $this->query;
    }

    /**
     * @return JWKS
     */
    public function get_jwks() : JWKS
    {
        return $this->jwks;
    }

    /**
     * @return Session
     */
    public function get_session() : Session
    {
        return $this->session;
    }

    /**
     * @param bool|null $force
     * @return bool
     */
    public function use_force_cognito( bool $force = null ) : bool
    {
        $is_forced = $this->force_cognito;

        if ( null !== $force ) {
            $this->force_cognito = $force;
        }

        return $is_forced;
    }

    /**
     * @param bool|null $allow
     * @return bool
     */
    public function allow_registration( bool $allow = null ) : bool
    {
        $is_allowed = $this->registration_allowed;

        if ( null !== $allow ) {
            $this->registration_allowed = $allow;
        }

        return $is_allowed;
    }

    /**
     * @return void
     */
    public function run() : void
    {
        register_activation_hook( INNCOGNITO_FILE, [ $this, 'activate' ] );
        register_deactivation_hook( INNCOGNITO_FILE, [ $this, 'deactivate' ] );

        add_action( 'init', [ $this->get_jwks(), 'populate' ] );
        add_action( 'init', [ $this, 'add_rewrite_endpoints' ] );
        add_action( 'template_redirect', [ $this, 'handle_request' ] );

        add_filter( 'authenticate', [ $this, 'force_cognito' ], PHP_INT_MAX, 2 );
    }

    /**
     * @param string $key
     * @return string
     */
    public function login_url( string $key ) : string
    {
        return $this->get_api()->login_url( $this->get_query()->url(), $key );
    }

    /**
     * @return void
     */
    public function add_rewrite_endpoints() : void
    {
        add_rewrite_endpoint( $this->get_query()->get_endpoint(), EP_ROOT );
    }

    /**
     * @return void
     */
    public function handle_request() : void
    {
        $query = $this->get_query();

        if ( ! $query->is_root() ) {
            return;
        }

        if ( is_user_logged_in() ) {
            wp_redirect( User::admin_url( get_current_user_id() ) );
            exit;
        }

        nocache_headers();

        $jwks = $this->get_jwks();

        if ( ! $jwks->exists() ) {
            error_log( 'Missing JWKS' );

            return;
        }

        $query->parse();
        $code = $query->get_var( 'code' );

        $session = $this->get_session();
        $session->init();

        if ( null === $code ) {
            $state = new State();

            if ( null !== ( $redirect_to = $query->get_var( 'redirect_to' ) ) ) {
                $state->set_redirect_to( $redirect_to );
            }

            if ( null === ( $key = $session->start( $state ) ) ) {
                return;
            }

            wp_redirect( $this->login_url( $key ) );
            exit;
        }

        $key = $query->get_var( 'state' );

        if ( null === $key ) {
            wp_die( __( 'Empty state.', 'inncognito' ), __( 'Inncognito', 'inncognito' ), 400 );
        }

        $state = $session->stop( $key );

        if ( is_wp_error( $state ) ) {
            wp_die( $state->get_error_message(), __( 'Inncognito', 'inncognito' ), 401 );
        }

        $response = $this->get_api()->token( $code, $query->url() );

        if ( is_wp_error( $response ) ) {
            Helpers::log_wp_error( $response );

            return;
        }

        if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
            error_log( wp_remote_retrieve_response_message( $response ) );

            return;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! isset( $body['id_token'] ) ) {
            error_log( 'Missing ID token' );

            return;
        }

        try {
            $jwt = Helpers::object_to_array( JWT::decode( $body['id_token'], JWK::parseKeySet( $jwks() ) ) );
        } catch ( Exception $exception ) {
            error_log( $exception->getMessage() );

            return;
        }

        $jwt = $this->verify_jwt_claims( $jwt );

        if ( is_wp_error( $jwt ) ) {
            Helpers::log_wp_error( $jwt );

            return;
        }

        $user_id = email_exists( $jwt['email'] );

        if ( $user_id ) {
            if ( ! User::is_inncognito( $user_id ) ) {
                User::inncognitize( $user_id );
            }
        } elseif ( $this->allow_registration() ) {
            $user_id = User::create_from_jwt( $jwt );

            if ( is_wp_error( $user_id ) ) {
                Helpers::log_wp_error( $user_id );

                return;
            }
        } else {
            wp_die( __( 'Registration is disabled.', 'inncognito' ), __( 'Inncognito', 'inncognito' ), 403 );
        }

        $is_forced = $this->use_force_cognito( false );
        $user = User::no_password_sign_in( $jwt['email'] );
        $this->use_force_cognito( $is_forced );

        if ( is_wp_error( $user ) ) {
            Helpers::log_wp_error( $user );

            return;
        }

        if (
            null !== ( $redirect_to = $state->get_redirect_to() ) &&
            ! in_array( $redirect_to, [
                'wp-admin/',
                admin_url(),
            ], true )
        ) {
            wp_safe_redirect( $redirect_to );
            exit;
        }

        wp_redirect( User::admin_url( $user->ID ) );
        exit;
    }

    /**
     * @link https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
     *
     * @param array $jwt
     * @return array|WP_Error
     */
    public function verify_jwt_claims( array $jwt )
    {
        if ( ! isset( $jwt['aud'] ) || $jwt['aud'] != $this->get_api()->get_client_id() ) {
            return new WP_Error(
                'inncognito_invalid_token_aud',
                __( 'Token was not issued for this audience.', 'inncognito' )
            );
        }

        if ( ! isset( $jwt['iss'] ) || $jwt['iss'] != $this->get_jwks()->iss() ) {
            return new WP_Error(
                'inncognito_invalid_token_iss',
                __( 'Token was not issued by this issuer.', 'inncognito' )
            );
        }

        if ( ! isset( $jwt['token_use'] ) || ! in_array( $jwt['token_use'], [ 'access', 'id' ], true ) ) {
            return new WP_Error(
                'inncognito_invalid_token_use',
                __( 'Token was not issued for this use case.', 'inncognito' )
            );
        }

        if ( ! isset( $jwt['email'] ) || ! is_email( $jwt['email'] ) ) {
            return new WP_Error(
                'inncognito_invalid_email',
                __( 'Invalid email.', 'inncognito' )
            );
        }

        if ( empty( $jwt['email_verified'] ) ) {
            return new WP_Error(
                'inncognito_unverified_email',
                __( 'Unverified email.', 'inncognito' )
            );
        }

        return $jwt;
    }

    /**
     * @param null|WP_User|WP_Error $user
     * @param string                $username
     * @return null|WP_User|WP_Error
     */
    public function force_cognito( $user, string $username )
    {
        if ( ! $this->use_force_cognito() || ! ( $user instanceof WP_User ) ) {
            return $user;
        }

        if ( User::is_inncognito( $user->ID ) ) {
            return new WP_Error(
                'inncognito_force_cognito',
                sprintf(
                    __( '<strong>Error</strong>: Sorry, %s cannot use the regular login form.', 'inncognito' ),
                    "<strong>$username</strong>"
                ) .
                "<br><a href=\"{$this->get_query()->url()}\">" .
                __( 'Proceed to Cognito', 'inncognito' ) .
                '</a>'
            );
        }

        return $user;
    }

    /**
     * @return void
     */
    public function activate() : void
    {
        $this->get_jwks()->populate();
    }

    /**
     * @return void
     */
    public function deactivate() : void
    {
        $this->get_jwks()->clear();
    }
}
