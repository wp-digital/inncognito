<?php

namespace Innocode\Cognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use WP_Error;
use WP_User;
use stdClass;

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
     * @var Rewrite
     */
    private $rewrite;
    /**
     * @var Controller
     */
    private $controller;
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
     * @var CognitoIdentityProviderClient
     */
    private $cognito_identity_provider_client;
    /**
     * @var RESTController
     */
    private $rest_controller;

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
        $this->rewrite = new Rewrite();
        $this->controller = new Controller();
        $this->jwks = new JWKS( $region, $user_pool_id );
        $this->session = new Session();
        $this->rest_controller = new RESTController();
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
     * @return Rewrite
     */
    public function get_rewrite() : Rewrite
    {
        return $this->rewrite;
    }

    /**
     * @return Controller
     */
    public function get_controller() : Controller
    {
        return $this->controller;
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
     * @return CognitoIdentityProviderClient
     */
    public function get_cognito_identity_provider_client() : CognitoIdentityProviderClient
    {
        if ( null === $this->cognito_identity_provider_client ) {
            $api = $this->get_api();
            $jwks = $this->get_jwks();
            $this->cognito_identity_provider_client = new CognitoIdentityProviderClient( [
                'credentials' => [
                    'key'    => $api->get_client_id(),
                    'secret' => $api->get_client_secret(),
                ],
                'region'  => $jwks->get_region(),
                'version' => 'latest',
            ] );
        }

        return $this->cognito_identity_provider_client;
    }

    /**
     * @return RESTController
     */
    public function get_rest_controller() : RESTController
    {
        return $this->rest_controller;
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
        add_action( 'rest_api_init', [ $this->get_rest_controller(), 'register_routes' ] );
        add_action( 'template_redirect', [ $this, 'handle_request' ] );
        add_action( 'delete_expired_transients', [ User::class, 'flush_expired_tokens' ] );

        add_filter( 'authenticate', [ $this, 'force_cognito' ], PHP_INT_MAX, 2 );
        add_action( 'validate_password_reset', [ $this, 'disable_password_reset'], PHP_INT_MAX, 2 );

        add_filter( 'show_password_fields', [ $this, 'should_show_password_fields' ], 10, 2 );
        add_action( 'show_user_profile', [ $this, 'show_profile' ] );
        add_action( 'user_profile_update_errors', [ $this, 'update_mfa' ], 10, 3 );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ] );

        // Integrations
        add_filter( 'pll_modify_rewrite_rule', [ $this, 'pll_modify_rewrite_rule' ], 10, 3 );
    }

    /**
     * @param string      $key
     * @param string|null $scope
     * @return string
     */
    public function api_url( string $key, string $scope = null ) : string
    {
        return $this->get_api()->login_url( $this->login_url(), $key, $scope );
    }

    /**
     * @param string|null $redirect_to
     * @return string
     */
    public function login_url( string $redirect_to = null ) : string
    {
        return $this->get_query()->url( '/', $redirect_to );
    }

    /**
     * @param string|null $redirect_to
     * @return string
     */
    public function token_url( string $redirect_to = null ) : string
    {
        return $this->get_query()->url( 'token', $redirect_to );
    }

    /**
     * @return void
     */
    public function add_rewrite_endpoints() : void
    {
        $this->get_rewrite()->init( $this->get_query()->get_endpoint() );
    }

    /**
     * @return void
     */
    public function handle_request() : void
    {
        $query = $this->get_query();

        if ( ! $query->exists() ) {
            return;
        }

        $query->parse();
        $code = $query->get_var( 'code' );

        $controller = $this->get_controller();

        $session = $this->get_session();
        $session->set_cookie_path( $query->path() );

        if ( null === $code ) {
            $controller->index( $this );

            return;
        }

        $key = $query->get_var( 'state' );

        if ( null === $key ) {
            Helpers::error_die( __( 'Empty state.', 'inncognito' ) );
        }

        $state = $session->stop( $key );

        if ( is_wp_error( $state ) ) {
            Helpers::error_die( $state->get_error_message() );
        }

        $response = $this->get_api()->token( $code, $this->login_url() );

        if ( is_wp_error( $response ) ) {
            Helpers::log_wp_error( $response );

            return;
        }

        if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
            error_log( wp_remote_retrieve_response_message( $response ) );

            return;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        $action = $state->get_action();

        if ( $action === '' ) {
            $controller->login( $this, $body, $state );
        } elseif ( $action == 'token' ) {
            $controller->token( $this, $body, $state );
        }
    }

    /**
     * @param array  $body
     * @param string $use
     * @return array
     * @throws Exception
     */
    public function retrieve_jwt( array $body, string $use ) : array
    {
        $key = "{$use}_token";

        if ( ! isset( $body[ $key ] ) ) {
            throw new Exception( sprintf( 'Missing %s token.', $use ) );
        }

        $jwks = $this->get_jwks();

        if ( ! $jwks->exists() ) {
            throw new Exception( 'Missing JWKS.' );
        }

        $jwt = Helpers::object_to_array( JWT::decode( $body[ $key ], JWK::parseKeySet( $jwks() ), [ 'RS256' ] ) );

        return $this->verify_jwt_claims( $jwt, $use );
    }

    /**
     * @link https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
     *
     * @param array  $jwt
     * @param string $token_use
     * @return array
     * @throws Exception
     */
    public function verify_jwt_claims( array $jwt, string $token_use ) : array
    {
        if ( $token_use == 'id' && (
            ! isset( $jwt['aud'] ) || $jwt['aud'] != $this->get_api()->get_client_id()
        ) ) {
            throw new Exception( 'Token was not issued for this audience.' );
        } elseif ( $token_use == 'access' && (
            ! isset( $jwt['client_id'] ) || $jwt['client_id'] != $this->get_api()->get_client_id()
        ) ) {
            throw new Exception( 'Token was not issued for this client id.' );
        }

        if ( ! isset( $jwt['iss'] ) || $jwt['iss'] != $this->get_jwks()->iss() ) {
            throw new Exception( 'Token was not issued by this issuer.' );
        }

        if ( ! isset( $jwt['token_use'] ) || $jwt['token_use'] != $token_use ) {
            throw new Exception( 'Token was not issued for this use case.' );
        }

        if ( $token_use == 'id' ) {
            if ( ! isset( $jwt['email'] ) || ! is_email( $jwt['email'] ) ) {
                throw new Exception( 'Token has an invalid email.' );
            }

            if ( empty( $jwt['email_verified'] ) ) {
                throw new Exception( 'Token has an unverified email.' );
            }
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
                "<br><a href=\"{$this->login_url()}\">" .
                __( 'Proceed to Cognito', 'inncognito' ) .
                '</a>'
            );
        }

        return $user;
    }

    /**
     * @param WP_Error         $errors
     * @param WP_User|WP_Error $user
     * @return WP_Error
     */
    public function disable_password_reset( WP_Error $errors, $user ) : WP_Error
    {
        if ( ! $this->use_force_cognito() || ! ( $user instanceof WP_User ) ) {
            return $errors;
        }

        if ( User::is_inncognito( $user->ID ) ) {
            $errors->add(
                'inncognito_force_cognito',
                __( '<strong>Error</strong>: Sorry, this user cannot reset their password.', 'inncognito' ) .
                "<br><a href=\"{$this->login_url()}\">" .
                __( 'Proceed to Cognito', 'inncognito' ) .
                '</a>'
            );
        }

        return $errors;
    }

    /**
     * @param bool    $should_show
     * @param WP_User $user
     * @return bool
     */
    public function should_show_password_fields( bool $should_show, WP_User $user ) : bool
    {
        if ( $this->use_force_cognito() && User::is_inncognito( $user->ID ) ) {
            return false;
        }

        return $should_show;
    }

    /**
     * @param WP_User $user
     * @return void
     */
    public function show_profile( WP_User $user ) : void
    {
        if ( ! User::is_inncognito( $user->ID ) ) {
            return;
        }

        require_once __DIR__ . '/../resources/views/profile.php';
    }

    /**
     * @param WP_Error $errors
     * @param bool     $update
     * @param stdClass $user
     * @return void
     */
    public function update_mfa( WP_Error $errors, bool $update, stdClass $user ) : void
    {
        if (
            ! defined( 'IS_PROFILE_PAGE' ) ||
            ! IS_PROFILE_PAGE ||
            ! $update ||
            ! User::is_inncognito( $user->ID ) ||
            empty( $_POST['inncognito_mfa_user_code'] )
        ) {
            return;
        }

        $code = filter_var( $_POST['inncognito_mfa_user_code'], FILTER_VALIDATE_REGEXP, [
            'options' => [
                'regexp' => '/^[0-9]{6}$/',
            ],
        ] );

        if ( false === $code ) {
            $errors->add(
                'inncognito_mfa_user_code',
                __( '<strong>Error</strong>: Please enter a valid MFA one-time password.', 'inncognito' ),
                [ 'form-field' => 'inncognito_mfa_user_code' ]
            );

            return;
        }

        $token = User::get_token( $user->ID );

        if ( ! $token ) {
            $errors->add(
                'inncognito_user_token',
                __( '<strong>Error</strong>: You need to obtain a new access token from Cognito.', 'inncognito' ),
                [ 'form-field' => 'inncognito_mfa_user_code' ]
            );

            return;
        }

        try {
            $result = $this->get_cognito_identity_provider_client()->verifySoftwareToken( [
                'AccessToken'        => $token,
                'FriendlyDeviceName' => isset( $_POST['inncognito_mfa_user_device'] )
                    ? sanitize_text_field( $_POST['inncognito_mfa_user_device'] )
                    : null,
                'UserCode'           => $code,
            ] );
        } catch ( Exception $exception ) {
            $errors->add(
                'inncognito_mfa_user_code',
                sprintf(
                    '<strong>%s</strong>: %s.',
                    __( 'Error' ),
                    $exception->getMessage()
                ),
                [ 'form-field' => 'inncognito_mfa_user_code' ]
            );

            return;
        }

        if ( $result->get( 'Status' ) == 'ERROR' ) {
            $errors->add(
                'inncognito_mfa_user_code',
                __( '<strong>Error</strong>: Something went wrong.', 'inncognito' ),
                [ 'form-field' => 'inncognito_mfa_user_code' ]
            );
        }
    }

    /**
     * @param string $hook_suffix
     * @return void
     */
    public function enqueue_scripts( string $hook_suffix ) : void
    {
        if ( 'profile.php' != $hook_suffix ) {
            return;
        }

        // Domain mapping processes mu-plugins directory wrong.
        $has_domain_mapping = remove_filter( 'plugins_url', 'domain_mapping_plugins_uri', 1 );

        $suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '' : '.min';
        $script_url = plugins_url( "public/js/profile$suffix.js", INNCOGNITO_FILE );

        if ( $has_domain_mapping ) {
            add_filter( 'plugins_url', 'domain_mapping_plugins_uri', 1 );
        }

        wp_enqueue_script(
            'inncognito-profile',
            $script_url,
            [ 'jquery', 'wp-util', 'wp-api-request' ],
            INNCOGNITO_VERSION,
            true
        );
    }

    /**
     * @param bool   $modify
     * @param array  $rule
     * @param string $filter
     * @return bool
     */
    public function pll_modify_rewrite_rule( bool $modify, array $rule, string $filter ) : bool
    {
        if ( ! $modify || 'root' != $filter ) {
            return $modify;
        }

        list( $regex ) = array_keys( $rule );

        return $regex != "{$this->get_query()->get_endpoint()}(/(.*))?/?$";
    }

    /**
     * @return void
     */
    public function activate() : void
    {
        $this->get_jwks()->populate();
        $this->get_rewrite()->flush_rules();
    }

    /**
     * @return void
     */
    public function deactivate() : void
    {
        $this->get_jwks()->clear();
        $this->get_rewrite()->clear();
        User::clear_db();
    }
}
