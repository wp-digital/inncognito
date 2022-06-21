<?php

namespace Innocode\Cognito;

use Exception;
use Firebase\JWT\JWT;
use WP_Error;

final class State
{
    /**
     * @var string
     */
    private $action;
    /**
     * @var string|null
     */
    private $redirect_to;
    /**
     * @var int
     */
    private $expiration;
    /**
     * @var string|null
     */
    private $key;

    /**
     * @param string $action
     * @return void
     */
    public function set_action( string $action )
    {
        $this->action = $action;
    }

    /**
     * @return string
     */
    public function get_action() : string
    {
        return $this->action;
    }

    /**
     * @param string $redirect_to
     * @return void
     */
    public function set_redirect_to( string $redirect_to )
    {
        $this->redirect_to = $redirect_to;
    }

    /**
     * @return string|null
     */
    public function get_redirect_to()
    {
        return $this->redirect_to;
    }

    /**
     * @param int $expiration
     * @return void
     */
    public function set_expiration( int $expiration )
    {
        $this->expiration = $expiration;
    }

    /**
     * @return int
     */
    public function get_expiration() : int
    {
        return $this->expiration;
    }

    /**
     * @param string $key
     * @return void
     */
    public function set_key( string $key )
    {
        $this->key = $key;
    }

    /**
     * @return string|null
     */
    public function get_key()
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function __toString() : string
    {
        try {
            $encoded = JWT::jsonEncode( [
                'action'      => $this->get_action(),
                'redirect_to' => $this->get_redirect_to(),
                'expiration'  => $this->get_expiration(),
                'hash'        => wp_hash_password( $this->get_key() ),
            ] );
        } catch ( Exception $exception ) {
            error_log( $exception->getMessage() );

            return '';
        }

        return JWT::urlsafeB64Encode( $encoded );
    }

    /**
     * @param string $string
     * @param string $key
     * @return State|WP_Error
     */
    public static function decode( string $string, string $key )
    {
        try {
            $decoded = JWT::jsonDecode( JWT::urlsafeB64Decode( $string ) );
        } catch ( Exception $exception ) {
            return new WP_Error( 'inncognito_invalid_json', $exception->getMessage() );
        }

        $data = Helpers::object_to_array( $decoded );

        if ( ! isset( $data['hash'] ) || ! wp_check_password( $key, $data['hash'] ) ) {
            return new WP_Error( 'inncognito_hash_mismatch', __( 'Invalid key.', 'inncognito' ) );
        }

        $state = new self();

        if ( isset( $data['action'] ) ) {
            $state->set_action( $data['action'] );
        }

        if ( isset( $data['redirect_to'] ) ) {
            $state->set_redirect_to( $data['redirect_to'] );
        }

        if ( isset( $data['expiration'] ) ) {
            $state->set_expiration( $data['expiration'] );
        }

        $state->set_key( $key );

        return $state;
    }
}
