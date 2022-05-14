<?php

namespace Innocode\Cognito;

use WP_Error;

final class Session
{
    const TTL = 15 * MINUTE_IN_SECONDS;
    const KEY_LENGTH = 32;

    /**
     * @var string
     */
    private $cookie_name;
    /**
     * @var string
     */
    private $cookie_path;

    /**
     * @param string $cookie_name
     * @return void
     */
    public function set_cookie_name( string $cookie_name ) : void
    {
        $this->cookie_name = $cookie_name . ( defined( 'COOKIEHASH' ) ? '_' . COOKIEHASH : '' );
    }

    /**
     * @return string
     */
    public function get_cookie_name() : string
    {
        return $this->cookie_name;
    }

    /**
     * @param string $cookie_path
     * @return void
     */
    public function set_cookie_path( string $cookie_path ) : void
    {
        $this->cookie_path = $cookie_path;
    }

    /**
     * @return string
     */
    public function get_cookie_path() : string
    {
        return $this->cookie_path;
    }

    /**
     * @param State $state
     * @return string|null
     */
    public function start( State $state ) : ?string
    {
        $state->set_expiration( time() + Session::TTL );
        $state->set_key( wp_generate_password( Session::KEY_LENGTH, false ) );

        $token = (string) $state;

        if ( ! $token ) {
            return null;
        }

        $nonce = Nonce::create( $token );

        $this->set_cookie( $nonce );

        return $state->get_key();
    }

    /**
     * @param string $key
     * @return State|WP_Error
     */
    public function stop( string $key )
    {
        $cookie_name = $this->get_cookie_name();

        if ( ! isset( $_COOKIE[ $cookie_name ] ) ) {
            return new WP_Error( 'inncognito_empty_session', __( 'Invalid session. Cookies may be blocked or not supported.', 'inncognito' ) );
        }

        $cookie = $_COOKIE[ $cookie_name ];

        $this->unset_cookie();

        if ( null === ( $token = Nonce::verify( $cookie ) ) ) {
            return new WP_Error( 'inncognito_malformed_session', __( 'Malformed session.', 'inncognito' ) );
        }

        $state = State::decode( $token, $key );

        if ( is_wp_error( $state ) ) {
            return $state;
        }

        if ( $state->get_expiration() < time() ) {
            return new WP_Error( 'inncognito_expired_session', __( 'Expired session.', 'inncognito' ) );
        }

        return $state;
    }

    /**
     * @param string $value
     * @param int    $expires
     * @return void
     */
    private function set_cookie( string $value, int $expires = 0 ) : void
    {
        setcookie( $this->get_cookie_name(), $value, $expires, $this->get_cookie_path(), COOKIE_DOMAIN, is_ssl(), true );
    }

    /**
     * @return void
     */
    private function unset_cookie() : void
    {
        $this->set_cookie( ' ', time() - YEAR_IN_SECONDS );
    }
}
