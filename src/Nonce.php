<?php

namespace Innocode\Cognito;

final class Nonce
{
    /**
     * @param string $token
     * @return string
     */
    public static function create( string $token ) : string
    {
        $tick = Nonce::get_tick();
        $hash = Nonce::generate_hash( $token, $tick );

        return "$token|$hash";
    }

    /**
     * @param string $nonce
     * @return string|null
     */
    public static function verify( string $nonce ) : ?string
    {
        if ( ! strpos( $nonce, '|' ) ) {
            return null;
        }

        list( $token, $hash ) = explode( '|', wp_unslash( $nonce ), 2 );

        $tick = Nonce::get_tick();

        if ( hash_equals( Nonce::generate_hash( $token, $tick ), $hash ) ) {
            return $token;
        }

        $tick -= 1;

        if ( hash_equals( Nonce::generate_hash( $token, $tick ), $hash ) ) {
            return $token;
        }

        return null;
    }

    /**
     * @param string $token
     * @param float  $tick
     * @return string
     */
    public static function generate_hash( string $token, float $tick ) : string
    {
        $data = [ $tick, $token ];

        if ( is_user_logged_in() ) {
            $data[] = get_current_user_id();
            $data[] = wp_get_session_token();
        }

        return wp_hash( implode( '|', $data ), 'nonce' );
    }

    /**
     * @return float
     */
    public static function get_tick() : float
    {
        return ceil( time() / Session::TTL );
    }
}
