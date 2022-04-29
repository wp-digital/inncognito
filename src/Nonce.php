<?php

namespace Innocode\Cognito;

final class Nonce
{
    /**
     * @return float
     */
    public static function get_tick() : float
    {
        return ceil( time() / Session::TTL );
    }

    /**
     * @param string $token
     * @return string
     */
    public static function create( string $token ) : string
    {
        $tick = Nonce::get_tick();
        $hash = wp_hash( "$token|$tick", 'nonce' );

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

        if ( hash_equals( wp_hash( "$token|$tick", 'nonce' ), $hash ) ) {
            return $token;
        }

        $tick -= 1;

        if ( hash_equals( wp_hash( "$token|$tick", 'nonce' ), $hash ) ) {
            return $token;
        }

        return null;
    }
}
