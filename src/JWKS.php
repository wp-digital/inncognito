<?php

namespace Innocode\Cognito;

use WP_Error;

class JWKS
{
    /**
     * @var string
     */
    protected $region;
    /**
     * @var string
     */
    protected $user_pool_id;
    /**
     * @var array|null
     */
    protected $value;

    /**
     * @param string $region
     * @param string $user_pool_id
     */
    public function __construct( string $region, string $user_pool_id )
    {
        $this->region = $region;
        $this->user_pool_id = $user_pool_id;
    }

    /**
     * @return string
     */
    public function get_region() : string
    {
        return $this->region;
    }

    /**
     * @return string
     */
    public function get_user_pool_id() : string
    {
        return $this->user_pool_id;
    }

    /**
     * @return string
     */
    public function iss() : string
    {
        return sprintf(
            "https://cognito-idp.%s.amazonaws.com/%s",
            $this->get_region(),
            $this->get_user_pool_id()
        );
    }

    /**
     * @return array|WP_Error
     */
    public function download()
    {
        return wp_remote_get( "{$this->iss()}/.well-known/jwks.json" );
    }

    /**
     * @return void
     */
    public function populate()
    {
        if ( get_option( 'inncognito_jwks_stored' ) ) {
            return;
        }

        $response = $this->download();

        if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
            return;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! isset( $body['keys'] ) ) {
            return;
        }

        update_option( 'inncognito_jwks', $body, false );
        update_option( 'inncognito_jwks_stored', current_time( 'mysql' ) );
    }

    /**
     * @return void
     */
    public function clear()
    {
        delete_option( 'inncognito_jwks' );
        delete_option( 'inncognito_jwks_stored' );
    }

    /**
     * @return array|null
     */
    public function __invoke()
    {
        if ( null !== $this->value ) {
            return $this->value;
        }

        $this->value = get_option( 'inncognito_jwks', null );

        return $this->value;
    }

    /**
     * @return bool
     */
    public function exists() : bool
    {
        return null !== $this();
    }
}
