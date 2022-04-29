<?php

namespace Innocode\Cognito;

use WP_Error;

class API
{
    /**
     * @var string
     */
    protected $domain;
    /**
     * @var string
     */
    protected $client_id;
    /**
     * @var string
     */
    protected $client_secret;

    /**
     * @param string $domain
     * @param string $client_id
     * @param string $client_secret
     */
    public function __construct( string $domain, string $client_id, string $client_secret )
    {
        $this->domain = $domain;
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
    }

    /**
     * @return string
     */
    public function get_domain() : string
    {
        return $this->domain;
    }

    /**
     * @return string
     */
    public function get_client_id() : string
    {
        return $this->client_id;
    }

    /**
     * @return string
     */
    public function get_client_secret() : string
    {
        return $this->client_secret;
    }

    /**
     * @return string
     */
    public function get_authorization_header() : string
    {
        return 'Basic ' . base64_encode( "{$this->get_client_id()}:{$this->get_client_secret()}" );
    }

    /**
     * @param string $redirect_uri
     * @param string $state
     * @return string
     */
    public function login_url( string $redirect_uri, string $state ) : string
    {
        return add_query_arg( [
            'response_type' => 'code',
            'client_id'     => $this->get_client_id(),
            'redirect_uri'  => rawurlencode( $redirect_uri ),
            'state'         => $state,
        ], $this->endpoint( 'login' ) );
    }

    /**
     * @param string $code
     * @param string $redirect_uri
     * @param array  $args
     * @return array|WP_Error
     */
    public function token( string $code, string $redirect_uri, array $args = [] )
    {
        return wp_remote_post(
            $this->endpoint( 'oauth2/token' ),
            wp_parse_args( $args, [
                'headers'   => [
                    'Content-Type'  => 'application/x-www-form-urlencoded',
                    'Authorization' => $this->get_authorization_header(),
                ],
                'body'      => [
                    'grant_type'   => 'authorization_code',
                    'client_id'    => $this->get_client_id(),
                    'code'         => $code,
                    'redirect_uri' => $redirect_uri,
                ],
            ] )
        );
    }

    /**
     * @param string $path
     * @return string
     */
    protected function endpoint( string $path ) : string
    {
        return rtrim( $this->get_domain(), '/' ) . '/' . trim( $path, '/' );
    }
}
