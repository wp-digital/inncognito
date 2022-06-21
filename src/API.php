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
     * @var string|null
     */
    protected $redirect_uri = null;

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
     * @return void
     */
    public function set_redirect_uri( string $redirect_uri )
    {
        $this->redirect_uri = $redirect_uri;
    }

    /**
     * @return string|null
     */
    public function get_redirect_uri()
    {
        return $this->redirect_uri;
    }

    /**
     * @param string      $callback_url
     * @param string      $state
     * @param string|null $scope
     * @return string
     */
    public function login_url( string $callback_url, string $state, string $scope = null ) : string
    {
        if ( null === ( $redirect_uri = $this->get_redirect_uri() ) ) {
            $redirect_uri = $callback_url;
        } else {
            $state .= '+' . rawurlencode( $callback_url );
        }

        return add_query_arg( [
            'response_type' => 'code',
            'client_id'     => $this->get_client_id(),
            'redirect_uri'  => rawurlencode( $redirect_uri ),
            'state'         => $state,
            'scope'         => $scope,
        ], $this->endpoint( 'login' ) );
    }

    /**
     * @param string $code
     * @param string $callback_url
     * @param array  $args
     * @return array|WP_Error
     */
    public function token( string $code, string $callback_url, array $args = [] )
    {
        return wp_remote_post(
            $this->endpoint( 'oauth2/token' ),
            wp_parse_args( $args, [
                'timeout'   => 30,
                'headers'   => [
                    'Content-Type'  => 'application/x-www-form-urlencoded',
                    'Authorization' => $this->get_authorization_header(),
                ],
                'body'      => [
                    'grant_type'   => 'authorization_code',
                    'client_id'    => $this->get_client_id(),
                    'code'         => $code,
                    'redirect_uri' => null !== ( $redirect_uri = $this->get_redirect_uri() )
                        ? $redirect_uri
                        : $callback_url,
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
