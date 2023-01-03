<?php

namespace Innocode\Cognito;

class Query
{
    /**
     * @var string
     */
    protected $endpoint;
    /**
     * @var array
     */
    protected $vars = [];

    /**
     * @param string $endpoint
     *
     * @return void
     */
    public function set_endpoint( string $endpoint ) : void
    {
        $this->endpoint = $endpoint;
    }

    /**
     * @return string
     */
    public function get_endpoint() : string
    {
        return $this->endpoint;
    }

    /**
     * @return array
     */
    public function get_vars() : array
    {
        return $this->vars;
    }

    /**
     * @param string $name
     * @return mixed|null
     */
    public function get_var( string $name )
    {
        $vars = $this->get_vars();

        return $vars[ $name ] ?? null;
    }

    /**
     * @return string|null
     */
    public function value() : ?string
    {
        return get_query_var( $this->get_endpoint(), null );
    }

    /**
     * @return bool
     */
    public function exists() : bool
    {
        return null !== $this->value();
    }

    /**
     * @return bool
     */
    public function is_root() : bool
    {
        return '' === $this->value();
    }

    /**
     * @return bool
     */
    public function is_token() : bool
    {
        return 'token' == $this->value();
    }

    /**
     * @param string $value
     * @return string
     */
    public function path( string $value = '' ) : string
    {
        return trailingslashit( "/{$this->get_endpoint()}/" . ltrim( $value, '/' ) );
    }

    /**
     * @param string      $value
     * @param string|null $redirect_to
     * @return string
     */
    public function url( string $value = '', string $redirect_to = null ) : string
    {
        if ( null !== $redirect_to ) {
            $redirect_to = rawurlencode( $redirect_to );
        }

        $url = rtrim( home_url(), '/' ) . $this->path( $value );

        return add_query_arg( 'redirect_to', $redirect_to, $url );
    }

    /**
     * @return void
     */
    public function parse() : void
    {
        if ( isset( $_GET['code'] ) ) {
            $this->vars['code'] = $_GET['code'];
        }

        if ( isset( $_GET['state'] ) ) {
            $this->vars['state'] = $_GET['state'];
        }

        if ( isset( $_GET['redirect_to'] ) ) {
            $this->vars['redirect_to'] = esc_url_raw( $_GET['redirect_to'] );
        }
    }
}
