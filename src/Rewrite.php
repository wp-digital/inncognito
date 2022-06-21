<?php

namespace Innocode\Cognito;

final class Rewrite
{
    /**
     * @param string $endpoint
     * @return void
     */
    public function init( string $endpoint )
    {
        add_rewrite_endpoint( $endpoint, EP_ROOT );

        $this->maybe_flush_rules();
    }

    /**
     * @return void
     */
    public function maybe_flush_rules()
    {
        if ( get_option( 'inncognito_rewrite_rules_flushed' ) ) {
            return;
        }

        $this->flush_rules();

        update_option( 'inncognito_rewrite_rules_flushed', current_time( 'mysql' ) );
    }

    /**
     * @return void
     */
    public function flush_rules()
    {
        flush_rewrite_rules();
    }

    /**
     * @return void
     */
    public function clear()
    {
        delete_option( 'inncognito_rewrite_rules_flushed' );
    }
}
