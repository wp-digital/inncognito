<?php

namespace Innocode\Cognito\Integrations\Polylang;

use Innocode\Cognito\Interfaces\IntegrationInterface;
use Innocode\Cognito\Plugin;

class Integration implements IntegrationInterface
{
    /**
     * @var Plugin
     */
    protected $plugin;

    /**
     * @return Plugin
     */
    public function get_plugin() : Plugin
    {
        return $this->plugin;
    }

    /**
     * @param Plugin $plugin
     * @return void
     */
    public function run( Plugin $plugin ) : void
    {
        $this->plugin = $plugin;

        add_filter( 'pll_modify_rewrite_rule', [ $this, 'pll_modify_rewrite_rule' ], 10, 3 );
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

        return $regex != "{$this->get_plugin()->get_query()->get_endpoint()}(/(.*))?/?$";
    }
}
