<?php

namespace Innocode\Cognito\Integrations\GoogleAuthenticator;

use Innocode\Cognito\Interfaces\IntegrationInterface;
use Innocode\Cognito\Plugin;
use Innocode\Cognito\User;
use WP_User;

class Integration implements IntegrationInterface
{
    /**
     * @param Plugin $plugin
     * @return void
     */
    public function run( Plugin $plugin ) : void
    {
        add_filter( 'get_user_option_googleauthenticator_enabled', [ $this, 'force_disabled' ], 10, 3 );
    }

    /**
     * @param mixed   $result
     * @param string  $option
     * @param WP_User $user
     * @return string
     */
    public function force_disabled( $result, string $option, WP_User $user ) : string
    {
        return $result === 'enabled' && User::is_inncognito( $user->ID ) ? 'disabled' : $result;
    }
}
