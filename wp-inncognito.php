<?php
/**
 * Plugin Name: Inncognito
 * Description: Login and Registration with user's AWS Cognito account.
 * Version: 1.7.0
 * Author: Innocode
 * Author URI: https://innocode.com
 * Tested up to: 6.0.2
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: inncognito
 */

if ( file_exists( __DIR__ . '/vendor/autoload.php' ) ) {
    require_once __DIR__ . '/vendor/autoload.php';
}

use Innocode\Cognito;

define( 'INNCOGNITO_VERSION', '1.7.0' );
define( 'INNCOGNITO_FILE', __FILE__ );

if (
    ! defined( 'INNCOGNITO_DOMAIN' ) ||
    ! defined( 'INNCOGNITO_CLIENT_ID' ) ||
    ! defined( 'INNCOGNITO_CLIENT_SECRET' ) ||
    ! defined( 'INNCOGNITO_REGION' ) ||
    ! defined( 'INNCOGNITO_USER_POOL_ID' )
) {
    return;
}

$GLOBALS['inncognito'] = new Cognito\Plugin(
    INNCOGNITO_DOMAIN,
    INNCOGNITO_CLIENT_ID,
    INNCOGNITO_CLIENT_SECRET,
    INNCOGNITO_REGION,
    INNCOGNITO_USER_POOL_ID
);

if ( defined( 'INNCOGNITO_REDIRECT_URI' ) ) {
    $GLOBALS['inncognito']
        ->get_api()
        ->set_redirect_uri( INNCOGNITO_REDIRECT_URI );
}

if ( ! defined( 'INNCOGNITO_ENDPOINT' ) ) {
    define( 'INNCOGNITO_ENDPOINT', 'inncognito' );
}

$GLOBALS['inncognito']
    ->get_query()
    ->set_endpoint( INNCOGNITO_ENDPOINT );

if ( ! defined( 'INNCOGNITO_COOKIE' ) ) {
    define( 'INNCOGNITO_COOKIE', 'inncognito' );
}

$GLOBALS['inncognito']
    ->get_session()
    ->set_cookie_name( INNCOGNITO_COOKIE );

if ( defined( 'INNCOGNITO_FORCE_COGNITO' ) && INNCOGNITO_FORCE_COGNITO ) {
    $GLOBALS['inncognito']->use_force_cognito( true );
}

if ( defined( 'INNCOGNITO_DISALLOW_REGISTRATION' ) && INNCOGNITO_DISALLOW_REGISTRATION ) {
    $GLOBALS['inncognito']->allow_registration( false );
}

$GLOBALS['inncognito']->run();

if ( ! function_exists( 'inncognito' ) ) {
    function inncognito() : ?Cognito\Plugin {
        global $inncognito;

        if ( is_null( $inncognito ) ) {
            trigger_error(
                'Missing required constants',
                E_USER_ERROR
            );
        }

        return $inncognito;
    }
}
