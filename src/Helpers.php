<?php

namespace Innocode\Cognito;

use stdClass;
use WP_Error;

class Helpers
{
    /**
     * @param WP_Error $error
     * @return void
     */
    public static function log_wp_error( WP_Error $error ) : void
    {
        error_log( "{$error->get_error_code()}: {$error->get_error_message()}" );
    }

    /**
     * @param stdClass $object
     * @return array
     */
    public static function object_to_array( stdClass $object ) : array
    {
        return json_decode( json_encode( $object ), true );
    }
}
