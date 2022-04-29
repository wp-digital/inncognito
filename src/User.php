<?php

namespace Innocode\Cognito;

use WP_Error;
use WP_User;

final class User
{
    /**
     * @param array $data
     * @return int|WP_Error
     */
    public static function create_from_jwt( array $data )
    {
        $username = '';

        if ( isset( $data['preferred_username'] ) ) {
            $username = $data['preferred_username'];
        } elseif ( isset( $data['username'] ) ) {
            $username = $data['username'];
        }

        if ( ! $username && isset( $data['email'] ) ) {
            $username = $data['email'];
        }

        $username = sanitize_user( $username, true );
        $base_username = $username;

        while ( username_exists( $username ) ) {
            $username = uniqid( $base_username );
        }

        $userdata = [
            'user_login' => $username,
            'user_email' => $data['email'] ?? '',
            'user_pass'  => wp_generate_password( 32 ),
        ];

        if ( isset( $data['website'] ) ) {
            $userdata['user_url'] = $data['website'];
        }

        if ( isset( $data['name'] ) ) {
            $userdata['display_name'] = $data['name'];
        }

        if ( isset( $data['nickname'] ) ) {
            $userdata['nickname'] = $data['nickname'];
        }

        if ( isset( $data['given_name'] ) ) {
            $userdata['first_name'] = $data['given_name'];
        }

        if ( isset( $data['family_name'] ) ) {
            $userdata['last_name'] = $data['family_name'];
        }

        $is_super_admin = false;

        if ( ! empty( $data['cognito:groups'] ) && is_array( $data['cognito:groups'] ) ) {
            foreach ( $data['cognito:groups'] as $group ) {
                if ( $group == 'super_admin' ) {
                    $userdata['role'] = 'administrator';
                    $is_super_admin = true;

                    break;
                }

                if ( null !== ( $role = get_role( $group ) ) ) {
                    $userdata['role'] = $role->name;

                    break;
                }
            }
        }

        $user_id = wp_insert_user( $userdata );

        if ( is_wp_error( $user_id ) ) {
            return $user_id;
        }

        User::inncognitize( $user_id );

        if ( $is_super_admin ) {
            grant_super_admin( $user_id );
        }

        return $user_id;
    }

    /**
     * @param string $username
     * @return WP_Error|WP_User
     */
    public static function no_password_sign_in( string $username )
    {
        $authenticate = function ( $user, string $username ) {
            return ! ( $user instanceof WP_User ) && ! empty( $username )
                ? User::find_user( $username )
                : $user;
        };

        add_filter( 'authenticate', $authenticate, 10, 2 );

        $user = wp_signon( [
            'user_login' => $username,
            'remember'   => true,
        ] );

        remove_filter( 'authenticate', $authenticate );

        if ( ! is_wp_error( $user ) ) {
            wp_set_current_user( $user->ID );
        }

        return $user;
    }

    /**
     * @param string $username
     * @return WP_User|null
     */
    public static function find_user( string $username ) : ?WP_User
    {
        $user = get_user_by( 'login', $username );

        if ( $user instanceof WP_User ) {
            return $user;
        }

        $user = get_user_by( 'email', $username );

        return $user ?: null;
    }

    /**
     * @param int $user_id
     * @return bool
     */
    public static function is_inncognito( int $user_id ) : bool
    {
        return (bool) get_user_meta( $user_id, 'inncognito', true );
    }

    /**
     * @param int $user_id
     * @return void
     */
    public static function inncognitize( int $user_id ) : void
    {
        update_user_meta( $user_id, 'inncognito', current_time( 'mysql' ) );
    }

    /**
     * @param int $user_id
     * @return string
     */
    public static function admin_url( int $user_id ) : string
    {
        if ( is_multisite() && ! get_active_blog_for_user( $user_id ) && ! is_super_admin( $user_id ) ) {
            return user_admin_url();
        }

        if ( is_multisite() && ! user_can( $user_id, 'read' ) ) {
            return get_dashboard_url( $user_id );
        }

        if ( ! user_can( $user_id, 'edit_posts' ) ) {
            return user_can( $user_id, 'read' ) ? admin_url( 'profile.php' ) : home_url();
        }

        return admin_url();
    }
}
