# Inncognito

### Description

Login and Registration with user's AWS Cognito account.

### Install

- Preferable way is to use [Composer](https://getcomposer.org/):

    ````
    composer require innocode-digital/wp-inncognito
    ````

  By default, it will be installed as [Must Use Plugin](https://codex.wordpress.org/Must_Use_Plugins).
  It's possible to control with `extra.installer-paths` in `composer.json`.

- Alternate way is to clone this repo to `wp-content/mu-plugins/` or `wp-content/plugins/`:

    ````
    cd wp-content/plugins/
    git clone git@github.com:innocode-digital/wp-inncognito.git
    cd wp-inncognito/
    composer install
    ````

If plugin was installed as regular plugin then activate **AWS Lambda Prerender** from Plugins page
or [WP-CLI](https://make.wordpress.org/cli/handbook/): `wp plugin activate wp-inncognito`.

### Configuration

Add the following constants to `wp-config.php`:

````
define( 'INNCOGNITO_DOMAIN', '' ); // Either domain or fully qualified URL (Cognito or custom).
define( 'INNCOGNITO_CLIENT_ID', '' );
define( 'INNCOGNITO_CLIENT_SECRET', '' );
define( 'INNCOGNITO_REGION', '' ); // e.g. eu-west-1
define( 'INNCOGNITO_USER_POOL_ID', '' );
````

### Usage

Force users to log in with their AWS Cognito account. Works for users who were logged in with SSO at
least once.

```
define( 'INNCOGNITO_FORCE_COGNITO', true );
```

---

Disable registration through AWS Cognito during SSO.

````
define( 'INNCOGNITO_DISALLOW_REGISTRATION', true );
````
