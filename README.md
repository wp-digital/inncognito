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
    git clone git@github.com:innocode-digital/inncognito.git
    cd inncognito/
    composer install
    ````

If plugin was installed as regular plugin then activate **AWS Lambda Prerender** from Plugins page
or [WP-CLI](https://make.wordpress.org/cli/handbook/): `wp plugin activate inncognito`.

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

Change callback URL:

```
define( 'INNCOGNITO_REDIRECT_URI', 'https://another-site.com/login/' );
```

Use case could be when e.g. you do not want to be limited with callback URL requirement
(it's required to set all callbacks in Cognito settings) but want to use one with custom
redirects handling.

---

Change login URL to custom endpoint:

```
define( 'INNCOGNITO_ENDPOINT', 'cognito' ); // default: 'inncognito'
```

---

Change session cookie name:

```
define( 'INNCOGNITO_COOKIE', 'cognito' ); // default: 'inncognito'
```

Session is used to handle actions and redirects, prevent CSRF attacks.

---

Force users to log in with their AWS Cognito account:

```
define( 'INNCOGNITO_FORCE_COGNITO', true );
```

Works for users who were logged in with SSO at least once.

---

Disable registration through AWS Cognito during SSO:

````
define( 'INNCOGNITO_DISALLOW_REGISTRATION', true );
````
