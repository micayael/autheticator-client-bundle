Authenticator Client Bundle
===========================

Instalación del bundle
----------------------

### Agregar al composer.json
~~~
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/micayael/autheticator-client-bundle.git"
        }
    ],
    "require": {
        ...
        "micayael/autheticator-client-bundle": "dev-master"
    },
~~~

### Activación del bundle en el AppKernel.php

~~~
        $bundles = [
            ...
            new Csa\Bundle\GuzzleBundle\CsaGuzzleBundle(),
            new Micayael\Authenticator\ClientBundle\AuthenticatorClientBundle(),
            ...
        ];
~~~

### Configuración del guzzle para consultar el servicio del authenticator

~~~
csa_guzzle:
    profiler: '%kernel.debug%'
    logger: true
    clients:
        authenticator:
            config:
                base_uri: http://localhost:8001
                headers:
                    "Content-Type": application/json
~~~

### Configuración del bundle

~~~
authenticator_client:
    token_uri: /api/jwt/token
    default_target_route: admin # opcional, default: admin
    change_password_url: http://authenticator_url/admin/resetting/request
    type: basic_auth
    basic_auth:
        username: app1
        password: app1
~~~

o

~~~
authenticator_client:
    token_uri: /api/jwt/token
    change_password_url: http://authenticator_url/admin/resetting/request
    type: app_id
    app_id: app2_id_test
~~~

### Publicación de assets

~~~
bin/console assets:install --relative --symlink
~~~

### Importación de rutas en el archivo routing.yml

~~~
authenticator:
    resource: "@AuthenticatorClientBundle/Resources/config/routing.yml"
    prefix: /
~~~

### Configuración del security

~~~
    providers:
        authenticator:
            id: 'authenticator_client.authenticator_user_provider'

    encoders:
        AppBundle\Security\User\AuthenticatorUser: plaintext

    firewalls:
        main:
            anonymous: ~
            logout:
                path: /logout

            guard:
                authenticators:
                    - 'authenticator_client.login_form_authenticator'

    access_control:
        - { path: ^/login, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        - { path: ^/admin, roles: ROLE_USER }
~~~

Documentación Extra
-------------------

- Para definir tiempo de vida y nombre de la sesión:  https://symfony.com/doc/current/reference/configuration/framework.html#session
- En caso de que ocurra un error se puede apuntar en la configuración del
csa_guzzle al entorno de desarrollo del authenticator
base_uri: http://localhost:8001/app_dev.php y para ver los datos se puede cambiar la
configuración dentro del config_dev.yml de la aplicación cliente para que intercepte
las redirecciones intercept_redirects: true

Referencias
-----------

- https://knpuniversity.com/screencast/symfony-security