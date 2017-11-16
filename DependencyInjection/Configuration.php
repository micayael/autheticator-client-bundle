<?php

namespace Micayael\Authenticator\ClientBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files.
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/configuration.html}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('authenticator_client');

        $rootNode
            ->children()
                ->scalarNode('token_uri')
                    ->info('URI del servicio para obtener tokens')
                    ->defaultValue('/api/jwt/token')
                    ->cannotBeEmpty()
                ->end()

                ->enumNode('type')
                    ->info('indica si la autenticación contra el servicio del Authenticator debe ser usando basic authentication o app_id')
                    ->values(array('basic_auth', 'app_id'))
                    ->isRequired()
                ->end()

                ->scalarNode('change_password_url')
                    ->info('indica la url del authenticator para que el usuario solicite nuevamente su password')
                    ->isRequired()
                ->end()

                ->arrayNode('basic_auth')
                    ->cannotBeEmpty()
                    ->children()
                        ->scalarNode('username')
                            ->info('Usuario para autenticación por basic authentication')
                            ->cannotBeEmpty()
                        ->end()
                        ->scalarNode('password')
                            ->info('Password para autenticación por basic authentication')
                            ->cannotBeEmpty()
                        ->end()
                    ->end()
                ->end()

                ->scalarNode('app_id')
                    ->info('AppId para conexión en caso de haber seleccionado esta forma de autenticación')
                    ->cannotBeEmpty()
                ->end()

                ->scalarNode('default_target_route')
                    ->info('Ruta predeterminada para ingresar después de un login si no existe referrer')
                    ->defaultValue('admin')
                    ->cannotBeEmpty()
                ->end()
            ->end()
        ;

        return $treeBuilder;
    }
}
