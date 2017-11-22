<?php

namespace Micayael\Authenticator\ClientBundle\Security;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use Lcobucci\JWT\Parser;
use Micayael\Authenticator\ClientBundle\Form\LoginForm;
use Micayael\Authenticator\ClientBundle\Security\User\AuthenticatorUser;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\Authenticator\AbstractFormLoginAuthenticator;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class LoginFormAuthenticator extends AbstractFormLoginAuthenticator
{
    use TargetPathTrait;

    private $formFactory;
    private $router;
    private $authenticatorClient;
    private $configs;

    public function __construct(FormFactoryInterface $formFactory, RouterInterface $router, Client $csa_guzzleClientAuthenticator, $configs)
    {
        $this->formFactory = $formFactory;
        $this->router = $router;
        $this->authenticatorClient = $csa_guzzleClientAuthenticator;
        $this->configs = $configs;
    }

    public function getCredentials(Request $request)
    {
        $loginPath = $this->getLoginUrl();
        // Para eliminar el app_dev.php en caso de ser otro environment diferente a producción
        $loginPath = substr($loginPath, strrpos($loginPath, '/'));

        $isLoginSubmit = $request->getPathInfo() == $loginPath && $request->isMethod('POST');

        if (!$isLoginSubmit) {
            return;
        }

        $form = $this->formFactory->create(LoginForm::class);
        $form->handleRequest($request);
        $data = $form->getData();

        $request->getSession()->set(
            Security::LAST_USERNAME,
            $data['_username']
        );

        return $data;
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try {
            $config_token_uri = $this->configs['host'] . $this->configs['token_uri'];

            $jsonContentToSend = null;

            if ($this->configs['type'] === 'basic_auth') {
                $jsonContentToSend = [
                    'auth' => [$this->configs['basic_auth']['username'], $this->configs['basic_auth']['password']],
                    'json' => [
                        'username' => $credentials['_username'],
                        'password' => $credentials['_password'],
                    ],
                ];
            } else {
                $jsonContentToSend = [
                    'json' => [
                        'username' => $credentials['_username'],
                        'password' => $credentials['_password'],
                        'app_id' => $this->configs['app_id'],
                    ],
                ];
            }

            $serviceResponse = $this->authenticatorClient->request('post', $config_token_uri, $jsonContentToSend);

            $tokenString = json_decode($serviceResponse->getBody())->token;

            $token = (new Parser())->parse((string) $tokenString);

            $roles = ['ROLE_USER'];

            if($token->getClaim('super_admin')){
                $roles[] = 'ROLE_ADMIN';
            }

            foreach ($token->getClaim('permisos') as $permiso) {
                $roles[] = 'ROLE_'.strtoupper($permiso);
            }

            return new AuthenticatorUser($token->getClaim('username'), $roles);
        } catch (ConnectException $e) {
            throw new AuthenticationException('No fue posible autenticar al usuario');
        } catch (RequestException $e) {
            return null;
        }
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);

        if (!$targetPath) {
            $targetPath = $this->router->generate($this->configs['default_target_route']);
        }

        return new RedirectResponse($targetPath);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        // Retorna siempre true porque con el método getUser ya se valida la autenticación del usuario
        // contra el servicio
        return true;
    }

    protected function getLoginUrl()
    {
        return $this->router->generate('authenticator_security_login');
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
