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

    protected function getLoginUrl()
    {
        return $this->router->generate('authenticator_security_login');
    }

    /**
     * Does the authenticator support the given Request?
     *
     * If this returns false, the authenticator will be skipped.
     *
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request)
    {
        return false !== strpos($this->getLoginUrl(), $request->getPathInfo()) && $request->isMethod('POST');
    }

    /**
     * Get the authentication credentials from the request and return them
     * as any type (e.g. an associate array).
     *
     * Whatever value you return here will be passed to getUser() and checkCredentials()
     *
     * For example, for a form login, you might:
     *
     *      return array(
     *          'username' => $request->request->get('_username'),
     *          'password' => $request->request->get('_password'),
     *      );
     *
     * Or for an API token that's on a header, you might use:
     *
     *      return array('api_key' => $request->headers->get('X-API-TOKEN'));
     *
     * @param Request $request
     *
     * @return mixed Any non-null value
     *
     * @throws \UnexpectedValueException If null is returned
     */
    public function getCredentials(Request $request)
    {
        if(!$this->supports($request)){
            return false;
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

    /**
     * Return a UserInterface object based on the credentials.
     *
     * The *credentials* are the return value from getCredentials()
     *
     * You may throw an AuthenticationException if you wish. If you return
     * null, then a UsernameNotFoundException is thrown for you.
     *
     * @param mixed                 $credentials
     * @param UserProviderInterface $userProvider
     *
     * @throws AuthenticationException
     *
     * @return UserInterface|null
     */
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

    /**
     * Returns true if the credentials are valid.
     *
     * If any value other than true is returned, authentication will
     * fail. You may also throw an AuthenticationException if you wish
     * to cause authentication to fail.
     *
     * The *credentials* are the return value from getCredentials()
     *
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     *
     * @throws AuthenticationException
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        // Retorna siempre true porque con el método getUser ya se valida la autenticación del usuario
        // contra el servicio
        return true;
    }

    /**
     * Called when authentication executed and was successful!
     *
     * This should return the Response sent back to the user, like a
     * RedirectResponse to the last page they visited.
     *
     * If you return null, the current request will continue, and the user
     * will be authenticated. This makes sense, for example, with an API.
     *
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey The provider (i.e. firewall) key
     *
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);

        if (!$targetPath) {
            $targetPath = $this->router->generate($this->configs['default_target_route']);
        }

        return new RedirectResponse($targetPath);
    }

    /**
     * Does this method support remember me cookies?
     *
     * Remember me cookie will be set if *all* of the following are met:
     *  A) This method returns true
     *  B) The remember_me key under your firewall is configured
     *  C) The "remember me" functionality is activated. This is usually
     *      done by having a _remember_me checkbox in your form, but
     *      can be configured by the "always_remember_me" and "remember_me_parameter"
     *      parameters under the "remember_me" firewall key
     *  D) The onAuthenticationSuccess method returns a Response object
     *
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }
}
