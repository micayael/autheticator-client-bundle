<?php

namespace Micayael\Authenticator\ClientBundle\Security\User;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class AuthenticatorUserProvider implements UserProviderInterface
{
    public function loadUserByUsername($username)
    {
        // make a call to your webservice here
        return new AuthenticatorUser($username, []);
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof AuthenticatorUser) {
            throw new UnsupportedUserException(
                sprintf('Instances of "%s" are not supported.', get_class($user))
            );
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return AuthenticatorUser::class === $class;
    }
}
