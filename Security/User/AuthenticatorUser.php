<?php

namespace Micayael\Authenticator\ClientBundle\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

class AuthenticatorUser implements UserInterface
{
    private $username;
    private $roles;

    public function __construct($username, array $roles)
    {
        $this->username = $username;
        $this->roles = $roles;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function getSalt()
    {
    }

    public function eraseCredentials()
    {
    }

    public function getPassword()
    {
    }
}
