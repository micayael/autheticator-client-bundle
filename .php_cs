<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__)
    ->exclude('vendor')
;

return PhpCsFixer\Config::create()
    ->setUsingCache(false)
    ->setRules([
        '@Symfony' => true,
        'phpdoc_var_without_name' => false,
    ])
    ->setFinder($finder)
;