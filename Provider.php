<?php

namespace SocialiteProviders\MinecraftEvoPixel;

use GuzzleHttp\RequestOptions;
use RuntimeException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'MCEVO';

    /**
     * Base URL for Minecraft EvoPixel.
     */
    protected const BASE_URL = 'https://minecraft.evopixel.ro';

    /**
     * {@inheritdoc}
     */
    protected $scopes = [
        'profile',
        'email',
    ];

    /**
     * {@inheritdoc}
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    protected $usesPKCE = true;

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        if ($this->isStateless() || !$this->clientId || strlen((string) $this->clientSecret) < 32) {
            throw new RuntimeException('Minecraft OAuth credentials are not configured.');
        }

        return $this->buildAuthUrlFromBase(
            static::BASE_URL.'/auth/oauth/authorize',
            $state
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null)
    {
        foreach (['state', 'client_id', 'redirect_uri', 'scope', 'response_type', 'code_challenge', 'code_challenge_method'] as $field) {
            if (array_key_exists($field, $this->parameters)) {
                throw new RuntimeException('Use the provider configuration for protected OAuth parameters.');
            }
        }

        return parent::getCodeFields($state);
    }

    /**
     * {@inheritdoc}
     */
    protected function hasInvalidState()
    {
        return parent::hasInvalidState() || ($this->request->input('iss') !== null && $this->request->input('iss') !== static::BASE_URL);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return static::BASE_URL.'/auth/oauth/token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get(
            static::BASE_URL.'/auth/oauth/userinfo',
            [
                RequestOptions::HEADERS => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::TIMEOUT => 10,
            ]
        );

        $user = json_decode((string) $response->getBody(), true);

        if ($response->getStatusCode() !== 200 || !is_array($user)) {
            throw new RuntimeException('Minecraft returned an invalid profile.');
        }

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenResponse($code)
    {
        return $this->tokenRequest($this->getTokenFields($code));
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        if (!is_string($user['id'] ?? null) || !preg_match('/^[a-z0-9_.]{3,32}$/D', $user['id'])) {
            throw new RuntimeException('Minecraft returned an invalid identity.');
        }

        $avatar = $user['avatar'] ?? null;

        if (!is_string($avatar) || !preg_match('#^https://mc-heads\.net/avatar/[a-zA-Z0-9_.-]{1,64}/160\.png$#D', $avatar)) {
            $avatar = null;
        }

        return (new User())->setRaw($user)->map([
            'id'       => $user['id'],
            'nickname' => is_string($user['nickname'] ?? null) ? $user['nickname'] : $user['id'],
            'name'     => is_string($user['name'] ?? null) ? $user['name'] : $user['id'],
            'email'    => is_string($user['email'] ?? null) ? (filter_var($user['email'], FILTER_VALIDATE_EMAIL) ?: null) : null,
            'avatar'   => $avatar,
        ]);
    }

    /**
     * Read a rotated token response without following redirects or retrying it.
     */
    public function getRefreshTokenResponse($refreshToken)
    {
        if (!is_string($refreshToken) || $refreshToken === '' || strlen($refreshToken) > 512) {
            throw new RuntimeException('A refresh token is required.');
        }

        $fields = ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken, 'client_id' => $this->clientId];
        if ($this->clientSecret !== null && $this->clientSecret !== '') {
            $fields['client_secret'] = $this->clientSecret;
        }

        $data = $this->tokenRequest($fields);
        if (!is_string($data['refresh_token'] ?? null) || $data['refresh_token'] === ''
            || !is_int($data['expires_in'] ?? null) || $data['expires_in'] < 1 || !is_string($data['scope'] ?? null)) {
            throw new RuntimeException('The server returned an invalid refresh token response.');
        }

        return $data;
    }

    /**
     * Revoke this client's token without closing the application's session.
     */
    public function revokeToken($token)
    {
        if (!is_string($token) || $token === '' || strlen($token) > 512) {
            throw new RuntimeException('A token is required.');
        }
        $fields = ['token' => $token, 'client_id' => $this->clientId];
        if ($this->clientSecret !== null && $this->clientSecret !== '') {
            $fields['client_secret'] = $this->clientSecret;
        }
        $response = $this->getHttpClient()->post(str_replace('/token', '/revoke', $this->getTokenUrl()), [
            RequestOptions::HEADERS => ['Accept' => 'application/json'], RequestOptions::FORM_PARAMS => $fields,
            RequestOptions::ALLOW_REDIRECTS => false, RequestOptions::TIMEOUT => 10,
        ]);
        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException('Token revocation failed.');
        }
    }

    /**
     * Use one bounded HTTP exchange for authorization codes and refresh tokens.
     */
    protected function tokenRequest(array $fields)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => ['Accept' => 'application/json'], RequestOptions::FORM_PARAMS => $fields,
            RequestOptions::ALLOW_REDIRECTS => false, RequestOptions::TIMEOUT => 10,
        ]);
        $body = (string) $response->getBody();
        $data = strlen($body) <= 1048576 ? json_decode($body, true) : null;
        if ($response->getStatusCode() !== 200 || !is_array($data)
            || !is_string($data['access_token'] ?? null) || $data['access_token'] === ''
            || preg_match('/[\x00-\x20\x7f]/', $data['access_token'])) {
            throw new RuntimeException('The server returned an invalid access token.');
        }

        return $data;
    }
}