# Socialite Providers Minecraft EvoPixel

Minecraft EvoPixel OAuth2 provider for Laravel Socialite

This provider authenticates Minecraft EvoPixel accounts, not Microsoft or Mojang accounts.

```bash
composer require evopixel/socialiteproviders-minecraft-evopixel
```

## Installation & Basic Usage

Please see the [Base Installation Guide](https://socialiteproviders.com/usage/), then follow the provider specific instructions below.

Requires PHP 7.4 or 8.x, SocialiteProviders Manager 4.x from 4.3, and Laravel Socialite 5.2.1 or later for PKCE. Composer installs compatible dependencies.

### Add configuration to `config/services.php`

```php
'mcevo' => [
    'client_id' => env('MINECRAFT_EVOPIXEL_CLIENT_ID'),
    'client_secret' => env('MINECRAFT_EVOPIXEL_CLIENT_SECRET'),
    'redirect' => env('MINECRAFT_EVOPIXEL_REDIRECT_URI'),
],
```

Use the client ID, secret and callback URL registered for your **Web** application with Minecraft EvoPixel. Keep the secret on the server and make sure the HTTPS callback URL matches exactly.

### Add provider event listener

Configure the package's listener to listen for `SocialiteWasCalled` events.

#### Laravel 11+

Register the listener in the `boot()` method of `App\Providers\AppServiceProvider`:

```php
\Illuminate\Support\Facades\Event::listen(function (\SocialiteProviders\Manager\SocialiteWasCalled $event) {
    $event->extendSocialite('mcevo', \SocialiteProviders\MinecraftEvoPixel\Provider::class);
});
```

#### Laravel 10 or below

Add the event to your `listen[]` array in `app/Providers/EventServiceProvider`. See the [Base Installation Guide](https://socialiteproviders.com/usage/) for detailed instructions.

```php
protected $listen = [
    \SocialiteProviders\Manager\SocialiteWasCalled::class => [
        // ... other providers
        \SocialiteProviders\MinecraftEvoPixel\MinecraftEvoPixelExtendSocialite::class.'@handle',
    ],
];
```

### Usage

You should now be able to use the provider like you would regularly use Socialite (assuming you have the facade installed):

```php
return Socialite::driver('mcevo')->redirect();
```

Retrieve the authenticated user in your callback:

```php
$user = Socialite::driver('mcevo')->user();
```

Both routes must use session middleware. Keep the session between redirect and callback for state and S256 PKCE validation; do not use `stateless()` for this flow. Handle rejected authorization and failed requests through your application's authentication error flow.

The default scopes are `profile` and `email`. Use `setScopes(['profile'])` before `redirect()` if email is not needed.

This package uses a Web OAuth client, with credentials and the callback handled by Laravel. A SPA frontend can use this flow through its Laravel backend; keep the client secret and OAuth tokens on the server.

### Returned User fields

- `id`
- `nickname`
- `name`
- `email`
- `avatar`

`id` is the lowercase AuthMe username; `nickname` is the stored username. `name` uses the stored display name when available, otherwise the username. The `profile` scope is required; email additionally requires `email`. The email and avatar may be `null`. The complete response is available through `$user->getRaw()`, including `email_verified`; Minecraft email is not treated as verified. Use the provider and `id` to identify linked accounts. Renaming an AuthMe account changes its identity and requires relinking.

### Refresh tokens and revocation

The resulting Socialite user exposes `refreshToken` when refresh access is enabled for the registered client and granted by the server. Use the `profile` and `email` scopes; Minecraft does not use `offline_access` or `access_type=offline`.

Refresh tokens renew API access. Your application manages its own session. Access tokens expire after five minutes.

```php
$tokens = Socialite::driver('mcevo')->getRefreshTokenResponse($storedRefreshToken);
// Replace both stored tokens atomically; each refresh token can be used once.
$accessToken = $tokens['access_token'];
$refreshToken = $tokens['refresh_token'];
```

Serialize refresh requests for the same authorization. Do not retry a consumed token: reuse revokes its token family. If the request fails or its outcome is unknown, authorize again. Store tokens encrypted on the server and never place them in URLs or logs.

`getRefreshTokenResponse()` returns the complete response array on all supported versions. If your Laravel Socialite version provides `refreshToken()`, you can also use that method to receive a token object. Both methods retain the granted scopes.

`revokeToken($token)` accepts an access or refresh token. Revocation does not close your Laravel session; handle local logout in your application.

Minecraft OAuth uses only `profile` and `email`. This provider does not request OpenID Connect ID tokens or central OIDC logout.
