<?php

namespace SocialiteProviders\MinecraftEvoPixel\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Laravel\Socialite\Two\InvalidStateException;
use Mockery;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SocialiteProviders\Manager\SocialiteWasCalled;
use SocialiteProviders\MinecraftEvoPixel\MinecraftEvoPixelExtendSocialite;
use SocialiteProviders\MinecraftEvoPixel\Provider;

class ProviderTest extends TestCase
{
    protected $request;
    protected $session;
    protected $provider;

    protected function setUp(): void
    {
        $this->session = new Store('minecraft-test', new ArraySessionHandler(120));
        $this->session->start();
        $this->request = Request::create('/callback?state=expected&code=code');
        $this->request->setLaravelSession($this->session);
        $this->provider = new Provider($this->request, 'client', str_repeat('s', 64), 'https://app.example/callback');
    }

    protected function tearDown(): void
    {
        Mockery::close();
    }

    public function testRedirectUsesTheFixedEndpointWithStateAndS256Pkce()
    {
        $url = $this->provider->redirect()->getTargetUrl();
        $this->assertSame('https://minecraft.evopixel.ro/auth/oauth/authorize', strtok($url, '?'));
        parse_str(parse_url($url, PHP_URL_QUERY), $fields);
        $this->assertSame('client', $fields['client_id']);
        $this->assertSame('https://app.example/callback', $fields['redirect_uri']);
        $this->assertSame('profile email', $fields['scope']);
        $this->assertSame('code', $fields['response_type']);
        $this->assertNotEmpty($fields['state']);
        $this->assertSame($this->session->get('state'), $fields['state']);
        $this->assertSame('S256', $fields['code_challenge_method']);
        $this->assertSame(rtrim(strtr(base64_encode(hash('sha256', $this->session->get('code_verifier'), true)), '+/', '-_'), '='), $fields['code_challenge']);
    }

    public function testInvalidStateDoesNotContactTheServer()
    {
        $this->session->put('state', 'different');
        $this->provider->setHttpClient(new Client(['handler' => function () {
            $this->fail('Invalid state must not send an HTTP request.');
        }]));
        $this->expectException(InvalidStateException::class);
        $this->provider->user();
    }

    public function testTokenExchangeUsesTheVerifierAndReadsTheAuthenticatedProfile()
    {
        $this->session->put(['state' => 'expected', 'code_verifier' => str_repeat('v', 64)]);
        $history = [];
        $handler = HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['access_token' => 'token', 'expires_in' => 300])),
            new Response(200, [], json_encode([
                'id' => 'player', 'nickname' => 'Player', 'name' => 'Player',
                'email' => 'player@example.test', 'email_verified' => false,
                'avatar' => 'https://mc-heads.net/avatar/player/160.png',
            ])),
        ]));
        $handler->push(Middleware::history($history));
        $this->provider->setHttpClient(new Client(['handler' => $handler]));
        $user = $this->provider->user();
        $this->assertSame('player', $user->getId());
        $this->assertSame('Player', $user->getNickname());
        $this->assertSame('Player', $user->getName());
        $this->assertSame('player@example.test', $user->getEmail());
        $this->assertFalse($user->getRaw()['email_verified']);
        $this->assertSame('https://mc-heads.net/avatar/player/160.png', $user->getAvatar());
        $this->assertSame('https://minecraft.evopixel.ro/auth/oauth/token', (string) $history[0]['request']->getUri());
        $this->assertSame('https://minecraft.evopixel.ro/auth/oauth/userinfo', (string) $history[1]['request']->getUri());
        parse_str((string) $history[0]['request']->getBody(), $fields);
        $this->assertSame('code', $fields['code']);
        $this->assertSame('client', $fields['client_id']);
        $this->assertSame(str_repeat('s', 64), $fields['client_secret']);
        $this->assertSame(str_repeat('v', 64), $fields['code_verifier']);
        $this->assertSame('authorization_code', $fields['grant_type']);
        $this->assertSame('Bearer token', $history[1]['request']->getHeaderLine('Authorization'));
        $this->assertFalse($history[0]['options']['allow_redirects']);
        $this->assertFalse($history[1]['options']['allow_redirects']);
        $this->assertNull($this->session->get('code_verifier'));
        $this->assertNull($this->session->get('state'));
    }

    public function testMissingEmailAndInvalidOptionalFieldsDoNotBecomeTrustedProfileData()
    {
        $this->profileResponse(['id' => 'player', 'nickname' => [], 'name' => [], 'email' => [], 'avatar' => 'http://untrusted.example/avatar.png']);
        $user = $this->provider->userFromToken('token');
        $this->assertSame('player', $user->getName());
        $this->assertSame('player', $user->getNickname());
        $this->assertNull($user->getEmail());
        $this->assertNull($user->getAvatar());
    }

    /**
     * @dataProvider invalidProfiles
     */
    public function testInvalidProfilesAreRejected($body)
    {
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], $body)]))]));
        $this->expectException(RuntimeException::class);
        $this->provider->userFromToken('token');
    }

    public function invalidProfiles()
    {
        return [['not-json'], ['null'], ['{}'], ['{"id":123}'], ['{"id":"<script>"}']];
    }

    public function testInvalidTokenResponseDoesNotRequestAProfile()
    {
        $this->session->put(['state' => 'expected', 'code_verifier' => str_repeat('v', 64)]);
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], '{}')]))]));
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('invalid access token');
        $this->provider->user();
    }

    public function testRejectedTokensDoNotAuthenticate()
    {
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(401)]))]));
        $this->expectException(ClientException::class);
        $this->provider->userFromToken('invalid');
    }

    public function testMissingCredentialsCannotStartAuthorization()
    {
        $provider = new Provider($this->request, 'client', '', 'https://app.example/callback');
        $this->expectException(RuntimeException::class);
        $provider->redirect();
    }

    public function testListenerRegistersTheExistingMcevoDriver()
    {
        $event = Mockery::mock(SocialiteWasCalled::class);
        $event->shouldReceive('extendSocialite')->once()->with('mcevo', Provider::class);
        (new MinecraftEvoPixelExtendSocialite())->handle($event);
        $this->addToAssertionCount(1);
    }

    protected function profileResponse(array $profile)
    {
        $this->provider->setHttpClient(new Client(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode($profile)),
        ]))]));
    }
}
