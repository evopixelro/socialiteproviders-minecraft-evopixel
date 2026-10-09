<?php

namespace SocialiteProviders\MinecraftEvoPixel;

use SocialiteProviders\Manager\SocialiteWasCalled;

class MinecraftEvoPixelExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite('mcevo', Provider::class);
    }
}
