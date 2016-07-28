import "hash"

private rule Symfony : CMS
{
    meta:
        generated = "2016-07-27T18:00:53.795037"

    condition:
        /* Symfony 2.0.0 */
        hash.sha1(0, filesize) == "6163f3511d50461762aa74a95edb8a343783e30a" or // src/Symfony/Component/Process/ExecutableFinder.php
        hash.sha1(0, filesize) == "79ec09fff79c959a6742e654999fda719f418f14" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "4cbb162e37b6b50a2bbc2538f2999e43cfab2373" or // src/Symfony/Component/Security/Http/EntryPoint/RetryAuthenticationEntryPoint.php
        hash.sha1(0, filesize) == "85eabed3f3f536cd15361a16e48b9eb5fdaa856b" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "d64d0d344a19d88f22f6292aa4ce325e0fb4ef05" or // src/Symfony/Component/Locale/Stub/StubLocale.php

        /* Symfony 2.0.1 */
        hash.sha1(0, filesize) == "35784dc8039ae772123778e95859091d1cfb5877" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php

        /* Symfony 2.0.2 */
        hash.sha1(0, filesize) == "1f702e4984de7e4d459d39150c37938fe43493d0" or // src/Symfony/Component/Process/ExecutableFinder.php

        /* Symfony 2.0.5 */
        hash.sha1(0, filesize) == "52e7120bb25cd72b09319ef1d361497b62546017" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 2.0.7 */
        hash.sha1(0, filesize) == "3d842e49d31e30da2222fa25374050fb20aa9696" or // src/Symfony/Component/Security/Http/EntryPoint/RetryAuthenticationEntryPoint.php

        /* Symfony 2.0.8 */
        hash.sha1(0, filesize) == "60d33340cf687cc00f4a120a04348ec4f96924d8" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "5df2046aa9769b9a84046bf79afccf20e2a8f363" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "a3d61ab7fb861051e745de22a582d76025e50f09" or // src/Symfony/Component/Locale/Stub/StubLocale.php

        /* Symfony 2.0.10 */
        hash.sha1(0, filesize) == "2fb648e3000a93047da08cdea266567eaa4639f7" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 2.0.13 */
        hash.sha1(0, filesize) == "e0d8ce8ebe492c25e20e3cfd5a15801f81c3c063" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "bfd9ed6ac31beaf82b8f7ed2e90022746ba5189b" or // src/Symfony/Component/Locale/Stub/StubLocale.php

        /* Symfony 2.0.14 */
        hash.sha1(0, filesize) == "dc8dd695d20e11869ae5dd166dc18c392f861873" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "ddba591ab4299da26b73b182d5a0f644d4648bf1" or // src/Symfony/Component/Locale/Stub/StubLocale.php

        /* Symfony 2.0.15 */
        hash.sha1(0, filesize) == "9bb2498e325307d0ed937cad815e307eee637a53" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "ffbb92ae550aa33507c75b44d7cf697327cde6f6" or // src/Symfony/Component/Locale/Stub/StubLocale.php

        /* Symfony 2.0.16 */
        hash.sha1(0, filesize) == "1f18cd13a17715f032bf31d1773423aa8e00c3d3" or // src/Symfony/Component/Locale/Stub/StubLocale.php

        /* Symfony 2.0.17 */
        hash.sha1(0, filesize) == "45c3a716928da5f58f02184953bb593b2980db5e" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "60a0574dac77cf2ca6bbafd48eb3185a86a2240f" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php

        /* Symfony 2.0.18 */
        hash.sha1(0, filesize) == "56b90e28b88f9bba9ffe3bae22ed8cf39a6d9c57" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 2.0.19 */
        hash.sha1(0, filesize) == "7556ace5e63b129436f3a228dc839ea9baa99c8c" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php

        /* Symfony 2.0.22 */
        hash.sha1(0, filesize) == "62cee24b9350733037f8d82512d8495fc59dec97" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 2.0.23 */
        hash.sha1(0, filesize) == "599b934af5fa5aebb07dbeae8501c1f3cf1d2663" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 3.0.0 */
        hash.sha1(0, filesize) == "b7d69cb038d1d41d5b98c223a75aab98d374ea3d" or // src/Symfony/Component/Console/Application.php
        hash.sha1(0, filesize) == "86e4068b5a6f10fa1ee5f3cfc9c379873ca53a19" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "addc7b61421b846a7c8c2ef6d7abf73d18da9954" or // src/Symfony/Component/Process/Tests/ExecutableFinderTest.php
        hash.sha1(0, filesize) == "2124f10ddd27eb9ca3e10f7622e4138e0ae92f1d" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "e05109f8617a0ca50828aad9848c5283fff37d62" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "90b2309866d2654a062d2875ed494e0a49f665a1" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "1e8a87822f306b32447d8a36260dcc3cc8bd808b" or // src/Symfony/Component/Security/Http/EntryPoint/RetryAuthenticationEntryPoint.php
        hash.sha1(0, filesize) == "74146bf3d62ff4a130793bf39b0babb0d227309a" or // src/Symfony/Component/Security/Http/Tests/Firewall/DigestDataTest.php

        /* Symfony 3.0.1 */
        hash.sha1(0, filesize) == "3adf6d51a741311e22b999d471e849b66324c9d6" or // src/Symfony/Component/Console/Application.php
        hash.sha1(0, filesize) == "e1099f0ac51aac5c1b0ee8187bdeb736a5cfd2fc" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "d121e833072d9a3ad7892237fb6bc720ac07a59f" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "ce10d0f6b769e1d6ae0ad960e04dea8abc3ebd9b" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 3.0.2 */
        hash.sha1(0, filesize) == "47a9016c8964d620a048cbf0555e7684ecf26ae1" or // src/Symfony/Component/Console/Application.php
        hash.sha1(0, filesize) == "ad8804b616bd2cef819ab56f519641254cda898f" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "27edaaf9680fa59a3800a2c62ff3cf8b8ce22244" or // src/Symfony/Component/Process/Tests/ExecutableFinderTest.php
        hash.sha1(0, filesize) == "ea7de97854f40646a141983b7c6dc862af05b64d" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "57f938b2a09c2a0419e3eb8c0656c3c4a75b204b" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "02e026d80d8ab3e3c4d234bbf1acf4ad97e633e8" or // src/Symfony/Component/HttpKernel/UriSigner.php

        /* Symfony 3.0.3 */
        hash.sha1(0, filesize) == "682b99b50cb4be4543d971ee9b6e3d01bcfa9c8a" or // src/Symfony/Component/Console/Application.php
        hash.sha1(0, filesize) == "b350dc90abd7893738c032e3445fda12a7aa4ca6" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "6ec3f890a50d81190a90e6825da1f1d5c03de2be" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 3.0.4 */
        hash.sha1(0, filesize) == "f6fb03db040050191e7af9407c8969d22433abc3" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "8b14fbcb4d4fd5b5bf2de45a70ca58fb12062487" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "dd9dd72e79dabfa2fda4c14da79c92643deb9b64" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 3.0.5 */
        hash.sha1(0, filesize) == "13b3bb65c4cd2c1b616f49c12c187fde8cb50ed2" or // src/Symfony/Component/Process/Process.php

        /* Symfony 3.0.7 */
        hash.sha1(0, filesize) == "840a8ac4788a3fb1e6149f1ad8d62345b048dd0b" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "80c1e9e23a57cd615912ccd3574c94a26cd938a6" or // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

        /* Symfony 3.0.8 */
        hash.sha1(0, filesize) == "8f403c7d03d6942e77165d0bd23bb99366d54eae" or // src/Symfony/Component/Console/Application.php
        hash.sha1(0, filesize) == "0a448b71d1d34d6456fe842d4d8169886e060024" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "b0db65337162103f9469d98febf8830e0fa2e947"    // src/Symfony/Component/DependencyInjection/Dumper/PhpDumper.php

}