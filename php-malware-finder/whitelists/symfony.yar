import "hash"

private rule Symfony : CMS
{
    meta:
        generated = "2018-05-30T11:41:41.112501"

    condition:
        /* Symfony 2.0.19 */
        hash.sha1(0, filesize) == "1fd782e06d6f9deabbc1a79542d53f7ae35a4308" or // tests/Symfony/Tests/Component/Security/Http/Firewall/DigestDataTest.php

        /* Symfony 3.0.0 */
        hash.sha1(0, filesize) == "73b94cff56707cecf81493590a8ef318ef31faee" or // src/Symfony/Component/Process/ExecutableFinder.php
        hash.sha1(0, filesize) == "393474833397003658a3e05883afea9715d3e1d8" or // src/Symfony/Component/HttpKernel/UriSigner.php
        hash.sha1(0, filesize) == "dc0c2d801a89f2e4a1be3722c91a363ddb2f7ab9" or // src/Symfony/Component/VarDumper/Caster/ExceptionCaster.php

        /* Symfony 3.0.9 */
        hash.sha1(0, filesize) == "a10a4593f4df6dbb804a10bf3db8b47cd71edfd0" or // src/Symfony/Component/Console/Application.php
        hash.sha1(0, filesize) == "a6155a3b5d89fe330ed8627953b76d3d31867e8e" or // src/Symfony/Component/Security/Http/Tests/Firewall/DigestAuthenticationListenerTest.php
        hash.sha1(0, filesize) == "6896951a4f46633697b6c9e193ea996bde3685a5" or // src/Symfony/Component/VarDumper/Caster/ExceptionCaster.php

        /* Symfony 4.0.0 */
        hash.sha1(0, filesize) == "693d923f3232b462e7104eff546735c98844cbe8" or // src/Symfony/Component/Security/Http/EntryPoint/RetryAuthenticationEntryPoint.php
        hash.sha1(0, filesize) == "f0fc40c87f5d8c06d5529ab0093e735f30df5917" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "e8fb0a72f9a3c11be20e2cc7a28d11df3416fc9f" or // src/Symfony/Component/Process/Tests/ExecutableFinderTest.php
        hash.sha1(0, filesize) == "561a4d214202da50d8816a3a59bc4ebe1356c7cf" or // src/Symfony/Component/Form/Tests/Extension/Core/Type/FileTypeTest.php
        hash.sha1(0, filesize) == "b67f52cfe76bf1e5ced4625ba506258508d075de" or // src/Symfony/Component/EventDispatcher/EventDispatcher.php
        hash.sha1(0, filesize) == "a79b90692b4edf22230e9cad0d38596e4994383f" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "3123a1fbb7cc12ca526a5b1e3939b024992e5a10" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "c47ee46b12ca5a74f624069924e35bceba7aa57d" or // src/Symfony/Component/Process/Tests/ProcessTest.php
        hash.sha1(0, filesize) == "39af1d8a3bb291edca53669647d3d0df11ff0c6b" or // src/Symfony/Component/Process/ExecutableFinder.php
        hash.sha1(0, filesize) == "7901c56989cc0e1a4db453e37fe7449053915b78" or // src/Symfony/Component/Debug/DebugClassLoader.php
        hash.sha1(0, filesize) == "ce0f8199388e3ba36b28ecd8674f750860ec1228" or // src/Symfony/Component/HttpKernel/UriSigner.php

        /* Symfony 4.0.2 */
        hash.sha1(0, filesize) == "1c562d622fc3cb58eb2c3b24107a23c055b7cc64" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "c00515f3dad94c02368fe7d0543a3b8707c87f7a" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "2c138140d599c584016edb867420033a3da198cc" or // src/Symfony/Component/Process/Tests/ProcessTest.php

        /* Symfony 4.0.3 */
        hash.sha1(0, filesize) == "8381bfe62e337a44e9cd825c2123075de1a08013" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "a9b821f59fb1a093d1cd36916116496606e41da2" or // src/Symfony/Component/Filesystem/Tests/FilesystemTest.php
        hash.sha1(0, filesize) == "7041d041961aa55a90325852e181bdf78edfb6e4" or // src/Symfony/Component/Process/Tests/ProcessTest.php
        hash.sha1(0, filesize) == "02de4ca28714c29df4fb425dd0e1afa412529a0c" or // src/Symfony/Component/Debug/DebugClassLoader.php

        /* Symfony 4.0.4 */
        hash.sha1(0, filesize) == "4caf5145213b4cb8f5922de87233a621859d2525" or // src/Symfony/Component/Process/Process.php

        /* Symfony 4.0.5 */
        hash.sha1(0, filesize) == "ba720c308bbea2f2dccc30217f0225cbc6f887a2" or // src/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "3edaf086dbd7202caec6e15ce578dd846245c1c8" or // src/Symfony/Bundle/FrameworkBundle/Controller/RedirectController.php
        hash.sha1(0, filesize) == "7009a4e3cd672535586eb18dcbdb203e77de8b21" or // src/Symfony/Component/Debug/DebugClassLoader.php

        /* Symfony 4.0.7 */
        hash.sha1(0, filesize) == "912d67551dc6bb768733d58d5224da11c78b1b4d" or // src/Symfony/Component/Process/Process.php

        /* Symfony 4.0.10 */
        hash.sha1(0, filesize) == "e4b1a36ca3eb6eebf8b67d46fb592cdf20687dd8"    // src/Symfony/Component/Process/ExecutableFinder.php

}
