/*
    Careful. Those rules are pretty heavy on computation
    since the sha1sum may be recomputed for every test.
    Please make sure that you're calling those rules after all the others.
*/

private rule Symfony : Blog
{
    condition:
       hash.sha1(0, filesize) ==  "3006ce2ddce200e1c66185b95065dc7f9d224465" or // vendor/twig/twig/lib/Twig/Node/Macro.php
       hash.sha1(0, filesize) ==  "39bae7f6aa0f4affe06a0d7b7d8306e1e27e441e" or // vendor/doctrine/common/lib/Doctrine/Common/Proxy/ProxyGenerator.php
       hash.sha1(0, filesize) ==  "4848d9582a2205c1b037a542faa5ed1b755d6620" or // vendor/phpoffice/phpword/src/PhpWord/Shared/PCLZip/pclzip.lib.php
       hash.sha1(0, filesize) ==  "85a49736e0df50f8aaad652c517f4f230726f73c" or // vendor/mouf/mouf/vendor/twig/twig/test/Twig/Tests/Node/MacroTest.php
       hash.sha1(0, filesize) ==  "8954260cbb93f46da59cff358c824679395664c2" or // vendor/twig/twig/lib/Twig/Node/CheckSecurity.php
       hash.sha1(0, filesize) ==  "9b2834dabbb7331a02a158b91fdb48f73e8bc0ea" or // vendor/dompdf/dompdf/include/page_cache.cls.php
       hash.sha1(0, filesize) ==  "a3e936e90a73ece5637a10cd7c26f047d0d5a820" or // vendor/dompdf/dompdf/include/attribute_translator.cls.php
       hash.sha1(0, filesize) ==  "b4cbea1458132e156327f20810cf2a2d1f961869" or // vendor/doctrine/inflector/lib/Doctrine/Common/Inflector/Inflector.php
       hash.sha1(0, filesize) ==  "beea13bcbd977cb7ee29fdf4bca36c9c19e5a562" or // vendor/dompdf/dompdf/include/cellmap.cls.php
       hash.sha1(0, filesize) ==  "da96d532cc2f930449a4e19a0e280d759366a8de" or // vendor/dompdf/dompdf/include/style.cls.php
       hash.sha1(0, filesize) ==  "e4b9be9277626f5377ecb3306fd4f2fb7a99508f" // vendor/swiftmailer/swiftmailer/lib/classes/Swift/Transport/SimpleMailInvoker.php
}

private rule Wordpress : Blog
{
    condition:
        /* Wordpress 4.4.1 */
        hash.sha1(0, filesize)  == "7db1719874b1415e54981c6f1ed698274abffd28" or // wp-includes/formatting.php
        hash.sha1(0, filesize)  == "ccd23ef96a588840943fba081bfa6f88531c4abc" or // wp-admin/includes/class-pclzip.php

        /* Wordpress 4.2.3 */
        hash.sha1(0, filesize)  == "f1c4697ae04da5eb19847c8f1296edce2ad3cec9" or // wp-includes/formatting.php
        hash.sha1(0, filesize)  == "e7caf1f66c38bb119fe709ade012a989d8610f07" or // wp-admin/includes/class-pclzip.php
        hash.sha1(0, filesize)  == "8ddb9eff06105b9699c6b03db54472291abcb823" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize)  == "9dd666651f57ef6e704310fe37ffce7dfd2322e4" or // wp-includes/comment.php

        /* Wordpress 3.9 */
        hash.sha1(0, filesize)  == "b20e3d401b0ab935ed6401392233b36966523e20" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize)  == "3748c7a2150a9da2d2dda10062b00d34982b3d87" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize)  == "1a4e6932523c34d95f050960e7c3d082adb28156" or // wp-includes/ID3/getid3.php
        hash.sha1(0, filesize)  == "48a3dab94dc548169700bb411148c6fbf30274c3" or // wp-includes/ID3/getid3.lib.php
        hash.sha1(0, filesize)  == "c605d1224cf4b24ad2457dd87885de9030e20731" or // wp-includes/SimplePie/File.php
        hash.sha1(0, filesize)  == "005f02927a6904c4e7f3b88ebdd9feaa6221790b" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize)  == "12b433cc24cca9747b1fcb1132ffb6b1e6ab75b0" or // wp-includes/comment.php

        /* Wordpress 3.5.1 */
        hash.sha1(0, filesize)  == "833281b4d1113180e4d1ca026f5e85a680d52662" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize)  == "b4e4b88f2be38ed9c3147b77c2f3a7f929caba2c" or // wp-admin/includes/menu.php

        /* Wordpress 3.2.1 */
        hash.sha1(0, filesize)  == "b4f53b8c360f9e47cc63047305a0ce2e3ff6a251" or // wp-includes/functions.php
        hash.sha1(0, filesize)  == "ac8298df16a560c80fb213ef3f51f90df8ef5292" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize)  == "232e4705e3aa28269c4d5e4a4a700bb7a2d06f24" or // wp-admin/includes/menu.php

        /* Wordpress 4.4 */
        hash.sha1(0, filesize)  == "2fdf93ae88735d062a8635ac1d22a6904cb89ab8" or // wp-includes/formatting.php
        hash.sha1(0, filesize)  == "ccd23ef96a588840943fba081bfa6f88531c4abc" // wp-admin/includes/class-pclzip.php
}

private rule Prestashop : ECommerce
{
    condition:
        /* Prestashop 1.6.1.0 */
        hash.sha1(0, filesize)  == "544cd822e2195ac162c9f0387031709042a72cfd" or // tools/htmlpurifier/HTMLPurifier.standalone.php
        hash.sha1(0, filesize)  == "bb8c0d735809b9412265729906016329f3e681ff" or // classes/webservice/WebserviceOutputJSON.php
        hash.sha1(0, filesize)  == "15da986fccdc7104f9d4e8c344f332db5ae9a32b" // classes/Tools.php
}

private rule Magento : ECommerce
{
    condition:
        /* Magento 1.9.2.0 */
        hash.sha1(0, filesize)  == "4fa9deecb5a49b0d5b1f88a8730ce20a262386f7" or // lib/Zend/Session.php
        hash.sha1(0, filesize)  == "f214646051f5376475d06ef50fe1e5634285ba1b" or // app/code/core/Mage/Adminhtml/Model/Url.php

        /* Magento 1.7.0.2 */
        hash.sha1(0, filesize)  == "f46cf6fd47e60e77089d94cca5b89d19458987ca" or // lib/Zend/Session.php
        hash.sha1(0, filesize)  == "ffb3e46c87e173b1960e50f771954ebb1efda66e" or // lib/Zend/Ldap/Converter.php
        hash.sha1(0, filesize)  == "7faa31f0ee66f32a92b5fd516eb65ff4a3603156" or // lib/PEAR/SOAP/WSDL.php
        hash.sha1(0, filesize)  == "539de72a2a424d86483f461a9e38ee42df158f26" or // app/code/core/Mage/Adminhtml/Model/Url.php
        hash.sha1(0, filesize)  == "6b3f32e50343b70138ce4adb73045782b3edd851" or // lib/phpseclib/Net/SSH1.php

        /* Magento 1.4.1.1 */
        hash.sha1(0, filesize)  == "0b74f4b259c63c01c74fb5913c3ada87296107c8" or // lib/Zend/Session.php
        hash.sha1(0, filesize)  == "951a4639e49c6b2ad8adeb38481e2290297c8e70" or // lib/Zend/Ldap/Converter.php
        hash.sha1(0, filesize)  == "44ba7a5b685f4a52113559f366aaf6e9a22ae21e"  // app/code/core/Mage/Adminhtml/Model/Url.php
}

private rule Drupal : Blog
{
    condition:
        /* Drupal 7.38 */
        hash.sha1(0, filesize) == "ad7587ce735352b6a55526005c05c280e9d41822" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "dfa67a40daeb9c1dd28f3fab00097852243258ed" or // modules/system/system.module

        /* Drupal 7.33 */
        hash.sha1(0, filesize) == "19c45985dfee7dc27a3a275542dee7c8fc7ebd6d" or // modules/simpletest/drupal_web_test_case.php
        hash.sha1(0, filesize) == "e53ae29f02d7bd8667ce701b6d13ca71249e6598" or // modules/contrib/simplenews/tests/d6_simplenews_61.php
        hash.sha1(0, filesize) == "5e1093b4d8bcb438b07e8a428957bd3f79c1042c" or // modules/contrib/simplenews/tests/d6_simplenews_62.php
        hash.sha1(0, filesize) == "1335f535e2b20634fa8be3e95411921dfe47041d" or // modules/socials/og/og_migrate/tests/drupal-6.og.database.php
        hash.sha1(0, filesize) == "c748f376cccb982448e99dee184dfec3a1979f44" or // modules/socials/og/tests/drupal-7.og.update_7001.database.php
        hash.sha1(0, filesize) == "1335f535e2b20634fa8be3e95411921dfe47041d" or // modules/socials/og/tests/drupal-6.og.database.php
        hash.sha1(0, filesize) == "10aa23f49747970a204c5df98d4c36e64e354760" or // modules/socials/og/og_ui/tests/drupal-6.og-ui.database.php

        /* Drupal 7.15 */
        hash.sha1(0, filesize)  == "23cc0e2c6eebe94fe189e258a3658b40b0005891" or // modules/simpletest/tests/upgrade/drupal-6.bare.database.php
        hash.sha1(0, filesize)  == "8cb36d865b951378c3266dca7d5173a303e8dcff" or // modules/simpletest/tests/upgrade/drupal-6.filled.database.php
        hash.sha1(0, filesize)  == "6c9c01bef14f8f64ef0af408f7ed764791531cc6" or // modules/system/system.module
        hash.sha1(0, filesize)  == "ad03ed890400cf319f713ee0b4b6a62a5710f580" // modules/system/system.admin.inc
}

private rule Roundcube
{
    condition:
        /* Roundcube 1.1.2 */
        hash.sha1(0, filesize) == "afab52649172b46f64301f41371d346297046af2" or // program/lib/Roundcube/rcube_utils.php
        hash.sha1(0, filesize) == "e6b81834e081cc2bd38fce787c5088e63d933953" or // program/include/rcmail_output_html.php
        hash.sha1(0, filesize) == "7783e9fad144ca5292630d459bd86ec5ea5894fc" or // vendor/pear-pear.php.net/Net_LDAP2/Net/LDAP2/Util.php

        /* Roundcube 1.0.6 */
        hash.sha1(0, filesize) == "76d55f05f2070f471ba977b5b0f690c91fa8cdab" or // program/lib/Roundcube/rcube_utils.php
        hash.sha1(0, filesize) == "c68319e3e1adcd3e22cf2338bc79f12fd54f6d4a" // program/include/rcmail_output_html.php
}

private rule Concrete5
{
    condition:
        /* concrete5 7.4.2 */
        hash.sha1(0, filesize) == "927bbd60554ae0789d4688738b4ae945195a3c1c" or // concrete/vendor/oyejorge/less.php/lib/Less/Tree/Dimension.php
        hash.sha1(0, filesize) == "67f07022dae5fa39e8a37c09d67cbcb833e10d1f" or // concrete/vendor/oyejorge/less.php/lib/Less/Tree/Unit.php
        hash.sha1(0, filesize) == "e1dcbc7b05e8ba6cba392f8fd44a3564fcad3666" // concrete/vendor/doctrine/inflector/lib/Doctrine/Common/Inflector/Inflector.php
}

private rule Dotclear : Blog
{
    condition:
        /* dotclear 2.8.0 */
        hash.sha1(0, filesize) == "c732d2d54a80250fb8b51d4dddb74d05a59cee2e" or // inc/public/class.dc.template.php
        hash.sha1(0, filesize) == "cc494f7f4044b5a3361281e27f2f7bb8952b8964" or // inc/core/class.dc.modules.php

        /* dotclear 2.7.5 */
        hash.sha1(0, filesize) == "192126b08c40c5ca086b5e4d7433e982f708baf3" or // inc/public/class.dc.template.php
        hash.sha1(0, filesize) == "51e6810ccd3773e2bd453e97ccf16059551bae08" or // inc/libs/clearbricks/common/lib.date.php
        hash.sha1(0, filesize) == "4172e35e7c9ce35de9f56fb8dfebe8d453f0dee4" or // inc/libs/clearbricks/template/class.template.php
        hash.sha1(0, filesize) == "cf65db6ae55486f51370f87c4653aaed56903ccc" // inc/core/class.dc.modules.php
}

private rule Owncloud
{
    condition:
        /* ownCloud 8.1.0 */
        hash.sha1(0, filesize) == "a58489a3d8401295bb09cfbad09486f605625658" or // 3rdparty/phpseclib/phpseclib/phpseclib/Net/SSH1.php
        hash.sha1(0, filesize) == "463627a4064dc05e93e6f9fc5605d4c8a4e09200" or // 3rdparty/jeremeamia/SuperClosure/src/SerializableClosure.php
        hash.sha1(0, filesize) == "5346cb6817a75c26a6aad86e0b4ffb1d5145caa5" or // 3rdparty/symfony/process/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "c8a6d4292448c7996e0092e6bfd38f90c34df090" or // core/doc/admin/_images/oc_admin_app_page.png
        hash.sha1(0, filesize) == "acc7af31d4067c336937719b9a9ad7ac8497561e" // core/doc/admin/_sources/configuration_server/performance_tuning.txt
}

private rule Phpmyadmin
{
    condition:
        /* phpmyadmin 4.4.11 */
        hash.sha1(0, filesize) == "52afd26f6d38e76d7d92b96809f98e526e45c021" or // libraries/DatabaseInterface.class.php
        hash.sha1(0, filesize) == "398507962b9dd89b0352f2ea9c648152fe932475" // libraries/DBQbe.class.php
}

private rule Misc
{
    condition:
        /* HTMLPurifier standalone 4.6.0 */
        hash.sha1(0, filesize) == "9452a5f1183cbef0487b922cc1ba904ea21ad39a"
}

private rule IsWhitelisted
{
    condition:
        Symfony or
        Wordpress or
        Prestashop or
        Magento or
        Drupal or
        Roundcube or
        Concrete5 or
        Dotclear or
        Owncloud or
        Phpmyadmin or
        Misc
}
