/*
    Careful; those rules are pretty heavy on computation,
    since the sha1sum my be recomputed for every since test;
    please make sure that you're calling them after every other ones.
*/
private rule Wordpress : Blog
{
    condition:
        /* Wordpress 3.5.1 */
        hash.sha1(0, filesize)  == "833281b4d1113180e4d1ca026f5e85a680d52662" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize)  == "b4e4b88f2be38ed9c3147b77c2f3a7f929caba2c" or // wp-admin/includes/menu.php

        /* Wordpress 3.2.1 */
        hash.sha1(0, filesize)  == "b4f53b8c360f9e47cc63047305a0ce2e3ff6a251" or // wp-includes/functions.php
        hash.sha1(0, filesize)  == "ac8298df16a560c80fb213ef3f51f90df8ef5292" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize)  == "232e4705e3aa28269c4d5e4a4a700bb7a2d06f24" // wp-admin/includes/menu.php
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

private rule IsWhitelisted
{
    condition:
        Wordpress or
        Prestashop or
        Magento or
        Drupal or
        Roundcube or
        Concrete5 or
        Dotclear or
        Owncloud or
        Phpmyadmin
}
