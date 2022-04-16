/*
    Careful. Those rules are pretty heavy on computation
    since the sha1sum may be recomputed for every test.
    Please make sure that you're calling those rules after all the others.
*/

include "whitelists/drupal.yar"
include "whitelists/wordpress.yar"
include "whitelists/symfony.yar"
include "whitelists/phpmyadmin.yar"
include "whitelists/magento1ce.yar"
include "whitelists/magento2.yar"
include "whitelists/prestashop.yar"
include "whitelists/custom.yar"


private rule Magento : ECommerce
{
    condition:
        /* Magento 1.14.2.0 */
        hash.sha1(0, filesize)  == "039ad85dc5940947849f7fe1a179563c829403ab" or // lib/PEAR/XML/Parser/Simple.php
        hash.sha1(0, filesize)  == "5f577c2a35ababbf39e0efb53294e5adf523822b" or // lib/PEAR/XML/Serializer.php
        hash.sha1(0, filesize)  == "27f0e4b1a09e816e40f9e6396c2d4a3cabdb2797" or // lib/PEAR/XML/Parser.php
        hash.sha1(0, filesize)  == "258522ff97a68138daf0566786b22e722c0ff520" or // lib/PEAR/XML/Unserializer.php
        hash.sha1(0, filesize)  == "a90d7f679a41443d58d5a96bcb369c3196a19538" or // iib/PEAR/SOAP/Base.php
        hash.sha1(0, filesize)  == "7faa31f0ee66f32a92b5fd516eb65ff4a3603156" or // lib/PEAR/SOAP/WSDL.php
        hash.sha1(0, filesize)  == "6b3f32e50343b70138ce4adb73045782b3edd851" or // lib/phpseclib/Net/SSH1.php
        hash.sha1(0, filesize)  == "ea4c5c75dc3e4ed53c6b9dba09ad9d23f10df9d5" or // lib/phpseclib/Crypt/Rijndael.php
        hash.sha1(0, filesize)  == "eb9dd8ec849ef09b63a75b367441a14ca5d5f7ae" or // lib/phpseclib/Crypt/Hash.php
        hash.sha1(0, filesize)  == "a52d111efd3b372104ebc139551d2d8516bbf5e0" or // lib/phpseclib/Crypt/RSA.php

        /* Magento 1.13.0.0 */
        hash.sha1(0, filesize)  == "988006fe987a3c192d74b355a5011326f7728d60" or // lib/PEAR/PEAR/PEAR.php
        hash.sha1(0, filesize)  == "0747f27fd0469608d1686abeaf667d9ad2b4c214" or // lib/PEAR/Mail/mime.php
        hash.sha1(0, filesize)  == "6c0b33527f8e4b0cab82fc9ba013549f945fad75" or // lib/PEAR/SOAP/Transport/HTTP.php
        hash.sha1(0, filesize)  == "9a340997bddbee19c1ec9ed62aa3b7e7a39d620a" or // lib/PEAR/PEAR.php
        hash.sha1(0, filesize)  == "a11e09ee903fe2a1f8188b27186d2dd5098419af" or // app/code/core/Mage/Adminhtml/Model/Url.php
        hash.sha1(0, filesize)  == "c60a936b7a532a171b79e17bfc3497de1e3e25be" or // app/code/core/Mage/Dataflow/Model/Profile.php
        hash.sha1(0, filesize)  == "9947a190e9d82a2e7a887b375f4b67a41349cc7f" or // app/code/core/Mage/Core/Model/Translate.php
        hash.sha1(0, filesize)  == "5fe6024f5c565a7c789de28470b64ce95763e3f4" or // cron.php

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
        hash.sha1(0, filesize)  == "44ba7a5b685f4a52113559f366aaf6e9a22ae21e"    // app/code/core/Mage/Adminhtml/Model/Url.php
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
        hash.sha1(0, filesize) == "c68319e3e1adcd3e22cf2338bc79f12fd54f6d4a"    // program/include/rcmail_output_html.php
}

private rule Concrete5
{
    condition:
        /* concrete5 7.4.2 */
        hash.sha1(0, filesize) == "927bbd60554ae0789d4688738b4ae945195a3c1c" or // concrete/vendor/oyejorge/less.php/lib/Less/Tree/Dimension.php
        hash.sha1(0, filesize) == "67f07022dae5fa39e8a37c09d67cbcb833e10d1f" or // concrete/vendor/oyejorge/less.php/lib/Less/Tree/Unit.php
        hash.sha1(0, filesize) == "e1dcbc7b05e8ba6cba392f8fd44a3564fcad3666"    // concrete/vendor/doctrine/inflector/lib/Doctrine/Common/Inflector/Inflector.php
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
        hash.sha1(0, filesize) == "cf65db6ae55486f51370f87c4653aaed56903ccc"    // inc/core/class.dc.modules.php
}

private rule Owncloud
{
    condition:
        /* ownCloud 8.1.0 */
        hash.sha1(0, filesize) == "a58489a3d8401295bb09cfbad09486f605625658" or // 3rdparty/phpseclib/phpseclib/phpseclib/Net/SSH1.php
        hash.sha1(0, filesize) == "463627a4064dc05e93e6f9fc5605d4c8a4e09200" or // 3rdparty/jeremeamia/SuperClosure/src/SerializableClosure.php
        hash.sha1(0, filesize) == "5346cb6817a75c26a6aad86e0b4ffb1d5145caa5" or // 3rdparty/symfony/process/Symfony/Component/Process/Process.php
        hash.sha1(0, filesize) == "c8a6d4292448c7996e0092e6bfd38f90c34df090" or // core/doc/admin/_images/oc_admin_app_page.png
        hash.sha1(0, filesize) == "acc7af31d4067c336937719b9a9ad7ac8497561e"    // core/doc/admin/_sources/configuration_server/performance_tuning.txt
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
        Magento1Ce or
        Magento2 or
        Drupal or
        Roundcube or
        Concrete5 or
        Dotclear or
        Owncloud or
        Phpmyadmin or
        Misc
}
