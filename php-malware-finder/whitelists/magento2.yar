import "hash"

private rule Magento2 : ECommerce
{
    meta:
        generated = "2016-07-27T19:16:30.428376"

    condition:
        /* Magento2 2.0 */
        hash.sha1(0, filesize) == "a46cd4176871076df0e7d9edd4d469cdc5414833" or // lib/internal/Magento/Framework/Shell.php
        hash.sha1(0, filesize) == "fcdadb38653801c605180fa7bc3da5ffe7a78108" or // app/code/Magento/Catalog/Model/Product/Image.php
        hash.sha1(0, filesize) == "a04c54d0bdd22c2033cc50a06866845763b18b51" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
        hash.sha1(0, filesize) == "fffb094a2d2f8f4e0f2f1ece46839055c3e5bcdd" or // dev/tests/api-functional/framework/bootstrap.php
        hash.sha1(0, filesize) == "571c65fda0b3baea7206430a87cbfcbba45e8f26" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
        hash.sha1(0, filesize) == "0bcbc44d143cba85713ffd3d6638294accb3cdba" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
        hash.sha1(0, filesize) == "f3fd57943825e6195963c1ebbbc73744cc997ca3" or // app/code/Magento/Backend/Model/Url.php
        hash.sha1(0, filesize) == "6b1207354e632ed5ff9d997673b1b8b7491e4830" or // dev/tests/integration/framework/bootstrap.php
        hash.sha1(0, filesize) == "381606c98428f5f1f1688861b9bb5b86573882ae" or // dev/tests/js/JsTestDriver/run_js_tests.php
        hash.sha1(0, filesize) == "2662ccbbd8c5841a0d5112038d8157fd5af61242" or // lib/web/extjs/resources/images/default/basic-dialog/btn-arrow.gif
        hash.sha1(0, filesize) == "073be1c00c938479a0daa737e8a2db25c051b33f" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
        hash.sha1(0, filesize) == "0eaa652145e3212563cfc960be6953b384ffe998" or // lib/web/prototype/windows/themes/lighting/spinner.gif

        /* Magento2 2.0.0 */
        hash.sha1(0, filesize) == "664fa0e4fa71b881e313cd0ee10ef39cd2d58e65" or // lib/internal/Magento/Framework/Shell.php
        hash.sha1(0, filesize) == "2d9966b5c02e42eedd670f12fff2d92969973eae" or // app/code/Magento/Catalog/Model/Product/Image.php
        hash.sha1(0, filesize) == "dcc5b6e3b86d741dd55eb9e0b8c337157eedd6e8" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
        hash.sha1(0, filesize) == "ade287d950958ff32c35d8243139bd3605fe992b" or // dev/tests/api-functional/framework/bootstrap.php
        hash.sha1(0, filesize) == "81bacb155d372b44c86205af20156ddfb59efab9" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
        hash.sha1(0, filesize) == "f0c3ea5c50c763aec35ee7db0e27e9cad7eff01e" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
        hash.sha1(0, filesize) == "cd1002f845b67164d3cda344124f1f7d9d22019e" or // app/code/Magento/Backend/Model/Url.php
        hash.sha1(0, filesize) == "a3eaabc2edf427e480b62029b89d61643a0c19fa" or // dev/tests/integration/framework/bootstrap.php
        hash.sha1(0, filesize) == "75f7eee0f3d16e2b415bb2866b22df71d209c38b" or // dev/tests/js/JsTestDriver/run_js_tests.php
        hash.sha1(0, filesize) == "690cfdb0e5273fa0ec92463ba1356b84edeb2359" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php

        /* Magento2 2.0.1 */
        hash.sha1(0, filesize) == "add333a8137ccbb305ecf60c3e55e28768c0f237" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php

        /* Magento2 2.1 */
        hash.sha1(0, filesize) == "181aac8d1a67fe106fa750933e6d2fe2194c889e" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
        hash.sha1(0, filesize) == "25d56e294e9852fbddbbb377cc55dc46fa0d2976" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
        hash.sha1(0, filesize) == "7ac6acb23d445922fbed93d4e19f14517ea710f9" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
        hash.sha1(0, filesize) == "64459becc8ec0520996804beba4aaba8fa18e558" or // app/code/Magento/Backend/Model/Url.php
        hash.sha1(0, filesize) == "92f71e0f24fbb82eb1c761102930594d0299717e"    // lib/internal/Magento/Framework/Shell/Driver.php

}
