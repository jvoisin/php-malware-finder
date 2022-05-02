private rule Magento2 : ECommerce
{
	condition:
		/* Magento2 2.0.0 */
		hash.sha1(0, filesize) == "cd1002f845b67164d3cda344124f1f7d9d22019e" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "d4ec772ebaa46f66f7ee12d31258bece6a1a416d" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "8145a57a795ba1a377fdd9ea6bb55174d17239ba" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "2d9966b5c02e42eedd670f12fff2d92969973eae" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "75f7eee0f3d16e2b415bb2866b22df71d209c38b" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "ade287d950958ff32c35d8243139bd3605fe992b" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "a3eaabc2edf427e480b62029b89d61643a0c19fa" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "690cfdb0e5273fa0ec92463ba1356b84edeb2359" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "dcc5b6e3b86d741dd55eb9e0b8c337157eedd6e8" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "81bacb155d372b44c86205af20156ddfb59efab9" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "5b286341ce1c6ff499e6a1c195355bb5de123cd9" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "97a69099eb1def6f1c3024e0ad7ff8051deb0a13" or // lib/web/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "477d7865ac4f9d0746a239bfb27e399a990dd49b" or // lib/web/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "e11ba669cf8d4e4dd657ce12dce82cd3fd0515e2" or // lib/web/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "664fa0e4fa71b881e313cd0ee10ef39cd2d58e65" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "093bb21d65d7828c182d4b1e6cfee6eb02847aff" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "a76a56301cf6916e4435805c758faf1265548261" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "72ec17234a61986a36c8f10dbc5f95999896057a" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "f0c3ea5c50c763aec35ee7db0e27e9cad7eff01e" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "313d2394605796c06a935527499280173124fb6b" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		hash.sha1(0, filesize) == "2421888cd70ba01de6320072d35a101110945455" or // setup/src/Magento/Setup/Module/I18n/Dictionary/Phrase.php
		hash.sha1(0, filesize) == "0a0ae6ff41e93076c78781509ff2151d5b799a6a" or // vendor/zendframework/zend-config/src/Reader/Json.php
		hash.sha1(0, filesize) == "62e0f4887818cb01fb3dd7f2dcc1dac74742fcb1" or // vendor/zendframework/zend-config/src/Reader/Yaml.php
		hash.sha1(0, filesize) == "b163b6e8d6700dcca6451c5c452ea5c1bbd687e4" or // vendor/zendframework/zend-config/src/Reader/Ini.php
		hash.sha1(0, filesize) == "502966548aa12798e152637e253ddbd06b9544fa" or // vendor/zendframework/zend-config/src/Reader/JavaProperties.php
		hash.sha1(0, filesize) == "1184cdbe3ac63e2aadbd826f2146a085f9ca2094" or // vendor/zendframework/zend-i18n/src/Validator/IsFloat.php
		hash.sha1(0, filesize) == "b0af434ee995d7e49ec49098313d1b0de6e73c04" or // vendor/zendframework/zend-view/src/Helper/Navigation/AbstractHelper.php
		hash.sha1(0, filesize) == "b5a4b8248d608a4b1529e5953aaa573b0f22fb2c" or // vendor/zendframework/zend-serializer/src/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "8c6ada59a4fef5b955a181b57352ac777d8414fc" or // vendor/zendframework/zend-validator/src/File/MimeType.php
		hash.sha1(0, filesize) == "000e0740938ef378705e751d8944b3c0ec3bdd9a" or // vendor/zendframework/zend-soap/src/Client.php
		hash.sha1(0, filesize) == "32266eb7343a11f4e7f8bd624a3ea6fc73628a58" or // vendor/oyejorge/less.php/lib/Less/Tree/Unit.php
		hash.sha1(0, filesize) == "3e4f63564a1d258b0a5723dbb81f1733c619cbcd" or // vendor/oyejorge/less.php/lib/Less/Tree/Dimension.php
		hash.sha1(0, filesize) == "06ce307f197a9d31a553b002183d073115ff803e" or // vendor/tubalmartin/cssmin/cssmin.php
		hash.sha1(0, filesize) == "f152f31d6f97f24d227cd51347d583c144bf167d" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "9182cd008814b95a86c5c9d318734330617c92e5" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "c02e4456afe25282720295660e52ee5f3f32b328" or // vendor/monolog/monolog/src/Monolog/Formatter/LineFormatter.php
		hash.sha1(0, filesize) == "172be2895cb70436fc146e7564966dce4f96e08a" or // vendor/symfony/console/Symfony/Component/Console/Application.php
		hash.sha1(0, filesize) == "a1b4f3d95eb18abd284aadd40097462838143a8e" or // vendor/symfony/console/Symfony/Component/Console/Tests/Helper/LegacyProgressHelperTest.php
		hash.sha1(0, filesize) == "3d32ace32fa8e80189192ea1d0853b8224fcae7a" or // vendor/symfony/console/Symfony/Component/Console/Tests/Helper/ProgressBarTest.php
		hash.sha1(0, filesize) == "725a80e1da25907af517807f62e25fc76fd7cf65" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "abe477d884c40043013e4b08501acff5351b5539" or // vendor/symfony/process/Tests/ExecutableFinderTest.php
		hash.sha1(0, filesize) == "a3b7be20d89f5d8e37024c118cbbc8492688ec03" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "a9d0c26df1fc39e7e8be5bfa51051b412c5f7403" or // vendor/squizlabs/php_codesniffer/CodeSniffer.php
		hash.sha1(0, filesize) == "76f1af35b350e0e8d1ac6d288c01d35572e3ee4a" or // vendor/squizlabs/php_codesniffer/CodeSniffer/Reports/Emacs.php
		hash.sha1(0, filesize) == "e2f190b4a5013d53449517377e1fe0dacd6e8ec6" or // vendor/squizlabs/php_codesniffer/scripts/phpcs
		hash.sha1(0, filesize) == "f2672f96d0143bbfe3a98fa95859df401a6eff76" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "057f48d63e8a02d6c83a9eb5bba81b087db79f51" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tokenizer/Transformer/DynamicVarBrace.php
		hash.sha1(0, filesize) == "bac1ed101e3c7880145c9ce6cf908b179b57e9c7" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Fixer/Symfony/PhpdocShortDescriptionFixer.php
		hash.sha1(0, filesize) == "1320c4b30065e82d2c9ed373a7a3975fc5c36416" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "1378de5151bda1f9e00b101d140ad2ca17660ba7" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/Transformer/DynamicVarBraceTest.php
		hash.sha1(0, filesize) == "f4aae1c84c801b8910c31c7d9167a232333444c1" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "f6d440287bdcd1d5198a3e5c12c11cc2900cc611" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		hash.sha1(0, filesize) == "4fe50dc31b47006753a33f114314132f452ecea8" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/TrimArraySpacesFixerTest.php
		hash.sha1(0, filesize) == "a2348096bec192beac0c0ab29ead03526b5d3009" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/PreIncrementFixerTest.php
		hash.sha1(0, filesize) == "289ae53f03114fdf9cf561f61dab5993f5f24098" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/JoinFunctionFixerTest.php
		hash.sha1(0, filesize) == "ad1a6ff2c74fd6a23ee431e6231aa834fc33bb0a" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Contrib/PhpUnitStrictFixerTest.php
		hash.sha1(0, filesize) == "ee168846484382604d4cd4cf2e9518a1ede818a8" or // vendor/magento/zendframework1/library/Zend/Session.php
		hash.sha1(0, filesize) == "b56421a26a863d08d4e18f69df234193ff351990" or // vendor/magento/zendframework1/library/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "86fe4608ce0b8c6a2250d485367a5f3521c6719b" or // vendor/magento/zendframework1/library/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "17a96b1806cf7b20fde6f2fefc0100f0b104f3af" or // vendor/magento/zendframework1/library/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "68e59449682a298d61609310d35205d5a3f789e6" or // vendor/magento/zendframework1/library/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "d01269880c68befd36f0edd8857b6b1d05965f20" or // vendor/magento/zendframework1/resources/languages/ja/Zend_Validate.php
		hash.sha1(0, filesize) == "82485c8d519d5b9947a37fffea10839db45c0fc9" or // vendor/magento/zendframework1/resources/languages/sk/Zend_Validate.php
		hash.sha1(0, filesize) == "4f16e01f1d672fa79fed63829dabac27fc56afca" or // vendor/magento/zendframework1/resources/languages/uk/Zend_Validate.php
		hash.sha1(0, filesize) == "bc6be8a711dd231d337b2bfb1dc6ea133f084055" or // vendor/magento/zendframework1/resources/languages/pt_BR/Zend_Validate.php
		hash.sha1(0, filesize) == "6e439473653593eb82620d898446349e2f39d941" or // vendor/magento/zendframework1/resources/languages/es/Zend_Validate.php
		hash.sha1(0, filesize) == "8e3726607b9b1e6dd2f6206ce6abd6e9733a3fff" or // vendor/magento/zendframework1/resources/languages/ru/Zend_Validate.php
		hash.sha1(0, filesize) == "838921b7c6897052e0472eeae4f1ea49da29c99d" or // vendor/magento/zendframework1/resources/languages/cs/Zend_Validate.php
		hash.sha1(0, filesize) == "3ce2c232924e5d44ea207f7636e65151f4bd4044" or // vendor/composer/composer/src/Composer/Util/Git.php
		hash.sha1(0, filesize) == "8050fbdd2f773e765a0c9148a8fee12a15eae74d" or // vendor/composer/composer/src/Composer/Command/ConfigCommand.php
		hash.sha1(0, filesize) == "bd10a894c29ab5e64bae971ce159c00937a7efed" or // vendor/pdepend/pdepend/src/bin/pdepend
		hash.sha1(0, filesize) == "f2672f96d0143bbfe3a98fa95859df401a6eff76" or // vendor/bin/jsonlint
		hash.sha1(0, filesize) == "e2f190b4a5013d53449517377e1fe0dacd6e8ec6" or // vendor/bin/phpcs
		hash.sha1(0, filesize) == "bd10a894c29ab5e64bae971ce159c00937a7efed" or // vendor/bin/pdepend
		hash.sha1(0, filesize) == "ccc9ec282ac5acb1ed551a5fa9dcb63527841750" or // vendor/bin/phpmd
		hash.sha1(0, filesize) == "6ccac6cef15b10b993da3117f6033b5a29bc738f" or // vendor/phpunit/phpunit/src/Framework/TestCase.php
		hash.sha1(0, filesize) == "ccc9ec282ac5acb1ed551a5fa9dcb63527841750" or // vendor/phpmd/phpmd/src/bin/phpmd
		
		/* Magento2 2.0.1 */
		hash.sha1(0, filesize) == "add333a8137ccbb305ecf60c3e55e28768c0f237" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "8abc8a07ab38ad2da15c2061c816ff638f0e0f95" or // setup/src/Magento/Setup/Module/I18n/Dictionary/Phrase.php
		hash.sha1(0, filesize) == "bb3d5b5058774b99326162a971064e770c1d400a" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "e11d7e94c9046166ced9717f1730df4f538358b2" or // vendor/symfony/process/Tests/ExecutableFinderTest.php
		hash.sha1(0, filesize) == "3ee3d886ac2431ce94b3d9863754b22eb59f10d5" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "696f1493509991c965fb042b9a80f72974023b8c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "368d7d21730e6d765c32ff201851db00b354ae51" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Fixer/Symfony/PhpdocShortDescriptionFixer.php
		hash.sha1(0, filesize) == "0d1fccb67a37a28e258bd0697b99c225ee95fc51" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "c51e1406b80f46f270901d0b02ea381ad709b95e" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "4cfae7375a5a512354d644cc4d2a2fb590077dd3" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/UnneededControlParenthesesFixerTest.php
		hash.sha1(0, filesize) == "a34bb133f5f3b5bc332078dae3cf0b667a25c2ba" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/ArrayElementWhiteSpaceAfterCommaFixerTest.php
		hash.sha1(0, filesize) == "11b2a61513faf81855fb2634fce23697618923c1" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/ArrayElementNoSpaceBeforeCommaFixerTest.php
		hash.sha1(0, filesize) == "09fa34dd77324cf97b547387a896f0ddc993385a" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		hash.sha1(0, filesize) == "da8346240d2012a694fa17a56c752e7211caafbf" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/TrimArraySpacesFixerTest.php
		hash.sha1(0, filesize) == "e69fd602a11eaf6f93a2928e9149ef25452f2643" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/ShortBoolCastFixerTest.php
		hash.sha1(0, filesize) == "2a88325ec2919a393b0d13e2bd8a39aed38d089c" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Contrib/PhpUnitStrictFixerTest.php
		hash.sha1(0, filesize) == "d0734194883ed7cbea57e363fecaeeb6d8d00e69" or // vendor/pdepend/pdepend/src/bin/pdepend
		hash.sha1(0, filesize) == "d0734194883ed7cbea57e363fecaeeb6d8d00e69" or // vendor/bin/pdepend
		
		/* Magento2 2.0.2 */
		hash.sha1(0, filesize) == "233f56fc60f40597126ac6da5a255ed2da65fa20" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/UnneededControlParenthesesFixerTest.php
		hash.sha1(0, filesize) == "0a5d3ab4932430db2bcd5897a94a837f2b5d4a62" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		
		/* Magento2 2.0.3 */
		hash.sha1(0, filesize) == "f3fd57943825e6195963c1ebbbc73744cc997ca3" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "cb814a8f56085e7238010cc3c743cb6fa9249bb6" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "19822e59997bc8ba37d4ee8fd4a9c8cd7a1a88a1" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "fcdadb38653801c605180fa7bc3da5ffe7a78108" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "381606c98428f5f1f1688861b9bb5b86573882ae" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "fffb094a2d2f8f4e0f2f1ece46839055c3e5bcdd" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "6b1207354e632ed5ff9d997673b1b8b7491e4830" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "073be1c00c938479a0daa737e8a2db25c051b33f" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "a04c54d0bdd22c2033cc50a06866845763b18b51" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "571c65fda0b3baea7206430a87cbfcbba45e8f26" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "892b8581b6f16d00ed67bbbe6647eac9ed5047a3" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "a46cd4176871076df0e7d9edd4d469cdc5414833" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "dbbf248c80845164bfee1165820a32b8f855b1fd" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "448a05674ff22088e7e7944224d78dd958836169" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "d1f98d5d8f6c883fa76605b7e50efddb6b73a40d" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "0bcbc44d143cba85713ffd3d6638294accb3cdba" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "ed5b0a09cefc83fedad57a7c79cd35f261c90e2b" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		hash.sha1(0, filesize) == "f3134582915a58e81289505201db72e55981a787" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "e1ef41c3d01cb1ada488ff1509beff743f5b0d86" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "11464980c1753f0169ba1d5d90d1f347604fe36d" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "a42a7f37f5e84cd11e0359f22d89ea486e3be903" or // vendor/sebastian/environment/src/Console.php
		
		/* Magento2 2.0.4 */
		
		/* Magento2 2.0.5 */
		
		/* Magento2 2.0.6 */
		hash.sha1(0, filesize) == "75f761fcdd8675aee7d190e31031be5912cd82c0" or // vendor/symfony/process/Process.php
		
		/* Magento2 2.0.7 */
		hash.sha1(0, filesize) == "50729d6c9165838ca734cd8286cdf6fe118ed533" or // vendor/sebastian/environment/src/Console.php
		
		/* Magento2 2.0.8 */
		hash.sha1(0, filesize) == "e1328d0b46579ef478a04d1e26e17b70c905052d" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "2f54337e672d3c5be8860cbe7b0e168bc0712a68" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "fdce42474a273767544ca7f6523f5fa746ee2986" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "e4446c8664ba8e523afe6276ff3d74c2464fc196" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/Transformer/DynamicVarBraceTest.php
		hash.sha1(0, filesize) == "385e32ecaaaa3a0c41adc65de81ea120d218cf82" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "5b3d6eb358bbec82eb1ba43631cf9e4be786a227" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/UnneededControlParenthesesFixerTest.php
		hash.sha1(0, filesize) == "02de582f2d14ebc6bb2822c75a4bf547e55efe9f" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		
		/* Magento2 2.0.9 */
		hash.sha1(0, filesize) == "78df93e21f17c38ba43d3ff5ce35dea223b867e1" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		
		/* Magento2 2.0.10 */
		hash.sha1(0, filesize) == "2fb8066ba8f7a6509ca5483a8cf436e0f8692c2a" or // vendor/symfony/process/ExecutableFinder.php
		hash.sha1(0, filesize) == "e1023b6db60214d8af90a29fc499cf4e559825b8" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "4d484b8c942943b66095429aeb3dbc5f7043c33e" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "23ba985a4971dfd9cca89f21e0b236172048d222" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tokenizer/Transformer/DynamicVarBrace.php
		hash.sha1(0, filesize) == "030764f1b7821cc2d84644961c37620da2d90f61" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Fixer/Symfony/PhpdocShortDescriptionFixer.php
		hash.sha1(0, filesize) == "4d484b8c942943b66095429aeb3dbc5f7043c33e" or // vendor/bin/jsonlint
		
		/* Magento2 2.0.11 */
		hash.sha1(0, filesize) == "c5e894f794e51cbe8e2880bc8d3ca66cdf03cc7c" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "e9121ed645f2c14e6823d538f2fd178b397e8a0c" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "b8bb6b6d02da2fdd37175c761fa97d783c41fc82" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "39e3e7114633b0e34c857f0870993aac7e22f194" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "f22f4f8bc8c4e523ece560c6deeb19dad0901fb1" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "156edf7756b2c963de57a8ca24d82235c104dd99" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "2129b5635fff163dae53baebe5d1757bff12b94a" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "a6a47849ce9bca1fb77c6a79881a71225077066b" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "467525aff9535f9f0c0aef54d7d08fa6e47a7c74" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "8d5b554f736f880a8ece739853af0cc48bb5a812" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "91fffd76393bb2c842979f3b692bbefa7c5aeb16" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "f42cc5335de5f06535e8e077206e177a9c896637" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "021e596bb7a67a5a938e4a845701a69f82b45b57" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "8c2ae1628d5444fc225c331b0a9b804338fd2e1b" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "d61d6b62141e345c12ad4efbbc335b6753472f2d" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "1baf421486a3f9643effa9682c9e233889e1202f" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "4f697b5a0c0f1a596769e6320ae6615f2557992d" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "5da62035633518dca120b129e4f633966bf1dbf5" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "24474e40bd0f47603105df1e9440ec4ad3604b49" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "9f6856d545db59534fa19e9484d63c6262a27e6b" or // vendor/symfony/process/ExecutableFinder.php
		hash.sha1(0, filesize) == "85753e9603a8257660ca373f5dd1ec54043ff183" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "efb174da3eba83465a2b22c41724a38ab021adc3" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "fe66d643505f98a8701e16a16df941db1e013acd" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.12 */
		hash.sha1(0, filesize) == "29509547a3df49795cd94499b8e5186a0d631f50" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "3a921750e6d75d4c48ffc27325a5e599ebe0268a" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "368ee3a68a2dd9486ac0592cddc9956656daea26" or // vendor/magento/zendframework1/library/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "d92effc195a34f3ef57ef1019e9517fd87fdb21a" or // vendor/composer/composer/src/Composer/Util/Git.php
		hash.sha1(0, filesize) == "648c71bf728c5ac30a78669003a5f8ac04db08c3" or // vendor/composer/composer/src/Composer/Command/ShowCommand.php
		hash.sha1(0, filesize) == "f8d7d78a68a7a454a3800a8ac16c1c7b9ad749f2" or // vendor/composer/composer/src/Composer/Command/ConfigCommand.php
		
		/* Magento2 2.0.13 */
		hash.sha1(0, filesize) == "ddead59890d2c99e76e468094d68fc419cbabbe7" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "3c024cef3450f55e1f2dc50d757eb6bda8e0aa9c" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "83e83fba96501b3453a4a0b7ab2f36b7426749f1" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "01dbe0bbf6b9cb214410f2ff38181d8d164a53ef" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "17ea2b0b2d2bdc3cdccdd5dff2a7246768049180" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "b7b54740e243add6033baca3770f76146c7b9ba5" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "0717b4bb444caec9679d7c0d6f6e9abb9442670b" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "5b871a979d648fe6474e232c656b92274e8abbf4" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "5bcf446b284592eb9e4c64ad87b317a73fa5f463" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "2c52f35481456d3c8dac49cd1ecc25792e0ae2d7" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "e121a225b0d12d2e4c03eac6deb45aa6c11249fb" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "d466f44dfb788cea74af332178be3442ad0de7e9" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "da9512c83a01edcb7562377f1c41bc1be93a15ed" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "b0627f6c3fc7571b81f7c677a5d2bf287e0b55ff" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "5aea5bcef2771467d3e4c84dd304217c3d096872" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "e49284de86eac76c768ad5013c7ca71be0869305" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "d89a4ba6245d4d8a24fe1d98c86ecd2ec4b40dcc" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "e74fc9b2dad2b6cab8b22e7d96ebc49a7cae9896" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "09abaf69f729ab2922aeda3fa8475d67795a2d7b" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "59da4d114e17ddb20be53460cde1aba2868e2d30" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "de5c49a3b9703f4f95584575d970654b3e6b839f" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "08902d712ff9dd3e6c09a7c208992af082f9c757" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "cacb07cec83967672afa69ef06bfd0ca456a1f58" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "111c13f7fa513fcf3f4438fe57bb7c049c12ddfe" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "050602a0e718f4bcbdbd4bac123dac20bb9d6bd0" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "c734de5a7d259c8d04d7ab33ab8d3fd5d7df795f" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "008fa7b844781b883d85d947cc089262c798cd8c" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "4398f0d56d5a74097ec5899c3a1714aaa6e28088" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "07d218a9f05e1ba2ae5e06908c4a7cfbdf07325c" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "2c831eeb01158462fb44fd12a3e52a00a23cd89c" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "7c0acbee4469e930b0a3da3f143fe36e77b0c347" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "15282670aaed1d3f1fcc8247adc45de8546669c7" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "1294e45f10b4b4eb609c3b0654562317176abd49" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "22ec9304340b38564305bf9e32d11b416bdf75d8" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		
		/* Magento2 2.0.14 */
		hash.sha1(0, filesize) == "6ed1dcee63761ea913b67ca03ded42e96f590b36" or // vendor/symfony/process/ExecutableFinder.php
		hash.sha1(0, filesize) == "aeffdf582ee6179f0df53cfc5fb508d30c79ca23" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "592ebc85426d16e61a417c1a603836f9b53811ab" or // vendor/symfony/process/Tests/ExecutableFinderTest.php
		hash.sha1(0, filesize) == "1f9ca2f9b4eb4c3bc7b5d5638e0b0e361b995a36" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "2f559ac195c2c93bb28ed025e7a6851bda5cbfa9" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.15 */
		hash.sha1(0, filesize) == "91e0f69fbdf38d8e6e3ccfa0f8e806b1530be8e1" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "49f41cbd82a981cd6bd8f97ba13630b910fd8685" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.16 */
		hash.sha1(0, filesize) == "557045c6b3132e37a8b9b48c8ee6a26df50b8763" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "94f6f8ce54742d8b479760d681c0442df4fd3514" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "4e6118b35adcc7088377d58bdb1436267524e343" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "4e6118b35adcc7088377d58bdb1436267524e343" or // vendor/bin/jsonlint
		
		/* Magento2 2.0.17 */
		hash.sha1(0, filesize) == "a788f8a799221cb24ddb7a8aeb33624e2cb476fc" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "963fb2ff6cf89995cb0b5fcac45d57dab9183d69" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "7fe6433f36919db43e23effd68a89f6d610865cc" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "bdf1fcbe43cdf5200e7e28bd25e845e8d731bc14" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "c4854bc0249e0f970521cc1cf57446f14309ff8c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.0.18 */
		hash.sha1(0, filesize) == "b9e783094ae318eb8e8b57d83a6f81395d4b8807" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "cedd6b5448398afd9466997142f7c2438f2c932f" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "ac8139452995845aea88df75c02376eaf1e3a5f2" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "c8157cd5255c95c69498ae8fd5a57ec0015d1bdf" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "11dbfaf75f2187398d49ea4a25878ef9342496af" or // vendor/seld/jsonlint/bin/jsonlint
		hash.sha1(0, filesize) == "11dbfaf75f2187398d49ea4a25878ef9342496af" or // vendor/bin/jsonlint
		
		/* Magento2 2.1.0 */
		hash.sha1(0, filesize) == "64459becc8ec0520996804beba4aaba8fa18e558" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "883a1d6ca14a96231887768babe9e8a0cd0800f4" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "1ef83ad7c62a035a71c786d2dd7de7fa993b88c9" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "0e4193c10af5017d0c2fd9300556d25b536e2251" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "85c69f4a3cfbe9670990523ba2c4be0225e5f5a0" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "181aac8d1a67fe106fa750933e6d2fe2194c889e" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "25d56e294e9852fbddbbb377cc55dc46fa0d2976" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "8bd120bbe2369df9f9056d49fa6f4a6c62637bc4" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "b8762bbde3a0202e289634005163291a8ee1cdb5" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "7ac6acb23d445922fbed93d4e19f14517ea710f9" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "92f71e0f24fbb82eb1c761102930594d0299717e" or // lib/internal/Magento/Framework/Shell/Driver.php
		hash.sha1(0, filesize) == "645a3175c03748862cffc45423f2af030ecc361a" or // vendor/oyejorge/less.php/lib/Less/Tree/Dimension.php
		hash.sha1(0, filesize) == "f392af8f698d1d7faefbcc0d357eba20c1040459" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "4e4ea26e0b80aedffec3b35057fd0496f74262c2" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "b9cd8abb45de04dedb9c5391d2440cc22c1cba6a" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "33c6049f790a9d9629ad0334cb0cb775a12990b1" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "44d33c9aabf64223a32610b719ad77666050b6dc" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Tokenizer/TokensTest.php
		hash.sha1(0, filesize) == "7af3018c4d08ebdeb88e072aab9e8909831a45b3" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/PSR2/BracesFixerTest.php
		hash.sha1(0, filesize) == "ae2c48bace90c07184b7f1e5b5dbf863ca6a5b75" or // vendor/fabpot/php-cs-fixer/Symfony/CS/Tests/Fixer/Symfony/NewWithBracesFixerTest.php
		
		/* Magento2 2.1.1 */
		hash.sha1(0, filesize) == "4b8a3269b7fb4d1bfc438a531f5675b44b01ba52" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		
		/* Magento2 2.1.2 */
		
		/* Magento2 2.1.3 */
		hash.sha1(0, filesize) == "76be172c911fee3eab5d821edde580e5805ed368" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "f68d5ea111181a2f292a0505159171b9711818e2" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "b48e85037627b2836145f25c6c7f459cff4b3cb2" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		
		/* Magento2 2.1.4 */
		hash.sha1(0, filesize) == "1b63becf463667081e723caa0696f1b1b67437db" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		
		/* Magento2 2.1.5 */
		hash.sha1(0, filesize) == "fa63bf2a0264c0044254c8e2dcc814ac7d8bddb2" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "395458537df4051959c333ac7271c8a863150789" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "229f6fcbfcd1713d616f2bb89f7c8c9a31a2deb4" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "456f9f8ead4e7b606f1b35669bd2dac104e421fc" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "02578d94159f1d88b32d9c0861055485cb7391fa" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "3f846c514532a7488b3268e62137cbef443d2471" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "843e8f286a4cf51ca5aa532beb07b0f0a64aa32e" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "32401af11c757b96d8f65085b420861125fa3090" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "1004650dd15224d6dffe8fe72e409091b357afa2" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "5687d9871695c46aebfc6af286ee984654f93a82" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "cd1039bdd8d22ea99ffbcbdcbb05c5cb1a50b5e5" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "d161688212ad42208d4c587f0530fba696fd0aca" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "5d327ec6c10da280b80958c76c030dec0a9de35e" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "d8a6ed90677727852f0b20f6112d08c1da149818" or // lib/internal/Magento/Framework/Shell/Driver.php
		
		/* Magento2 2.1.6 */
		hash.sha1(0, filesize) == "e6078d183e380a919948c3b3b4971c5e049747d4" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "d302d6e931b946f47aa9ae5c42a99e59317777a5" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		
		/* Magento2 2.1.7 */
		hash.sha1(0, filesize) == "bc8ae673be1f6d1253401f2347c1c115b2eb709c" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "370f0f3a2475c045746d732e55d8a0e069096c7b" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "46f2ec3159015327b7ced7e1f438cc9c27c280bf" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "30e1d4a9b8330866f6819b6d0450fc541b8bca24" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		hash.sha1(0, filesize) == "36d64a870bc04baf47a885a9c3806fd5b0d24023" or // vendor/pdepend/pdepend/src/bin/pdepend
		hash.sha1(0, filesize) == "36d64a870bc04baf47a885a9c3806fd5b0d24023" or // vendor/bin/pdepend
		
		/* Magento2 2.1.8 */
		hash.sha1(0, filesize) == "ffab57b32ad85e87e337f09e74c57dcfe5e1501b" or // lib/web/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "b7740681dc35c16ed01413b7e627655442a1cce0" or // lib/web/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "4772981059bba37ee951778fe941d81d56cf18f4" or // lib/web/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "398718704aad62d1cf8c17987b1ce355b5e99ea9" or // setup/src/Magento/Setup/Model/FixtureGenerator/BundleProductGenerator.php
		hash.sha1(0, filesize) == "00fbcf8ef6037fd2391c98dc33a66848a28937d9" or // setup/src/Magento/Setup/Model/FixtureGenerator/ProductGenerator.php
		
		/* Magento2 2.1.9 */
		hash.sha1(0, filesize) == "ac29b321ea84532f0acec3409b3ba30a7e64c998" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "930713b472a4e7a847fff028975761d98f7fe767" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "c11ff15722cc309480b728064bc7b438bc953f02" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		
		/* Magento2 2.1.10 */
		hash.sha1(0, filesize) == "dd3c76c21f587f44be23d457a1a1b8637bb30b47" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "44d8fa56264b9bdec449b1d9ea57d39596954971" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "cc3f72d557f455a2007da806998b8b763c38c131" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "a23bb20be73c3ab8405cf1264469048dc22d027e" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH1.php
		hash.sha1(0, filesize) == "6e53c5dbbdf61a9cfa527ab2882303118dd03692" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.1.11 */
		hash.sha1(0, filesize) == "cd3b469c4b1503d15d2cca1a797be5a5512dc141" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "c129cce146f4c256bf67e1457400afd813bfa677" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "da379747dcf7875aaaeeb5a7033f23609518c4b9" or // vendor/symfony/process/Process.php
		hash.sha1(0, filesize) == "5eaec66ad7c4e08384550cea788aaf774f8aed8c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.1.12 */
		hash.sha1(0, filesize) == "086c176ae4e7e5646fef9d1bd59b7bca237cd770" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/links.phtml
		hash.sha1(0, filesize) == "6a4ac438335055f2c6c11e55ab1999c215f14e19" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "dc9bcdad8e1dcacabf1bb1c7911a9e3442b71739" or // vendor/phpseclib/phpseclib/phpseclib/Net/SSH2.php
		hash.sha1(0, filesize) == "3c18c3e87cc8a0acd751a3d00cf214a66a0238fd" or // vendor/phpseclib/phpseclib/phpseclib/Net/SFTP/Stream.php
		hash.sha1(0, filesize) == "5d98e7c19aa3de7357d2db989b8073f7ca42a63c" or // vendor/symfony/filesystem/Tests/FilesystemTest.php
		
		/* Magento2 2.1.13 */
		hash.sha1(0, filesize) == "7c51edd333a7b2018cf4df44c80a94c5b99e7300" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "24756173c733960651944ebc84fca62b5ebe4700" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "44e349e59c1b9ab3197874065916af15bf55bd8d" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "fbd29c51a445f7822ef9b571716f9b4ddc70b7d2" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "d8a4719ec45463b2f24c2c402e217b669f47e865" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "927662c6812bde2292995180f11009d2ab564fdf" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "64c683ac71020dda7a65fc9f246ab3931c389b3a" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "8970e14580ef6a85920d23d285b42b1d50fe3b0f" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "112ce2a27bd9ccfe39bd6fe422f0c1dd00535ed4" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "cb41fcc6f7ff5005387f1d3952bb59859cefa6af" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "92c27bde01b4e9f005b0244668f872f1b063645b" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "c11e08cc70ea47f9c76c0252c47342ea0dcc63cd" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "a1e8b6b6cece2378a626fcd7640caeb575807a81" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "e8f824853c18d7956ad402d15584c884e022e279" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "e37c36c6c67d6c0726472bc792bbd96b76487ec9" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "366915b0c87c90d23c1516c88ddfce085aff3055" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "eee01dbf0891bf294a6e72dcab9ec79b27558a5a" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/links.phtml
		hash.sha1(0, filesize) == "61598b8e555ed8e00cb6fdd1a3bd9ae8c2db5631" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "5bcc966ecf955e4c7df5e93cfb502c367ec36170" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "3d8308628c5ac8518017d2655501b41fa2e04e4a" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "6a7131f77cd11804e2f607f4acca903761bbe444" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "3178b409e706058fdf9d96180444b779e411ecc9" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "d43603dee33dc0e3368f09c2e759e59239e309b5" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "c130c0553897052c22eba031eb234f34a440ee12" or // dev/tests/api-functional/framework/bootstrap.php
		hash.sha1(0, filesize) == "3156b1477f7b924c72a5d277f5b5e321ddf7e5ef" or // dev/tests/integration/framework/bootstrap.php
		hash.sha1(0, filesize) == "b900ac374f064046262e00d5005a81345f142e68" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "50215084a2d1c6680f84037560f9f7c38f8b50d2" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "53afa63b4d6c0225dacf5a415303bc4d37a78293" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "a5153b12896785bdb61576ffe6a087cf0ee5f288" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "29b626fbd91b2bbac0e6b8e1a6319f4b3a194e3d" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "a8a7eca1c7e1537d4dd5a29f9dba9ee527778d8e" or // lib/internal/Magento/Framework/View/Design/Theme/Validator.php
		hash.sha1(0, filesize) == "4e0e218e27b5e21ca4884638459b5b382097c162" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "9458004e6cbcf3bb8a46e6d3ed1a131ffce648f4" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "90493ac76005304e9cc8b8501217417eb7f46b74" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "5df3a83a6b78c80693b0fd9b1e92c02229e02abf" or // lib/internal/Magento/Framework/Validator/Constraint/Option/Callback.php
		hash.sha1(0, filesize) == "368ae2496b85f80b771dc11ddfed4a8f68db368f" or // lib/internal/Magento/Framework/Shell/Driver.php
		hash.sha1(0, filesize) == "1ed9b8d05f8f0f430af2a5886a7394156809d034" or // setup/src/Magento/Setup/Model/FixtureGenerator/BundleProductGenerator.php
		hash.sha1(0, filesize) == "95a42e9ce7d06999cf5c3dd764b0af88c54dff86" or // setup/src/Magento/Setup/Model/FixtureGenerator/ProductGenerator.php
		hash.sha1(0, filesize) == "2523c8fc35c8664f137545e4a5ee20a431492c1b" or // vendor/phpseclib/phpseclib/phpseclib/Crypt/RSA.php
		hash.sha1(0, filesize) == "9c5371ae100c7c27c02e5de69b206719a43cfc10" or // vendor/phpseclib/phpseclib/phpseclib/Math/BigInteger.php
		
		/* Magento2 2.1.14 */
		
		/* Magento2 2.2.0 */
		hash.sha1(0, filesize) == "b6db2ab078b844581bca4a7738a09301b001a616" or // app/code/Magento/Backend/view/adminhtml/templates/store/switcher/form/renderer/fieldset/element.phtml
		hash.sha1(0, filesize) == "afe78caf47645422b625a226bcc626f3c7ac2b0c" or // app/code/Magento/Backend/view/adminhtml/templates/widget/grid.phtml
		hash.sha1(0, filesize) == "ce662262e8069fecf6ecccff489d3104a345c405" or // app/code/Magento/Backend/view/adminhtml/templates/widget/grid/extended.phtml
		hash.sha1(0, filesize) == "14f70c016953e5666aa2ff348dd22853e876c62f" or // app/code/Magento/Backend/view/adminhtml/templates/widget/form/renderer/fieldset/element.phtml
		hash.sha1(0, filesize) == "34b8bbe912147d30f987c4ee092a73e8326e7758" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "0c16b0bea0813fd8f46d2616ad456ec9fa56689e" or // app/code/Magento/Quote/Api/CartRepositoryInterface.php
		hash.sha1(0, filesize) == "cd8a35413f9c1074aa1e7ec08e5618cc9536b7fa" or // app/code/Magento/Quote/Api/GuestPaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "98ffa5253645057aa3bb280ecfb50ffe3cb59afd" or // app/code/Magento/Quote/Api/PaymentMethodManagementInterface.php
		hash.sha1(0, filesize) == "0ae06d3897650908a07fe98c8cd1b7031f6e1338" or // app/code/Magento/SalesRule/Api/RuleRepositoryInterface.php
		hash.sha1(0, filesize) == "207bb68440ed72255299ece2dbee10b743b39eef" or // app/code/Magento/SalesRule/Api/CouponRepositoryInterface.php
		hash.sha1(0, filesize) == "079e6f766546e34702427f2c06f3ccb0ecb1648a" or // app/code/Magento/Sales/Api/InvoiceRepositoryInterface.php
		hash.sha1(0, filesize) == "f97aa293b22bfded923f302a135dc10af84a3b87" or // app/code/Magento/Sales/Api/TransactionRepositoryInterface.php
		hash.sha1(0, filesize) == "c5c618fbb4811d44d5e8e4fefd741cac1b51db92" or // app/code/Magento/Sales/Api/OrderItemRepositoryInterface.php
		hash.sha1(0, filesize) == "04898244b37732984fd9a9db1fb221103e19c0f8" or // app/code/Magento/Sales/Api/ShipmentRepositoryInterface.php
		hash.sha1(0, filesize) == "4a59a7a58889235c8c2e84868a8f4f6707ddb714" or // app/code/Magento/Sales/Api/CreditmemoRepositoryInterface.php
		hash.sha1(0, filesize) == "1de03af3ee8742af0cf9ff92667b70c901fc363a" or // app/code/Magento/Sales/Api/OrderRepositoryInterface.php
		hash.sha1(0, filesize) == "d801e2eea2127191b9b91f7d791762ba756ee8a9" or // app/code/Magento/Sales/view/adminhtml/templates/order/details.phtml
		hash.sha1(0, filesize) == "ffc9afc5a809197e70f2fa674e8ae4b818481584" or // app/code/Magento/Sales/view/adminhtml/templates/order/view/items.phtml
		hash.sha1(0, filesize) == "a3bd2339d5f24c3c4fed720a4cfd8aea0721c5a6" or // app/code/Magento/Sales/view/adminhtml/templates/order/view/items/renderer/default.phtml
		hash.sha1(0, filesize) == "0181a2ae1439dabb2af8f2f9233b0a76afcb20fa" or // app/code/Magento/Sales/view/adminhtml/templates/order/create/items/grid.phtml
		hash.sha1(0, filesize) == "b5e66ae20d0d97d6be5d9d0c1e369601874db3fe" or // app/code/Magento/Wishlist/view/frontend/templates/item/list.phtml
		hash.sha1(0, filesize) == "af78073d01fd1375a1c968c423dc6c655c079a5b" or // app/code/Magento/Wishlist/view/frontend/templates/item/column/cart.phtml
		hash.sha1(0, filesize) == "08fcaae7bccdf6b6e45971ed8dceabda0d6ac21b" or // app/code/Magento/SendFriend/view/frontend/templates/send.phtml
		hash.sha1(0, filesize) == "01da257f9949f057e1f4aadeb1dd9237de95c99e" or // app/code/Magento/Widget/view/adminhtml/templates/catalog/category/widget/tree.phtml
		hash.sha1(0, filesize) == "79148b03f41a7ca68b225bf4b55ebaf71b24a807" or // app/code/Magento/Tax/Api/TaxClassRepositoryInterface.php
		hash.sha1(0, filesize) == "7372bd4e85514ec15505b5713c503858d0f2b3ee" or // app/code/Magento/Tax/Api/TaxRuleRepositoryInterface.php
		hash.sha1(0, filesize) == "1818d990e5d11b0cbff9f4f087b82f519ddbdd0e" or // app/code/Magento/Tax/Api/TaxRateRepositoryInterface.php
		hash.sha1(0, filesize) == "8e564e0a37cc7415242eb40f27219d8faa6b31ac" or // app/code/Magento/Checkout/view/frontend/templates/cart/item/default.phtml
		hash.sha1(0, filesize) == "44c7222533b59f34b18f024d690ca0538549709f" or // app/code/Magento/Review/view/frontend/templates/customer/list.phtml
		hash.sha1(0, filesize) == "40fe1c9cb835f97037a9cd658dfcaa83ba60573a" or // app/code/Magento/Captcha/view/frontend/templates/default.phtml
		hash.sha1(0, filesize) == "0b021ba9ecf368d0de1322cd30204f72044fb881" or // app/code/Magento/Captcha/view/adminhtml/templates/default.phtml
		hash.sha1(0, filesize) == "f2cc39f08f1d7443928602f5deeb3082e47b7694" or // app/code/Magento/Theme/Test/Unit/Model/Design/Backend/FileTest.php
		hash.sha1(0, filesize) == "ad3da30d309429604417dd4b0297b4d773ff2670" or // app/code/Magento/Bundle/view/base/templates/product/price/tier_prices.phtml
		hash.sha1(0, filesize) == "65527739573da193f845f9a8622004f40a128b47" or // app/code/Magento/Shipping/view/adminhtml/templates/order/tracking/view.phtml
		hash.sha1(0, filesize) == "1518288cb19835a65baa67a024dd110401be0f10" or // app/code/Magento/Msrp/view/frontend/templates/render/item/price_msrp_item.phtml
		hash.sha1(0, filesize) == "21ac5cc041e00fec66eec002e8e983f459254b7a" or // app/code/Magento/Msrp/view/base/templates/product/price/msrp.phtml
		hash.sha1(0, filesize) == "dd796a759222f12779bef3ab3ced780c8f3d89a8" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "43ac934baf978b89030311f5a55e96d149a0e9ca" or // app/code/Magento/AdminNotification/view/adminhtml/templates/toolbar_entry.phtml
		hash.sha1(0, filesize) == "e5aa32e8c86107a517d6b74067a87a41e1c0dc43" or // app/code/Magento/Reports/view/frontend/templates/widget/compared/column/compared_default_list.phtml
		hash.sha1(0, filesize) == "4514dbaabb5bc4870233cd8d7b2d610c6c85bde6" or // app/code/Magento/Reports/view/frontend/templates/widget/compared/content/compared_grid.phtml
		hash.sha1(0, filesize) == "01e3bc7d3eadddff9ee630ea43835b88b5218975" or // app/code/Magento/Reports/view/frontend/templates/widget/compared/content/compared_list.phtml
		hash.sha1(0, filesize) == "8ba84ae0118091693c08531e7fbeb9405aeeb27b" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/column/viewed_default_list.phtml
		hash.sha1(0, filesize) == "662b14890cd60c4608b7b835e634852eed1f54ca" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/column/viewed_images_list.phtml
		hash.sha1(0, filesize) == "2137d2c24baa2f18f1f01c98efc0cd44b6b95cbd" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/content/viewed_list.phtml
		hash.sha1(0, filesize) == "bc5b153e7c4992793ebe7202fc261585b42d934b" or // app/code/Magento/Reports/view/frontend/templates/widget/viewed/content/viewed_grid.phtml
		hash.sha1(0, filesize) == "5324e08305e04a14af969c2885c304915ca8ef8a" or // app/code/Magento/Customer/Test/Unit/Controller/Account/EditPostTest.php
		hash.sha1(0, filesize) == "da8611c59ea795d8da55cba0e2ecadec4b1980dc" or // app/code/Magento/Customer/Api/GroupRepositoryInterface.php
		hash.sha1(0, filesize) == "0cf2358bfe71370b5933f697a20173f6a77966cf" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "54dae744d92fbd1e846a72acadf1a6f84fb4e4bf" or // app/code/Magento/Catalog/view/frontend/templates/product/image_with_borders.phtml
		hash.sha1(0, filesize) == "da3739beeb859ec0a604b8973537223b9929f0bc" or // app/code/Magento/Catalog/view/frontend/templates/product/listing.phtml
		hash.sha1(0, filesize) == "cbd37a04f47f4b41a056f64a48c20c7b3ebe1059" or // app/code/Magento/Catalog/view/frontend/templates/product/list.phtml
		hash.sha1(0, filesize) == "ebb7de64e8b564c9cc2537b64873e45f8d897f9b" or // app/code/Magento/Catalog/view/frontend/templates/product/widget/new/column/new_default_list.phtml
		hash.sha1(0, filesize) == "d729b49bd79eb095c2ee18840332104b6af101e5" or // app/code/Magento/Catalog/view/frontend/templates/product/widget/new/content/new_grid.phtml
		hash.sha1(0, filesize) == "b73df2971f39ea069f5ff603968317d4cf0e0eeb" or // app/code/Magento/Catalog/view/frontend/templates/product/widget/new/content/new_list.phtml
		hash.sha1(0, filesize) == "7bcecca698ca026a18d1c0cd6e331d4f01eb1543" or // app/code/Magento/Catalog/view/frontend/templates/product/list/items.phtml
		hash.sha1(0, filesize) == "9204037f1c67ab821f39968485878197f08ebbe9" or // app/code/Magento/Catalog/view/base/templates/product/price/tier_prices.phtml
		hash.sha1(0, filesize) == "7baae16a321991eff163cf6d353c3c80c181068e" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/options.phtml
		hash.sha1(0, filesize) == "1bef553f7eb2283e8b01157976f26a0337288b9c" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/set/main.phtml
		hash.sha1(0, filesize) == "83ab7e20e3b06491fc1955f8fc7c44d9f1da0461" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/form/renderer/fieldset/element.phtml
		hash.sha1(0, filesize) == "2b3d818faf3f19e9b209214e5ae269ec56f0f767" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/category/tree.phtml
		hash.sha1(0, filesize) == "af41b79ef688e3b085febdcf3c1fdcfac2a52604" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/category/widget/tree.phtml
		hash.sha1(0, filesize) == "3eda25a37ba1020ed42cf8473f21939675431823" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "d3c540171d56f22ba4b56d54bfca2b9b9237d5c9" or // app/code/Magento/CatalogSearch/view/frontend/templates/result.phtml
		hash.sha1(0, filesize) == "ccc3f04e8cbd3c16a047ef32ddd027949074923d" or // app/code/Magento/GroupedProduct/view/adminhtml/templates/catalog/product/composite/fieldset/grouped.phtml
		hash.sha1(0, filesize) == "9972746ccc65347da99374bff4c0db476918a025" or // app/code/Magento/Eav/Api/AttributeSetRepositoryInterface.php
		hash.sha1(0, filesize) == "ffe737082a4b67be6fecf8a49bcd9f9be2a4ebc9" or // dev/tests/js/JsTestDriver/run_js_tests.php
		hash.sha1(0, filesize) == "6f0496267604509f0b503df35e457402c52efc60" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "8575bd806d0585be272180dd48e9bb29bd23bd41" or // dev/tests/static/testsuite/Magento/Test/Legacy/ObsoleteCodeTest.php
		hash.sha1(0, filesize) == "6f6fc4f538cadc28ddd6c34b0b621e1d1f3694be" or // dev/tests/static/testsuite/Magento/Test/Legacy/_files/obsolete_classes.php
		hash.sha1(0, filesize) == "43a229164a52722b65e342fefe66384c376fc3e6" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "5ff6371675c12bcb8220e4e7ae2de389cf93c9b0" or // lib/web/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "1cf08f4739f91ac22a1db82b2fbf5371c5dced70" or // lib/web/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "1c6d46cc48f55aeee643ac8dfb81307c538240ee" or // lib/web/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "87afdc3d9e944d395a589228fd67d21e88a88546" or // lib/internal/Magento/Framework/Shell.php
		hash.sha1(0, filesize) == "66689eb745afaccd13b86a635663a70c68979839" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "cc769ea55968156fe55010ec8f342f326c4892bf" or // lib/internal/Magento/Framework/Filter/Test/Unit/TranslitTest.php
		hash.sha1(0, filesize) == "af2c52546d499780ffab9305c09712c226153b30" or // lib/internal/Magento/Framework/Api/Code/Generator/ExtensionAttributesGenerator.php
		hash.sha1(0, filesize) == "637424f32393446c14e84e5ccdc523b799d5a62c" or // lib/internal/Magento/Framework/Shell/Driver.php
		hash.sha1(0, filesize) == "a4eea004d560338df63eb552c5255ec0956b447a" or // setup/src/Magento/Setup/Model/FixtureGenerator/BundleProductGenerator.php
		hash.sha1(0, filesize) == "b4b7e15e1c2586281bc859487e175bf162ad09a8" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "a3bb9711fc5f3fd102e83a784b18fbecbdf51e56" or // vendor/friendsofphp/php-cs-fixer/src/Tokenizer/Transformer/CurlyBraceTransformer.php
		hash.sha1(0, filesize) == "30ca0624b916566d59d375f8dcb981fe0bbe80fe" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "b40c17220eb892683bdbe49dafb99f3544b9707a" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "b578dadd560b9fa5e6c7cc534e43c58b933d0ee8" or // vendor/zendframework/zend-config/src/Reader/Json.php
		hash.sha1(0, filesize) == "d0f531929accaa989747bce64e5d1d18619c266d" or // vendor/zendframework/zend-config/src/Reader/Yaml.php
		hash.sha1(0, filesize) == "c3efc47e0a6f3d2ce786d65903ba4bf7b18b8465" or // vendor/zendframework/zend-config/src/Reader/Ini.php
		hash.sha1(0, filesize) == "8e0199d56990d9548e906c7f43d8b6a0acc91b09" or // vendor/zendframework/zend-config/src/Reader/JavaProperties.php
		hash.sha1(0, filesize) == "49005b49d6358ba62e1e63b062549e6be44e84c5" or // vendor/zendframework/zend-i18n/src/Validator/IsFloat.php
		hash.sha1(0, filesize) == "7ebb06e9d13316c1b9014d89a80335a5801534de" or // vendor/zendframework/zend-view/src/Helper/Navigation/AbstractHelper.php
		hash.sha1(0, filesize) == "2a8ad0ada4579b7a093258b53fd654726a39b82f" or // vendor/zendframework/zend-soap/src/Client.php
		hash.sha1(0, filesize) == "5d0abe2949deabd3c8402a53e1335ec1a1a10a7a" or // vendor/monolog/monolog/src/Monolog/Formatter/LineFormatter.php
		hash.sha1(0, filesize) == "679d1e5f586fd2c0604d49035d07ee76fa80b4eb" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "c77c8aa209d8ce38742a83a569b37d2c4d86960a" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		hash.sha1(0, filesize) == "dcc4d118f3df90212cc0f83562a6526b57839510" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/Arrays/DisallowLongArraySyntaxUnitTest.inc
		hash.sha1(0, filesize) == "ce5d95770d202ca5ca20351d0809c44973614361" or // vendor/squizlabs/php_codesniffer/src/Reports/Emacs.php
		hash.sha1(0, filesize) == "32f8aa52981b30d5b6b9ad3064e6c4835292611e" or // vendor/phpspec/prophecy/src/Prophecy/Argument/Token/ApproximateValueToken.php
		hash.sha1(0, filesize) == "83f41387b29273eb40aefd1135e9e361c867631d" or // vendor/paragonie/random_compat/lib/random.php
		hash.sha1(0, filesize) == "c4d30424cccf6ec0f7419ee7a5f23db7a7c4b4e5" or // vendor/composer/composer/src/Composer/Util/Git.php
		hash.sha1(0, filesize) == "27e9cf7038646a28442aa46d37a28ec8e8716df1" or // vendor/composer/composer/src/Composer/Console/Application.php
		hash.sha1(0, filesize) == "9e225727717be62c96ce263044b4a26368d6b1f8" or // vendor/composer/composer/src/Composer/Json/JsonManipulator.php
		hash.sha1(0, filesize) == "dfe5659d01d976f2c204d7d38f24202747a7249f" or // vendor/composer/composer/src/Composer/Command/ShowCommand.php
		hash.sha1(0, filesize) == "d2d335780856a9bb3e75aa80d955455866dd9918" or // vendor/composer/composer/src/Composer/Command/ConfigCommand.php
		hash.sha1(0, filesize) == "3f3e243765fc816c8b654cd2eeb31ccbfffd876c" or // vendor/sebastian/environment/src/Console.php
		hash.sha1(0, filesize) == "1f7106a3fecd6a51f579d358089fc57a8249b6bd" or // vendor/phpunit/phpunit/src/Util/Log/TeamCity.php
		
		/* Magento2 2.2.1 */
		hash.sha1(0, filesize) == "7b4ca1bdf6da1b74bbb0e79cd5dca7e9358736fc" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "793f57e591242b263cdb8f438b487218eb222602" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
		
		/* Magento2 2.2.2 */
		hash.sha1(0, filesize) == "5c9d6542625efa7d9598d8670810fb4d2348c372" or // app/code/Magento/Customer/Api/CustomerRepositoryInterface.php
		hash.sha1(0, filesize) == "1ef0a76c00bbb37bbfc517675da2e6e75d6c69a4" or // app/code/Magento/Catalog/view/frontend/templates/product/list/items.phtml
		hash.sha1(0, filesize) == "bd9313c7fbeba61c905a3b9c13000d3c5316aa9c" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/category/tree.phtml
		hash.sha1(0, filesize) == "cbe1572a603dad3fbdaace2c9aeaf437db0c399d" or // lib/internal/Magento/Framework/View/Model/Layout/Merge.php
		hash.sha1(0, filesize) == "0fc99eccb4f7e3841f1f05a3acd274f44d07d784" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "f897f0201b4182cb13eb4fb07e6f685134f79e1d" or // vendor/friendsofphp/php-cs-fixer/src/Tokenizer/Transformer/CurlyBraceTransformer.php
		hash.sha1(0, filesize) == "18ceffbba547979679a41af4e1a1fb50673b521b" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "77d1c0c1403658f3b695ea297c62d3123a2d2afa" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "767c952605047fe1d2b6cde9ea959fa7419bf446" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "e806c939435bf2184070293d5f0e5786b0e260e4" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/Arrays/ArrayDeclarationUnitTest.1.inc
		hash.sha1(0, filesize) == "1e60b0a55c7010e44d1984dd3429faae582d66ab" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/Arrays/ArrayDeclarationUnitTest.1.inc.fixed
		
		/* Magento2 2.2.3 */
		hash.sha1(0, filesize) == "3d02e278b1aa38f9bc8ac8ce11a2b7507c67c4db" or // app/code/Magento/Checkout/view/frontend/templates/cart/item/default.phtml
		hash.sha1(0, filesize) == "097a07a8a48dcd13a0c3b8125b3b41fa5b89aeba" or // app/code/Magento/Downloadable/view/adminhtml/templates/product/edit/downloadable/samples.phtml
		hash.sha1(0, filesize) == "ec460f47a07de4973809bf83892325a053ab79d1" or // app/code/Magento/Catalog/view/frontend/templates/product/list.phtml
		hash.sha1(0, filesize) == "9bbeb014444ce6c87048116cd3ac6b0cf1cf7c76" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/set/main.phtml
		hash.sha1(0, filesize) == "5442561bcc0385b43e0fe5a68ccf98bbdec5ca72" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "bea5262b4308701259351b7d7ebbb718fedb60cb" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "c1ca941e582ca86847dde4197d6369dd48adc895" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "a33b73c4bb7d6b481092b146c92f2ce76971783e" or // vendor/zendframework/zend-soap/src/Client.php
		hash.sha1(0, filesize) == "33f2a3d42332b90bd774681ea1a35645f18e6613" or // vendor/symfony/console/Application.php
		hash.sha1(0, filesize) == "e9a33f8a16f28125962bdcd2fd692171cb5e50e7" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.2.inc.fixed
		hash.sha1(0, filesize) == "6148ebd6cb92f7d126f584cc28bc2dae00d420f8" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.1.inc.fixed
		hash.sha1(0, filesize) == "1e6dfa2f9ca1655679ef3372b9b5adecf7950250" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.2.inc
		hash.sha1(0, filesize) == "b6558129f141c2872fd3bababa30fa2197f464c8" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/WhiteSpace/ScopeIndentUnitTest.1.inc
		hash.sha1(0, filesize) == "dcc4d118f3df90212cc0f83562a6526b57839510" or // vendor/squizlabs/php_codesniffer/src/Standards/Generic/Tests/Arrays/DisallowLongArraySyntaxUnitTest.1.inc
		hash.sha1(0, filesize) == "e6916494d90eab4a3cb2cd60cecdbeb606c78036" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/WhiteSpace/OperatorSpacingUnitTest.inc
		hash.sha1(0, filesize) == "0125f48763b161a35ede5618b3fa554061a64ed6" or // vendor/squizlabs/php_codesniffer/src/Standards/Squiz/Tests/WhiteSpace/OperatorSpacingUnitTest.inc.fixed
		
		/* Magento2 2.2.4 */
		hash.sha1(0, filesize) == "f023851dc5ec2d325b9b29b202afc79e487adeff" or // app/code/Magento/Backend/view/adminhtml/templates/widget/grid/extended.phtml
		hash.sha1(0, filesize) == "7991cdeefa71c33b030c8146c547b56bf19a35b6" or // app/code/Magento/Backend/Model/Url.php
		hash.sha1(0, filesize) == "a4c0e1b01b752273f623267773d4b0941f5ec91f" or // app/code/Magento/Captcha/view/frontend/templates/default.phtml
		hash.sha1(0, filesize) == "2f4f179b463d43d7125c0edf96207cdaac0d3553" or // app/code/Magento/Captcha/view/adminhtml/templates/default.phtml
		hash.sha1(0, filesize) == "88688495df8a381a7e2f8c7d78244dc5aa3e449f" or // app/code/Magento/Catalog/view/frontend/templates/product/list/items.phtml
		hash.sha1(0, filesize) == "bc14eb76d717597ea55e5a059ac9027f9e37c41e" or // app/code/Magento/Catalog/view/adminhtml/templates/catalog/product/attribute/options.phtml
		hash.sha1(0, filesize) == "f5ff153b3ce5fe74d8555fafc7c4f5b338e72cd9" or // app/code/Magento/Catalog/Model/Product/Image.php
		hash.sha1(0, filesize) == "94295c58e11d35c4384bd5533a56b251b3a9f899" or // app/code/Magento/CatalogWidget/view/frontend/templates/product/widget/content/grid.phtml
		hash.sha1(0, filesize) == "caa1cdbac108de22eb304a1001b6387d66d3c8d1" or // dev/tests/integration/testsuite/Magento/Framework/Image/Adapter/InterfaceTest.php
		hash.sha1(0, filesize) == "554d4e860b7c9ac7e748634db8f2ce7d8a84de34" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "771f8a7b6cefa10280c8ca3664a481b89f97dc51" or // vendor/friendsofphp/php-cs-fixer/src/Tokenizer/Transformer/CurlyBraceTransformer.php
		hash.sha1(0, filesize) == "2c86d6b8985585facf4b82b459129890e67a8585" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "205f447fdd5382d4cec93066916bc36593117b89" or // vendor/paragonie/random_compat/lib/random.php
		
		/* Magento2 2.2.5 */
		hash.sha1(0, filesize) == "896c509fd0d3a1b2c5c68a31078c07227012ad87" or // dev/tests/static/testsuite/Magento/Test/Integrity/DependencyTest.php
		hash.sha1(0, filesize) == "fdf2c68d82619b50dcbb254cc1378c7ae19fc410" or // vendor/friendsofphp/php-cs-fixer/CHANGELOG.md
		hash.sha1(0, filesize) == "0c4aaf74d31d6553acdee867a44439f7b2e58c01" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocAlignFixer.php
		hash.sha1(0, filesize) == "e2615e1467ebca61785a35d1f3716fd144722527" or // vendor/friendsofphp/php-cs-fixer/src/Fixer/Phpdoc/PhpdocSummaryFixer.php
		hash.sha1(0, filesize) == "163720043b85199587fd2183a1311dacb3cec5c1" or // vendor/paragonie/random_compat/lib/random.php
		
		false
}
