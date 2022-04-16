private rule Magento1Ce : ECommerce
{
	condition:
		/* Magento CE 1.1.1 */
		hash.sha1(0, filesize) == "743c76e95b3849137c6b5552b568fa3c780c46f6" or // downloader/Maged/Pear.php
		hash.sha1(0, filesize) == "382cace9be19b080426456e4c984730c8ffbebf3" or // downloader/pearlib/php/System.php
		hash.sha1(0, filesize) == "7e0bab1294ba48689824a21e065d9643695e9f3c" or // downloader/pearlib/php/pearmage.php
		hash.sha1(0, filesize) == "f14a60868f4a51ee998e5e53de8bcffeecfaa56e" or // downloader/pearlib/php/pearcmd.php
		hash.sha1(0, filesize) == "174d2e99fbd72d9c11021e4650f2295fdf638083" or // downloader/pearlib/php/PEAR.php
		hash.sha1(0, filesize) == "f70bdefded327939aaa420b317e3bc15907cec3b" or // downloader/pearlib/php/PEAR/Registry.php
		hash.sha1(0, filesize) == "33c0a85ca6fa3a068656c404d9fcae90d687a399" or // downloader/pearlib/php/PEAR/Config.php
		hash.sha1(0, filesize) == "1c9b78e26352d32eaeb913579fb7789c2c9f567b" or // downloader/pearlib/php/PEAR/DependencyDB.php
		hash.sha1(0, filesize) == "f8bd96af3ec71ba5c4134d363cc50a209b9aef75" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "64bb826dd3bebbc228731e7997e157678acae8a9" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "4a0efdf2ad68ae8f602b53b82451171e65f82c09" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "d81f736df877f9126e4b55d1576e6f4fc932187e" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "bd99da4961c6fdd32b613a0038f6795d6810258f" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "1f3f1c184b3d1bdfe5243305320ce65a240f0485" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "b6c0294bc06354096936ba415a973e7e7b596c1a" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "8a1291211cbdcc17b26fd41b60a67eb0c35d25be" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "fcfdc0cb032200b95bdf177c0b50041e02c49d23" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "888454d2cea4ee1e53c60eee13b0454397d39c22" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "a0d304e026db4b836f3fbc71a6e77bc470f1b07c" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "c574ef276266161c851696615ae77b9f7a1a1b43" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "aeb3f5e823029465cbb7c3edbf84180bc0889952" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "5e3470d274cd5b2e279ac978ded8f220772df0be" or // app/code/core/Zend/Cache/Backend/File.php
		hash.sha1(0, filesize) == "0ccb0666a924e7c5167256e1b0751a0427ab2098" or // lib/LinLibertineFont/LinLibertineC_Re-2.8.0.ttf
		hash.sha1(0, filesize) == "b50d4664c1a7789fe6826a16a4970d65e51dc3fa" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "67386af90cbdb52a40ae5e458e2c7ac4688eddd2" or // lib/Varien/Data/Form/Element/Date.php
		hash.sha1(0, filesize) == "29012eb0dfee3e1b32ec76d433357b8c545540e7" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "c4a0b1abe86508dde3ffaaf1731796586d3b2333" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "0367960b396fbc2db3654ecf6dac52e89788d117" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "b40603ca11ce90532da0a853d45120e00e6de413" or // lib/Varien/Db/test.php
		hash.sha1(0, filesize) == "aae982ba3996eda190fa0c734f15f07253c1e51e" or // lib/Varien/Db/Tree.php
		hash.sha1(0, filesize) == "f9b9451b6c78160d889ecf1ba48020a6c17872b2" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "7477aa9fe2d3f24e7d32a53e3588dda01ee5fe26" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "8b92c7a7efc45174190dcb65b07beddf9e4d7153" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "4ce8e354e898f9c8986dbc9326a672b3312f6c69" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "7d0c4da4d1eade1f6c6633ade14121ab10c56d9f" or // lib/Zend/Cache/Backend/File.php
		
		/* Magento CE 1.1.2 */
		hash.sha1(0, filesize) == "05943fb7d0b4d698f6e4369e601254efb3fb00ef" or // lib/LinLibertineFont/LinLibertine_Bd-2.8.1.ttf
		
		/* Magento CE 1.1.3 */
		
		/* Magento CE 1.1.4 */
		
		/* Magento CE 1.1.5 */
		hash.sha1(0, filesize) == "a08c529465cbfdd88eff785e55487419a35041e5" or // downloader/Maged/Pear.php
		hash.sha1(0, filesize) == "7da9ee530dd22d47e4adc7f9cfe4bd5f31f8d426" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "c0286fe2fd26330143cfc53b984cf543ea4284b9" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "ee55c97ab67e3c220d2138dcb4b7f795ed424e57" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "56750037b5fb0beba3541a6405d46684235619ca" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "35d6542180b2d89477d2923151e755e2c438c06c" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "cf2450914ca13e60d30dacd243c9e4962785ff0b" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "e6c2bd60400cae9b30095328ec9d378af98d8bd9" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "450c9c35b69b5cdbfd82378247f2bd5e06c102ee" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "055bc24efb7da2740bf3e50e25fa91ac193b4f4c" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "8c3922d6b86d2d783cb68775a3eb1ca91bfa6ffb" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "b53329d05fefd512edc86f9a11c50e1f10b7543f" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "f87abb261a2dcc9b163314e47939fb89859574d1" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "a84f4c6b83a61dab0db37730b0f938b4e8473330" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "cbb147789c7072f587890b8332dad9bed063bb2d" or // lib/Varien/Data/Form/Element/Date.php
		hash.sha1(0, filesize) == "0159b4c43eae084bedbadc494d1298e3e181f4b0" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "44c3494ba9233407b0a5476d6cf9dc1eabd0f28a" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "6f259b077f88ad086b64a48a6fa0d0b40bd2a899" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "1061b92949e6c336246b5020d39be60ece155d63" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.1.6 */
		
		/* Magento CE 1.1.7 */
		hash.sha1(0, filesize) == "df23a41ed1e7996020489270e90a4aa2aa2be89d" or // downloader/Maged/Pear.php
		hash.sha1(0, filesize) == "ede3de4e1f73a6d047e7086d8317e06a6bf3be50" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "9cf1ea4c8cf4bc5e0b3a73a918d87c7663472c83" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "d7e5697b32e415f4db5f3fcc1d329577732a71c6" or // lib/Varien/Data/Form/Element/Image.php
		
		/* Magento CE 1.1.8 */
		
		/* Magento CE 1.2.0 */
		hash.sha1(0, filesize) == "d6ebc6b2915ee40734da5ca750ed522cb85dd1a7" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "277fdd2ebdaef4ed69caf17f5c416f1fc84a236c" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "37e38312a8883e404e1e810187cb42bb4eee3fa4" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "2760412ac71dc87364adc8ddd74c10913e9bd9e1" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "98357e8621dcd97741535e97ce2d8d9a72853985" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "286cf3a6569addf0ae4caba845cd94b9c0378158" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "f504a4747192d5428651979295780563491c3c3b" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "a16d202e41bae23330e0c110d5c211bb57ec0d87" or // lib/Zend/Service/ReCaptcha/MailHide.php
		hash.sha1(0, filesize) == "b606b94b19adba03b88b50567f59aae56ef2f91b" or // lib/Zend/Session/Exception.php
		hash.sha1(0, filesize) == "c22e09c85f4be958350c7f08a2570d3c3c1d4650" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "4cf814ec9721da591eb5ca2861eddb80cecc90d5" or // lib/Zend/Cache/Backend/File.php
		
		/* Magento CE 1.2.0.1 */
		
		/* Magento CE 1.2.0.2 */
		
		/* Magento CE 1.2.0.3 */
		hash.sha1(0, filesize) == "125119cd8cb47404d310f10216749983bba7591f" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		
		/* Magento CE 1.2.1 */
		hash.sha1(0, filesize) == "695c700689f7cfdb21ac04a91bed0d39088a381b" or // app/code/core/Mage/Core/Model/Translate.php
		
		/* Magento CE 1.2.1.1 */
		
		/* Magento CE 1.2.1.2 */
		
		/* Magento CE 1.3.0 */
		hash.sha1(0, filesize) == "f4e7a4fd12b9975e64ee9e11791cce63c30aedf7" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "ffdc0c6eb436576f8b68fe40279301ce133b562c" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "5fea618cc39851ff46dea7f25e29fb3b3e0498cf" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "62bff1028824ec8ac0b46cbf492a5fbebe400b08" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		
		/* Magento CE 1.3.1 */
		hash.sha1(0, filesize) == "b3c2e7755a0d2b5c75f918397a5ed7f6feea5577" or // lib/PEAR/SOAP/Transport.php
		hash.sha1(0, filesize) == "4b66586bfa75b202e9227ac784a8ff9629005201" or // lib/PEAR/SOAP/Transport/HTTP.php
		
		/* Magento CE 1.3.1.1 */
		
		/* Magento CE 1.3.2 */
		hash.sha1(0, filesize) == "d7d4f3d1931ee90f7d820d1a754dbeb5e969adc0" or // downloader/pearlib/php/System.php
		hash.sha1(0, filesize) == "7fc1f9a57e67ceb0c1208e15374ce3799bfeccf2" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "c3d1caf978ce50359052d09e1d017814bab8bce2" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "893280bc8bcf75b65e2a59b60df8afcabfb7e4e5" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "c09844900dade96dea89ce6a8b2a7454c3a5c331" or // app/code/core/Zend/Cache/Backend/File.php
		hash.sha1(0, filesize) == "94e01fee6209e3bbd9034af7c83a630d6cc1e664" or // lib/Varien/Autoload.php
		
		/* Magento CE 1.3.2.1 */
		
		/* Magento CE 1.3.2.2 */
		hash.sha1(0, filesize) == "082fd7a80bef30aca4e8d8ae4b1a9f9f6ae78dab" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "7d83812c0d978f2b4a4703e211476b855f20b5e9" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "958de36312c048d2c00aa78c5ea46a8ef48b3a32" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "7395a693295b54c4299f3393a479302b57a0d31a" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "d9bf44dbad9dafa0ea5976628eec3c15bf82b16d" or // lib/Varien/Autoload.php
		
		/* Magento CE 1.3.2.3 */
		
		/* Magento CE 1.3.2.4 */
		
		/* Magento CE 1.3.3.0 */
		
		/* Magento CE 1.4.0.0 */
		hash.sha1(0, filesize) == "7f2002909dd18f949f4ce314e4eb88cfd7cfe995" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "2addd217a3550aee35337810ed0e1827cfe0b759" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "b1a0974f819869bf60687f8138037c1533c005d4" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "e7b2cbeb82280d159a14f56004a9bd57a27c69b5" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "74f315376c667e8663667b43ae01d5f4438a1cae" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "55070101ed51ba9b710a133d443bf06690cc0a3a" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "e47990d40d3dc59cb50fbb8880a8cf7d4f78a291" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "6108e7ed98fed4f1056be8cecc85b3199be13a4d" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "75418233be7d2e5641ccd436b71d9fe7421c10bd" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "0ee9b3a1a41e2d000dbfea245fc048b0996ff1f5" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "5671193e8b5f0d6099382476b110a199cbd648d9" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "8c4b2e07d3f643e9a371772a7cf7b0ead9462270" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "95d8cc1b6a755466ed30d4a306a36d75ef1874f1" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "930af3e546e73fdd7ac82d53a8ccf618ce13316b" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "40cf1134b4ff2088bab26b0d29902f4efe875456" or // app/code/core/Mage/Adminhtml/Block/Customer/Edit/Renderer/Region.php
		hash.sha1(0, filesize) == "a9fbc4360285f686040a1fb42e19ae121ef37e1b" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "cefa8a549ad1ddc4cac45725b83f7a7517041203" or // app/design/frontend/default/iphone/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "f890c4755c69dd318efde4620962b5edd816bc9e" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "3df4377b9682ef76344b5eacdc43acf6a6484e7a" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "aebbeca270ebba508ac3a9e1c178a359006e8dad" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "16615eee0a74cde38b34767a777ce10dbe0dd7c9" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "7832f3a823fe08c5494f5c42a964f49790fb86f2" or // lib/Varien/Data/Form/Element/Image.php
		hash.sha1(0, filesize) == "c0c772d84c95e4737c4ac4849be4129e3e17447f" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "b8734fb02aa55fb19bacc16e848b88681b29f493" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "8a7d49626f09ce662f3a4b2d7c5c2b63e3a0b849" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "c3363ec292bb5cb07ad938853030c127d2b6ef97" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "b5499e5b6ce9bf40b7428cb5d8ba75af73cf36f1" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "063158d99db2cff6927ddb42d3b342c383f086bd" or // lib/Zend/Service/ReCaptcha/MailHide.php
		hash.sha1(0, filesize) == "d97634b7981e003503949f09fa5296658bf29bf4" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "ba5c8b927ccdfff1139ee6274d5cf6c9954bd706" or // lib/Zend/Session/Exception.php
		hash.sha1(0, filesize) == "b3904d9bd5b510249b6607c13adec6aff159b3a4" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.4.0.1 */
		
		/* Magento CE 1.4.1.0 */
		hash.sha1(0, filesize) == "c26d82fca7498e54640b615fabef8c4d45c6655d" or // app/code/core/Mage/GoogleCheckout/Block/Adminhtml/Shipping/Merchant.php
		hash.sha1(0, filesize) == "72863ffa4faa9bb2dd735611afe1310c58aff7f4" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "21ba19ce0f50a4084301e8689f2f7cda2f971204" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "fcd994fe6f9c177e32d64f2dbc11344306da73d8" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "2164a2692f6a7d4a0fe1589b9e2822f3b51a0363" or // app/code/core/Mage/Core/Model/Convert/Profile.php
		hash.sha1(0, filesize) == "b8435034f33e6261ae700052bf6fa9d8b0f821bd" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "a59a390c12706e4aa74e1f91868c8773cfbbbd81" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Category.php
		hash.sha1(0, filesize) == "640c7e18fc10ccb14b9b0fd2ff336f3894928cfb" or // app/code/core/Mage/Sitemap/Model/Mysql4/Catalog/Product.php
		hash.sha1(0, filesize) == "91460799f6a9c6385e9878fd0a79624b8112d079" or // app/code/core/Mage/Directory/Model/Mysql4/Currency.php
		hash.sha1(0, filesize) == "a61f87f2c29575ca5d31933daa9bb4e0c35cc7c5" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "ec5cfd2435a4fb385d5fb3f43249618091d4b1f2" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "34c3ae9b10cc1e3dcd346406daad972de2a9f53a" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "f1d50bfd4dc8cf023bb2467928ee07b8ca277f1f" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "04e7dc316cd70f8851e27d2f1ee094003c79191d" or // app/code/core/Mage/Adminhtml/Block/Customer/Edit/Renderer/Region.php
		hash.sha1(0, filesize) == "75c0b78644517ab431cd2067aeb4c9b606fe5629" or // app/code/core/Mage/Adminhtml/Block/Catalog/Product/Edit/Tab/Options/Option.php
		hash.sha1(0, filesize) == "3bb4df77cbfd37d70c24621a0e1819059bd06a74" or // app/design/frontend/default/iphone/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "2a78243468ee200ee3933d03fc2b52f375516b24" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "3133a72daf3fe6f51778fa89e07f7c7c07de9493" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "5129a7555895007ecc2a1975fcd91cf2d0d8abe1" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "e4269e6d47cbb5c606e916e1fcd80c1acc131e55" or // lib/Zend/Locale/Format.php
		
		/* Magento CE 1.4.1.1 */
		
		/* Magento CE 1.4.2.0 */
		hash.sha1(0, filesize) == "47576a4be1d4f450436ceef01f4d76561b49c10f" or // app/code/community/Find/Feed/Model/Import.php
		hash.sha1(0, filesize) == "b5503689bc6a42a1223019adfde7680b643bba92" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "428645582e2c32c01ce4fbed0efc865a86cc1ce1" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "2ed7f109642dbfec32434d722caea3ba919b78b1" or // app/code/core/Mage/GoogleBase/Model/Service/Item.php
		hash.sha1(0, filesize) == "59eca17b433527c716e39a79c2a6624267039031" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "aac39b74fe44c73becdbc55e1e13a07834f446ae" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "be6109e866f11177febd1a4adff8b8f15dcd7d4b" or // lib/Varien/Data/Form/Element/Editor.php
		hash.sha1(0, filesize) == "382fb51970f59f803508285ee8d2c4a2616ecc73" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "9c0c57a9d2df145526cbde494e00f0798ec40379" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "da6dbd6d8183b366dbf5ec1b4da8a064375452e3" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "af5d43214068dd919d70a61b66fb4b1761957b24" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "4d80fe8363e9d04cb962d50b3d0d88f039673a0d" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "11a78fc89381ba37849a82529b024c656d9025d4" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "7d086827328b7494bc490fb7206b3366d2c38e6f" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "63283e976d5fea1f63c18e8a6793b3a4ab9d71d4" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "1e9a01653ac90098c876b77e97e3670589ec3787" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "d75195ee5082cf62a51e1055e421ee8d4a2143b8" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "078401aeda210badab9ef4fc083a1b75292b2207" or // lib/Zend/Session/Exception.php
		hash.sha1(0, filesize) == "29ab7310cee069c1f6d76b53ec66a9edbd723de9" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "20bf0974e247e157a44f3582ec075ea0d151e446" or // lib/Zend/Ldap/Converter.php
		
		/* Magento CE 1.5.0.0 */
		hash.sha1(0, filesize) == "ca04390be3a2fb9125cc190f85eb6dc1ec99166a" or // downloader/Maged/Connect.php
		hash.sha1(0, filesize) == "d8521a4b500badf5608b9eefb1e7d4923d5c099c" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "542d271f564aa019943e9b5c9e82ba752da3807b" or // app/code/community/Find/Feed/Model/Import.php
		hash.sha1(0, filesize) == "ec386833ed576acee6a0cffae893d727b4fe20f5" or // app/code/core/Mage/ImportExport/Model/Import/Adapter.php
		hash.sha1(0, filesize) == "fe81b3452d5224fa03d122348ebd25fd6cf2bfe2" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "7e847df572b49a30b533058488d47256243281c5" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "b8ec0477409e6a3cf29ef2f5a51dd18457630fc5" or // app/code/core/Mage/XmlConnect/Block/Adminhtml/Mobile/Form/Element/Image.php
		hash.sha1(0, filesize) == "3e4338a076ef79058f5a069a7c07c8c14aae5655" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "4d4913c1f71c8b77ce1748fc1ed2f9c7af26f0e9" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "6409bc5c48b2676c7592c490363f8dbda40f8cb6" or // lib/Varien/Data/Form/Element/Image.php
		hash.sha1(0, filesize) == "8bb683957e1d561f60a0c311f532543b16d70946" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "87cf0da9bfefa24aa8984a902200cf3c073d57af" or // lib/Zend/View/Helper/HeadScript.php
		hash.sha1(0, filesize) == "3686394c1369d3c95d2d4eb6e55af54f2c217edb" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "51f42d5712d78d3949e625bdbb1164fa5df21f37" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "8fee7dddf97ee0020242555eb7b4a210ee0c5ddf" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "997e8decd0cd34c4a5740adb8a54ab1192227a72" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "72077639b329556270e1cb8f67607e3a12818ecc" or // lib/Zend/Form/Decorator/HtmlTag.php
		hash.sha1(0, filesize) == "168196bd79743a1726e6f9c51b8cded7f379071c" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "de086d6b6b7bd97c8cc02a5e71711625b5aa21f4" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "1f44a0506e92fbc4b93f630f2d4e269144e34c98" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.5.0.1 */
		
		/* Magento CE 1.5.1.0 */
		hash.sha1(0, filesize) == "1c1573c2f8fb87dc6d7fa4a86f9bed3966ab1559" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "e219e7d6a09ace697b471c1dff1e818a089e7bdb" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "1348243a2ef778d294f135f1eabd9b447a68276a" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.6.0.0 */
		hash.sha1(0, filesize) == "7c7c0e823b7149758466ce1c46b31cc752098981" or // downloader/Maged/Connect.php
		hash.sha1(0, filesize) == "f5355295887c7c920faec7a6649a3b0e501ed562" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "0d90dfcdadc2385454d6989c89e5619284d06a22" or // app/code/community/Find/Feed/Model/Import.php
		hash.sha1(0, filesize) == "ff8e400bbceefa8fb6ffdd7b6ca7c19424c3724c" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "0cc50b85016c0a281d463eaea15d9a60c8dde353" or // app/code/core/Mage/ImportExport/Model/Import/Adapter.php
		hash.sha1(0, filesize) == "c7b1ac6cb88d57a1ecc9f1228530422418092734" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "6f04c753855b120250fb93c3f18120439bac61a3" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "3ec46431440bbdd6dc012ec88ba8b2abb254a07a" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "08cd39581eebdce66eba747d99564f92aecd81bb" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "73d6f4ad968b6597969a846607c7fc4951da21f8" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "faf6a7d584a991040910bc3c1b75b1b953749dac" or // app/code/core/Mage/Core/Model/Translate/Inline.php
		hash.sha1(0, filesize) == "533d7cf5e90b1d7531d869a733c28a1d7b96c087" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Category.php
		hash.sha1(0, filesize) == "8df77b8fb1861b3a7d56dea614e329072170c4d4" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Product.php
		hash.sha1(0, filesize) == "c4fe77c103e8133560598cddd3f5b5d6d51000ef" or // app/code/core/Mage/Catalog/Block/Product/View/Options/Type/Select.php
		hash.sha1(0, filesize) == "e7d5e027d6d8d5aed1b7e6e2bb9c4823a244d81c" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "13f835ff37292f0f9cc6cf291c2d2c0bf3c6584d" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "910a7ffd9e47fa7323afb954504e7f665959d0dc" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Fieldset.php
		hash.sha1(0, filesize) == "9eddbdda8933a43af895db0198b11212ec0f9ca9" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "ead5c7a448033fdad1d4a6703d4ffc3a46bd3b08" or // app/code/core/Mage/Adminhtml/Block/Customer/Edit/Renderer/Region.php
		hash.sha1(0, filesize) == "35fca9cb6bce8e10563f014a74e6832055f374be" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "1881995b15ffff36404400667af328064456caba" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "a2c4546364372caac2b6565f6b74987df5e54e4e" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.6.1.0 */
		
		/* Magento CE 1.6.2.0 */
		
		/* Magento CE 1.7.0.0 */
		hash.sha1(0, filesize) == "e37b356ab26b4d7acd052139f0ed063a4e242065" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "a675fe32e519294e608a11e0e7ad26c6c0ee39e9" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "21396b418469673c1092f0ab94633f188d7baf15" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "dde0fd41aff7a751e69528f12eecdcb79261239a" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "948a6b886901cae250b4314f7ec1880b5bcd98ee" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "80b6306a8752dde8cebe44334f1c30e60509cae4" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "64c3885b5a8fc86af29bd6f08976d2da87727ddc" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "20a1cd0eb6f110bb98f35f2499614cb442959462" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Category.php
		hash.sha1(0, filesize) == "8b45c11270942e161b69e71e49e1595dc388ad8f" or // app/code/core/Mage/Sitemap/Model/Resource/Catalog/Product.php
		hash.sha1(0, filesize) == "2af8367688d9131c9fb5c6c749f92d46dd216d3e" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "a81945dcfc4fcf2e464669f02fc03bc09b231420" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		hash.sha1(0, filesize) == "0b4971706ce32b91df9649f61c0dbe52fa3c025b" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "b665a86b2caabb9efcf1c2013268cae2ec52dae5" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "9f7c657e9cb4caeeef7fbdf7658bcb93fb7f504e" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "9e002eb833e32a1d8bf0e05b8f817d8e3788e6d3" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "744c53013d70f0ef8d60a4e6ff532d50aba2c798" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "53ad2d03a76e1460b5c0ce75b1bcee79d5f96e5a" or // js/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "5d709e1db0c76651ff2e04084349b41ec8ac349e" or // js/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "26684d59fecefd29796e1ce35b9c8fde4001f80d" or // js/tiny_mce/tiny_mce_src.js
		
		/* Magento CE 1.7.0.1 */
		hash.sha1(0, filesize) == "a5dce2ba92736f0d1e33769d697b1777ddbadd98" or // app/code/core/Mage/Adminhtml/Block/System/Config/Form/Field.php
		
		/* Magento CE 1.7.0.2 */
		
		/* Magento CE 1.8.0.0 */
		hash.sha1(0, filesize) == "f4bfc9f458bdadf338482afddaa80530b1eb668f" or // cron.php
		hash.sha1(0, filesize) == "78f63461659a1a430b9e95910e3ad40daee0d7c4" or // downloader/lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "47bc9993a2ae847ee1baded420bc864a9e2add82" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "2ea72c5b3160e44b1ab812e40a002fd3ffb47e01" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "6053ccb397bd3237772c950e0c926f852a3231ed" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "c5359f0b869bfc7d07d669dea5996fecdfb01ad7" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "444479b4ce40a0c8e592d68a87c971934008a245" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "90f041175c2cea0f0663afa30f588fe4dad5b123" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "87feb95a759d68eb37cbed972425276586ae02bf" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "51b39b52f31bd6376a99979ad1235ad1f5e4cb94" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "2e2be1472eafa5164fb0c5926942ca9bfe670d2f" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "f0cfbfa1652bc187ad818823d9021507aa483610" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "44034f3de404aff9ca5b4bd177814ccf1a488a91" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "58fe31ecb9fed1ea5e1ec6e5b9cbd7339000be21" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.8.1.0 */
		hash.sha1(0, filesize) == "2a72c042ddf3151bc189a1a1abee570911e5b90f" or // cron.php
		
		/* Magento CE 1.9.0.0 */
		hash.sha1(0, filesize) == "beb8fa0b00d09fe07c4250b57638207d2baf58a9" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "e49b97bd3d87338e45952d3c14110f8c58ff2944" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "0845429e8d7ec4db23031fa8567712b620716ce3" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "030222d390a79416396528a36d00bd8782f42b44" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "c20d1956300ab8a7c7249327fad8460e26bfe5a4" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "57b95e9be59894c37bc07a8ef8ec90b9599c1b4b" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "882cf7e8f1edef0e29af45c97243918e41ac8ed8" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "d8cda57af7063c1727837dd8da9db48a67258126" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "1f80886d6860858d4b67d021c374a167a4452a9f" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "6e7249490d2717c9b8472fbd045c7603752bf09d" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "3edb4a845c40b7bd58a3c420c643fd1848d29a4a" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "56a365dec8f4871ff38b8d157557cd44c99a0f58" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "257622b757cb7a54fd2ca5248e1a36ebcd804cc0" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "6b5a32540833318714c783e546219d1ec7ff1d4c" or // lib/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "0f4d1b153641f3e38355e7b6e77d2ef0795d502a" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "d22c5d0518d02777887e16d52b8505aaa7f4165d" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "474e85d94ee74b3837b48ab9b0dcec24eb834974" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "8fa67d2a0a56159c7c45031d11fab3f8050c526d" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "ca6aec4ee5075ab676dc0834beebb16671535650" or // lib/Zend/Service/WindowsAzure/CommandLine/Scaffolders/DefaultScaffolder.phar
		hash.sha1(0, filesize) == "834db01a738509c1e104f97d5cd900c7b10d7205" or // lib/Zend/Service/WindowsAzure/CommandLine/Scaffolders/DefaultScaffolder/resources/PhpOnAzure.Web/resources/WebPICmdLine/Microsoft.Web.PlatformInstaller.UI.dll
		hash.sha1(0, filesize) == "a635e99c23f43b460511a7017cbde6020bb100b9" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "843ff3ac422f19112c787b2ef63ae4e3341b6d16" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "0c76cda5268b7c886f075491ab2e0857edf1f30c" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "08da1d6d302bd33f27081c3198ceeb6d902dfd00" or // lib/Zend/Ldap/Converter.php
		
		/* Magento CE 1.9.0.1 */
		
		/* Magento CE 1.9.1.0 */
		hash.sha1(0, filesize) == "5cc804265e9d69991e22aa92c82663fd03b1e9b8" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "4866408493f2f83827ef0fd1d7fce1802d219cf3" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "5b534fb113a2a6e555bcb09d80576c8d92cc45f0" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "f3b3eceb9c06bc59f23387c462b7817480efe1af" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "3d560f39b99e47b72ede84e7d6ac69e198c22098" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "e782aee39e228d0fbb0bb894b740961c156eef5a" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "0c882e8ac2d88a395fc14da2b1eab649bf1be462" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "91135f179fdbee4ac3806abba6120db0b73e6dbc" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "07c71d2a531adb843589c60f42f940c4f3fe7dbe" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "71b10a4a0cd8956f30e5ce13a91e6bbd74fa5421" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "410f0ba42bc4ffa69cf140768352368a3d09f73a" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "6be0dccd49f9878749ef9a85963e7f8d75b4d40d" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "a36be33cb14a5803bf0f4a6e188f6a0b16077853" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "ad57a755258346b526d694d2bc515b4171d16ea7" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "9d370bde321e7d936025773e0b3a8f7f01882f67" or // lib/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "62f77a3c4e2ea1ce8d00fe62a8065c3c2a892118" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "b8b3dbb3fb548a70b7ffb249862cb20c2e8826eb" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "f2c2a12241d8d571acafeb4ddfb7920c4b41ce9b" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "761b8134d057822aebd9b25599759593a62b59a8" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "32a5acd82a2e9163ca05a125c359e7f751ae55f3" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "5699310fb6d6e827050e152f99a085b88b05e488" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "8864eef8ceda89c902d033be651a9353e3cf5e73" or // lib/Zend/Date/DateObject.php
		hash.sha1(0, filesize) == "ebe09e979a43c009fbea2d65ce01ab7941cfa49a" or // js/tiny_mce/tiny_mce_jquery_src.js
		hash.sha1(0, filesize) == "f7ce9a2c3cddf03aa2069b3a4faaa4b4011a8571" or // js/tiny_mce/tiny_mce_prototype_src.js
		hash.sha1(0, filesize) == "77abde98292c0e2ea60c3cb796f4eda512eaa575" or // js/tiny_mce/tiny_mce_prototype.js
		hash.sha1(0, filesize) == "10de582f689b58d046d08da55fdfbf90c08524f5" or // js/tiny_mce/tiny_mce_jquery.js
		hash.sha1(0, filesize) == "e4473407525b5d622aaaa3f626946c6ef3ce3c1a" or // js/tiny_mce/tiny_mce.js
		hash.sha1(0, filesize) == "818d1825aef53ec014568c10181d75e88491f9d0" or // js/tiny_mce/tiny_mce_src.js
		hash.sha1(0, filesize) == "9539b243cb405912b865b0db36b312a9fe44d510" or // js/tiny_mce/plugins/paste/editor_plugin_src.js
		
		/* Magento CE 1.9.1.1 */
		hash.sha1(0, filesize) == "1a5df06c6ba7b717825db8d55e2ad3db8c834637" or // cron.php
		hash.sha1(0, filesize) == "abbd120b50f030bdd61e2ac14511d549cfac72f9" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "02bfd222251a3b35bff55c213a6e8126a2e60784" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "0c11c755b73650408655af02ea304786bbafbe9d" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "f8fcce0810ed8610fdc3d3dfa164d95835f84d93" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "3734e1824e4ad9f0516344427f4cc246ae00776a" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "5f65da3c0df60ac43befc42ea990639da9a89039" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "947e91de8554856c73ade2a1c9e6fecb725a26d3" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "4079c07a1059350c4d1e5a0bd3ad955cc4d02738" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "2b2d9c9ebe2144fe52d0e0be0cca17ea1285dbe7" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "45ea8b1dbffc1166987d889780fa9e990c02836f" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "3b404a87888f839158b19e748c71bad0b0908605" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "e810f8d584b0ad3e43d7ab15fda1c666a466df85" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "da92179998e43536f4439c3fdc0eb51cc4db96b7" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "fb0b0bf5cef93f8c817dad5872ce245f3d96d32d" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "782c7d8f1a2b06e5da59d0862766c6ba2b25f28e" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "d6fdfc01c4644292bd08f73f19f2dc539536de2c" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "c7d2ea2c3bd0ba9854630e3e63a950765c14f1bf" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "24dc54b5710bc353e5b3f493af8d3f18e99a2c3a" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.2.0 */
		hash.sha1(0, filesize) == "f9cc4c1a62436372f245fdda6a0a37e7df4a9cdb" or // cron.php
		hash.sha1(0, filesize) == "dd414df47f283a6db73cef174ab8e526512b64b8" or // lib/Zend/Tool/Project/Provider/Test.php
		hash.sha1(0, filesize) == "b8519e3973a2a0504942f31f905f7a6e9c533f63" or // lib/Zend/Validate/File/MimeType.php
		hash.sha1(0, filesize) == "89765ac6cbadcd08f693cd9f7557e42d90380313" or // lib/Zend/Locale/Format.php
		hash.sha1(0, filesize) == "72517e19f04eda76e203868603b3b5132d4ef9d7" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "dbc4bbfaecf84eeb4bf5c99c3e359bbbf32803be" or // lib/Zend/Soap/Client.php
		hash.sha1(0, filesize) == "b3f0a13af9d17e7ced224584c6447505586fdd1a" or // lib/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "a391b6abaf40851177c2a634c894a44a0fdcbd2d" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "227da1e56588f1d2c02ab5dd81784f1d38a5be5d" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.9.2.1 */
		
		/* Magento CE 1.9.2.2 */
		hash.sha1(0, filesize) == "9283d2576949b018bcc38dd35c28e4bf2d609db1" or // cron.php
		hash.sha1(0, filesize) == "66503bf10b6b58265728cc6e9b6d564bf5149bf2" or // lib/Zend/Session.php
		hash.sha1(0, filesize) == "0bab49baadf98015bfea963e0d9ae5944bec1233" or // lib/Zend/Locale/Data.php
		hash.sha1(0, filesize) == "b58925a24d9201f4efbc0f59782b2b99367ec006" or // lib/Zend/Amf/Server.php
		hash.sha1(0, filesize) == "7c00d311a20e650dccf8dff9d2eb346077ff91eb" or // lib/Zend/Date/DateObject.php
		
		/* Magento CE 1.9.2.3 */
		hash.sha1(0, filesize) == "19dbc4997004bb618bcc7b1e76b572424c7c93d1" or // cron.php
		hash.sha1(0, filesize) == "0989b6d28e5238a966d6333299750251f6621cf4" or // app/code/core/Mage/ImportExport/Model/Import/Uploader.php
		hash.sha1(0, filesize) == "3d8a99b05b05488ad1c89c249712dc1e45e9d1be" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Customer.php
		hash.sha1(0, filesize) == "2510ea6f36a7824721ef930bd3b34cb19b5a623a" or // app/code/core/Mage/ImportExport/Model/Export/Entity/Product/Type/Abstract.php
		hash.sha1(0, filesize) == "61c48e91b39b227207d857276ad43208a517f31a" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "e25d06c0cae8b8e5992b28014d7e1de33b97ab3b" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "531a0be26ca6b9444ab714983fe9727826f9a1bd" or // app/code/core/Mage/Core/Model/Layout.php
		hash.sha1(0, filesize) == "91a98939132e7b67dd9c5d9d1aa7278cc9356922" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "3173f1e7f8889b01bccf4b64ea98e8e9ea212883" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "7229c6ac1a40b4e97e1ff0274a85b33ae3a3ae56" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "6e6978736bd02faf3350f54fd0711abda85995af" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "2ade0c0fe3ba96238bcc8d9e486316ebebbc543d" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "06412e5959c3d322cf0702cd2533d6e89cc64b1e" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "1c7302f33d227f8bbb8e7dba6f45cacfa353a1e0" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "f60b8ccc6af994fcb5390858d913c6894daf8d6a" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "e67dbb73a945ced9ca3b139b4bb9634d49890494" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "a3b95117cb53b32f15933a323d0caecb28ba8f59" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "eddcb2ed2b259b3bc0819316a3f82e8e765010e3" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "c0db9c81f156724e5b34ce33bf584d7af6d9ec0b" or // lib/Varien/File/Uploader.php
		hash.sha1(0, filesize) == "4bf65c05b7f31d0b068a9586b3384f37818e83ba" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.2.4 */
		hash.sha1(0, filesize) == "1b93c2a04a83e7577623ee4af05c428819cb7c16" or // lib/Varien/File/Uploader.php
		
		/* Magento CE 1.9.3.0 */
		hash.sha1(0, filesize) == "3f1c255821b6a821dabca2dc02bd0d88ce19a2b2" or // cron.php
		hash.sha1(0, filesize) == "6e9a284038a3e121052e5ff3b69d580dc3dbd387" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "b2e8d4ed802a50d96711e73db12ef9e6225fd6ce" or // lib/Varien/Autoload.php
		
		/* Magento CE 1.9.3.1 */
		
		/* Magento CE 1.9.3.2 */
		hash.sha1(0, filesize) == "a5f4b3b79113406a25803258e67955ecaef58f96" or // cron.php
		hash.sha1(0, filesize) == "b59a9f79f93104dd0f2086ecb41b121ca83c49c5" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "10396708b76cffb8e5ec478e138668fe7f7fb08e" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "c3cc023db136ab16195a00821c28def911e5aa22" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "0c5c35de2e11051a72842dec7fa77279076c7107" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "6da6474df8515b58505301368d64b054a973be87" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "db22a8c5bac3dfecfd67be8cbb856256ce005e03" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "c78c97ee710b3ece67398146c337593d208b763a" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "c395f8c60434160d0a4fdca0a9981eb4c6a13021" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "9163281f49361481293a54155b48a18f502679ea" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "6c577b685ed6a73c08abaabef945070c722e14f9" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "5d7e38bd1345fa0afc6e0c1f2eec085d556da06a" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "cd52d865f0d58fe0fa993b3aaa134ed86b4ddd87" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "a80a3a304b0abd1732e704ccc3b8f4816605052b" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "c1cbd9d692c66deed9c4419c6c78491292aec5a0" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.3.3 */
		
		/* Magento CE 1.9.3.4 */
		
		/* Magento CE 1.9.3.6 */
		hash.sha1(0, filesize) == "45ffcf03c297d29169d2fd00790ff8eb83ef5fec" or // app/code/core/Zend/Serializer/Adapter/PhpCode.php
		hash.sha1(0, filesize) == "294d413697f3461aa1b20dab404040eb483cec95" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		
		/* Magento CE 1.9.3.7 */
		
		/* Magento CE 1.9.3.8 */
		hash.sha1(0, filesize) == "fb7414b830abc653d624019a18689d4dd69d7f90" or // cron.php
		hash.sha1(0, filesize) == "06f0a6333273222b5e39b7e9e8c5e3ef764d639b" or // app/code/core/Mage/CatalogRule/sql/catalogrule_setup/mysql4-upgrade-0.7.1-0.7.2.php
		hash.sha1(0, filesize) == "8bb1ce05c51baff0b8fe24c4320e22fcd18bbc47" or // app/code/core/Mage/Core/Model/Translate.php
		hash.sha1(0, filesize) == "b4aab58ed7efbe7aa809c1aae2fe90494a3d403e" or // app/code/core/Mage/Dataflow/Model/Profile.php
		hash.sha1(0, filesize) == "28f900ea871d38dfdb5347f1c9861a7621825a2d" or // app/code/core/Mage/Adminhtml/Model/Url.php
		hash.sha1(0, filesize) == "7d84d41fee5ec9e6825654a1ef4ea785bb1eda29" or // app/design/frontend/default/iphone/template/catalog/product/view/media.phtml
		hash.sha1(0, filesize) == "7ae589b2fa62b74e0075da5c5c3cba8282df7c4c" or // app/design/frontend/base/default/template/customer/widget/dob.phtml
		hash.sha1(0, filesize) == "fd489abda5b880c3c24fd48f7f8388917a119c19" or // app/design/adminhtml/default/default/template/notification/toolbar.phtml
		hash.sha1(0, filesize) == "ca8a29edddc5deccc47e95da68a20d557abd7621" or // lib/Magento/Autoload/Simple.php
		hash.sha1(0, filesize) == "7035f2cfad6f0936bd5c533fa26379440484c82c" or // lib/Mage/Autoload/Simple.php
		hash.sha1(0, filesize) == "79ee56a5b2a661467cf0b90060e98085a94bcd91" or // lib/Varien/Pear.php
		hash.sha1(0, filesize) == "b6abca064319d3f94430b0545e5d2e1eec4e1ea7" or // lib/Varien/Autoload.php
		hash.sha1(0, filesize) == "476d8b4554f8bf9cfe6d77c056eaf201eee1348a" or // lib/Varien/Data/Form/Element/Gallery.php
		hash.sha1(0, filesize) == "78694d3161b6dee34635eaf3dda65259d0045443" or // lib/Varien/Data/Form/Element/Multiline.php
		hash.sha1(0, filesize) == "14551c7936764a457729f2ceba437f6c4e829fbd" or // lib/Varien/Db/Tree.php
		
		/* Magento CE 1.9.3.9 */
		hash.sha1(0, filesize) == "b6b6747a3d7f3f54e150fbfc0ae9f22068276f57" or // cron.php
		
		false
}
