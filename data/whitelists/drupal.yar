import "hash"

private rule Drupal : CMS
{
    meta:
        generated = "2018-05-29T22:23:47.366743"

    condition:
        /* Drupal 5.0 */
        hash.sha1(0, filesize) == "f1eb3d374f15f22b20bfd75ee313857023ea364f" or // modules/color/color.module
        hash.sha1(0, filesize) == "1730e4fb6d18b065679fe914da683ce0c919d291" or // themes/garland/template.php
        hash.sha1(0, filesize) == "34715498bee1ecfe749d6a73a3e98775ace745e1" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "bf4a657c57358f7184da9c0403ff8f594da26fe4" or // modules/system/system.install
        hash.sha1(0, filesize) == "bd19a66385c4d84321a4a0fcad09592da5a8767c" or // includes/form.inc
        hash.sha1(0, filesize) == "93b7741008635667702e9657a6db496a21df3bbb" or // includes/xmlrpc.inc

        /* Drupal 5.1 */
        hash.sha1(0, filesize) == "e7600251d12b48a85a7e1e1ad35cc8bf03d9e370" or // modules/color/color.module
        hash.sha1(0, filesize) == "6569f949cecb5a074334d6e94ec0a4d550eaf367" or // includes/form.inc

        /* Drupal 5.2 */
        hash.sha1(0, filesize) == "05b40483364714c310d18526b856d5b823c50326" or // modules/color/color.module
        hash.sha1(0, filesize) == "c5e4b8f163bb7580d82d37008f084f15cecb7d88" or // themes/garland/template.php
        hash.sha1(0, filesize) == "3bf375e99b5fe211e6e2d8c512e348dcb08eda09" or // modules/system/system.install
        hash.sha1(0, filesize) == "689adbac4c770fb2312a32943ab57c366522b43b" or // includes/form.inc
        hash.sha1(0, filesize) == "f7c0c92ba2ac49b33cf333abf5c7638f45b12b74" or // includes/xmlrpc.inc

        /* Drupal 5.3 */
        hash.sha1(0, filesize) == "1565b1cfac5b9f8773338c52df83e643b238aa24" or // modules/color/color.module
        hash.sha1(0, filesize) == "633d701d7aaee4eeb1f86128fcedec43aade6d6c" or // modules/system/system.install

        /* Drupal 5.4 */
        hash.sha1(0, filesize) == "235a2ba6ce07344c8e7c544fd13d50e489871315" or // modules/color/color.module
        hash.sha1(0, filesize) == "3ba8b759ca4215a87affd1d46142745f2affe298" or // modules/system/system.install
        hash.sha1(0, filesize) == "49d374c029d4713879dd3c31afb4617307816388" or // includes/form.inc

        /* Drupal 5.6 */
        hash.sha1(0, filesize) == "7703e318cd7972790fc2b2171a756e4d51db5376" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "0acf5f02c673d7c2e215e80b3e9c44c9a66bb493" or // includes/form.inc

        /* Drupal 5.8 */
        hash.sha1(0, filesize) == "9ef2f823596c2ad04a186f303376d06d78d2fc1b" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "dcb29e1e0372fe1c56480cde6af09d7a4518ac09" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "e682ea838bae85ec2c1f2a06c6a7c49b545ec0ef" or // modules/color/color.module

        /* Drupal 5.10 */
        hash.sha1(0, filesize) == "3a06dd7ce5a2a4aa9542ced4c20f375643191b8f" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "ce633ea58a6de51e36f4c4cb7644e26b01480780" or // includes/form.inc

        /* Drupal 5.11 */
        hash.sha1(0, filesize) == "3aebbcd0f6b90304ddfb52edff97e20f6d7aef95" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "e5a533fddac060cf3146c347999595c58a159882" or // includes/form.inc

        /* Drupal 5.15 */
        hash.sha1(0, filesize) == "07b090bf9c8cf6736466a23c8f5925ffab837e44" or // modules/color/color.module
        hash.sha1(0, filesize) == "7b380e59f08d11a6d7c890cefbb2358fae24a434" or // includes/form.inc

        /* Drupal 5.17 */
        hash.sha1(0, filesize) == "d8687f6b0772b1f80d3e44a8b1e1fbb94202e5d1" or // includes/form.inc

        /* Drupal 5.22 */
        hash.sha1(0, filesize) == "23c6b18c7f4f599da8157b033f59e3425cc893f5" or // modules/locale/locale.module

        /* Drupal 6.0 */
        hash.sha1(0, filesize) == "3c01c46acb9f8e2a5dc41ef849766defde662ecd" or // includes/batch.inc
        hash.sha1(0, filesize) == "8c0212cf85917607951dfe4ea2a9aa49dc8872a4" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f92e2b1f7e899b18059bbdb4d3c9e938bb29a8ea" or // themes/garland/template.php
        hash.sha1(0, filesize) == "3cfbb369d412fa5e67e2862a18394d29cdcf9b0c" or // includes/menu.inc
        hash.sha1(0, filesize) == "482c91441f49765f15734ddbbae1272f11345af4" or // modules/color/color.module
        hash.sha1(0, filesize) == "40e4979ecf0f1ac140d919b212f03239c5b6aa92" or // modules/system/system.module
        hash.sha1(0, filesize) == "81c8b9b2c63c300f052cd6cd114ba2723bd588fa" or // includes/form.inc
        hash.sha1(0, filesize) == "bd6052877cf3fd94647cbce96dbe6e56dc50e10f" or // includes/xmlrpc.inc

        /* Drupal 6.1 */
        hash.sha1(0, filesize) == "3c3376a298abc4128a5d694a4cd5fd85e828e031" or // includes/menu.inc
        hash.sha1(0, filesize) == "5e5f0081619c744d82203acdd685908286995fbd" or // modules/system/system.module

        /* Drupal 6.2 */
        hash.sha1(0, filesize) == "f2aae0d40ea29a7392c2d61048f1d4f3aaf045e5" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "ce03cc0cf33d2a0ca284d5fdef2d565a0083433c" or // includes/menu.inc
        hash.sha1(0, filesize) == "49ffaf6b8dd7860f4e3f087f7d1dc97a1bc275e6" or // modules/system/system.module
        hash.sha1(0, filesize) == "fc911bd9cc9325ec4886152db537cdfd8f4e64bb" or // includes/xmlrpc.inc

        /* Drupal 6.3 */
        hash.sha1(0, filesize) == "80b13389511ea6e684bebba943af093b1e981858" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f92178aa9ef6362cded7cd8781c47eb83deb68be" or // includes/menu.inc
        hash.sha1(0, filesize) == "3dcd1690b4e1861ffaa896d33cd7f8b6498ea806" or // modules/system/system.module
        hash.sha1(0, filesize) == "bf20f4b2a6ffcf7c2338771153439082f39c460d" or // includes/form.inc
        hash.sha1(0, filesize) == "3a97f6da319588192cebfa3fe092dcda4412c6fa" or // includes/xmlrpc.inc

        /* Drupal 6.4 */
        hash.sha1(0, filesize) == "9b3b6f401a6c9b63e396b8c8dc687d7bae0f1b52" or // modules/system/system.module
        hash.sha1(0, filesize) == "831bf55ef200e3af6fd5cc59ff34499460349b5b" or // includes/form.inc

        /* Drupal 6.5 */
        hash.sha1(0, filesize) == "88eb3c9e014ac820a049987825d5f06b9e07f01b" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "3c20621fe031cfd9f77171491a8d84d38644768e" or // includes/menu.inc
        hash.sha1(0, filesize) == "7b768a62e50ae512a763b548704d5d50dcfcedb5" or // modules/system/system.module
        hash.sha1(0, filesize) == "7655e21aab65237f9bb767c9ebd8f9e8f80c254b" or // includes/form.inc
        hash.sha1(0, filesize) == "e16028c47285d1c8acb40917c5b7646dc43ba862" or // includes/xmlrpc.inc

        /* Drupal 6.6 */
        hash.sha1(0, filesize) == "582b5612950b654ca32185840672e4b39493f40c" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "70beea28b5e6599c53aae3de6da6ba84ce67f6df" or // includes/menu.inc
        hash.sha1(0, filesize) == "2e1b0bcc805cd538d544fdab801e79c9b42c5cc4" or // modules/system/system.module
        hash.sha1(0, filesize) == "67c5018ac240183211ad9e32e3490a491bfc21e3" or // includes/form.inc
        hash.sha1(0, filesize) == "d7badca996415761de8f4d44cf825567df60e79d" or // includes/xmlrpc.inc

        /* Drupal 6.7 */
        hash.sha1(0, filesize) == "9e8fb4a8241d37d52dc533e2aec9bdc9d44ac2c5" or // includes/menu.inc
        hash.sha1(0, filesize) == "d7295287f872616d6581963ca4fffc842877e54e" or // modules/system/system.module
        hash.sha1(0, filesize) == "0066f50873b4d8e826f5f9a3c2f931b9e449e3cf" or // includes/form.inc

        /* Drupal 6.8 */
        hash.sha1(0, filesize) == "522a021eabf04567c7d3ddfea8e80191a67b75c6" or // modules/system/system.module

        /* Drupal 6.9 */
        hash.sha1(0, filesize) == "47e69cf9117bd12900a7d0b322bbeb891cb876bd" or // modules/system/system.module
        hash.sha1(0, filesize) == "c35efa1e4c9e0793b890c0e7900617b7a708d906" or // includes/form.inc
        hash.sha1(0, filesize) == "9d3ef642d7f227b0a2a922c16fd04d7ae51fbbac" or // includes/xmlrpc.inc

        /* Drupal 6.10 */
        hash.sha1(0, filesize) == "1257503f9f9e90f0de517c0ec613d28476608f94" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "a9a48782feda7033d80d10077fbdf901478882b0" or // themes/garland/template.php
        hash.sha1(0, filesize) == "303b2365a1068f10362712ba57f8aa11641986ee" or // includes/menu.inc
        hash.sha1(0, filesize) == "f9a57bbb528fd3cab334f72fc7295fb32266aeec" or // modules/color/color.module
        hash.sha1(0, filesize) == "9958a8bbc30b7b235982f21f6c58fbbdf53e481d" or // modules/system/system.module
        hash.sha1(0, filesize) == "00a2edf2e518509dc352f407f4aaebd9e9432ea2" or // includes/form.inc

        /* Drupal 6.11 */
        hash.sha1(0, filesize) == "5cbbcac5697b1e3cbfc7c7071aa99d8eab48b9fa" or // includes/menu.inc
        hash.sha1(0, filesize) == "ca4b910750e51db3c7ad6859ce6bb19da6d119fa" or // modules/system/system.module
        hash.sha1(0, filesize) == "3dfc875a3fb589625dc7a45fdbf6e322f560c4af" or // includes/form.inc

        /* Drupal 6.12 */
        hash.sha1(0, filesize) == "13e042bbd65139c41ebcab31b2d7f82343044a60" or // modules/system/system.module
        hash.sha1(0, filesize) == "45aee133a5c7c39c932e97939c8333a09ecdaa58" or // includes/form.inc

        /* Drupal 6.13 */
        hash.sha1(0, filesize) == "a607ad688c31b9bbf56f933f9d942f1771f6eee7" or // modules/color/color.module
        hash.sha1(0, filesize) == "21778d2e8795c1deba246006623621efe5b0349d" or // modules/system/system.module
        hash.sha1(0, filesize) == "6ed25b5b4e1292685e81537d6c6d49e4140c080c" or // includes/form.inc

        /* Drupal 6.14 */
        hash.sha1(0, filesize) == "03e44afcb7dc4b0a8acde5f89a6cba050537cc91" or // modules/node/node.module
        hash.sha1(0, filesize) == "98e92c349a39518cf5a56236070c2585eae773d3" or // includes/locale.inc
        hash.sha1(0, filesize) == "5a8177828846fbfe19f4b1faf2d23d6481fba20c" or // themes/garland/template.php
        hash.sha1(0, filesize) == "1ebddd7ba111f431149df0ee5f589671637aef4a" or // modules/system/system.module
        hash.sha1(0, filesize) == "b6977eb520a2bd3fe759f828c764cf898cf2e556" or // includes/form.inc

        /* Drupal 6.15 */
        hash.sha1(0, filesize) == "fd20764485c46379fadb3e58db23ec8cabd28578" or // modules/node/node.module
        hash.sha1(0, filesize) == "2b63f034c12d60202f689283f087f6f5f48946c1" or // includes/menu.inc
        hash.sha1(0, filesize) == "ab7b91796db0ef4681b5e67e95e03a009c688c5f" or // modules/system/system.module
        hash.sha1(0, filesize) == "80a31ba9e3a927adda8e57668c8ec970d6a207a6" or // includes/form.inc

        /* Drupal 6.16 */
        hash.sha1(0, filesize) == "3756e7b875afe0669c0d3256c1d93afe29e755d7" or // modules/node/node.module
        hash.sha1(0, filesize) == "ecd57dc215a2944b78968fa709812cf320446fc6" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "0078d227e54de10cb9d2460f3b18d8ceb6fdb86e" or // includes/locale.inc
        hash.sha1(0, filesize) == "0a7d62958d36a81c9e938f199e8c760123727baf" or // includes/menu.inc
        hash.sha1(0, filesize) == "c91aab4890cafc70cfee4277042d505f3f15e1ff" or // modules/system/system.module
        hash.sha1(0, filesize) == "527bb89b9ccbdf5a1e08c81ab2686a893c07ed78" or // includes/form.inc

        /* Drupal 6.17 */
        hash.sha1(0, filesize) == "2368a5402417369e2cd6318e103ca07747666aaa" or // modules/node/node.module
        hash.sha1(0, filesize) == "1d387478445f18f8668b5d7ed7d1d96eb0aedb3d" or // includes/locale.inc
        hash.sha1(0, filesize) == "599bcbdc3c2ff6e8ebe6cf8f24614f8d1c553410" or // themes/garland/template.php
        hash.sha1(0, filesize) == "d63700c733fcb3f8fe927225b132a9cc10211ba1" or // modules/system/system.module
        hash.sha1(0, filesize) == "48dcc2f93ecd31c679e702a1faf2b2caff8b1180" or // includes/form.inc
        hash.sha1(0, filesize) == "8b3f52ad501ca0b4726af6996e57618b4ca5e4f8" or // includes/xmlrpc.inc

        /* Drupal 6.18 */
        hash.sha1(0, filesize) == "a2c40e8095cdcd133bd4cb8a720740cd6cd68c90" or // modules/system/system.module

        /* Drupal 6.19 */
        hash.sha1(0, filesize) == "58dbd82382056e8a5367492c57a8807cbad402cb" or // modules/node/node.module
        hash.sha1(0, filesize) == "c008f67f93a812c1df421e6259db83a3532fdd80" or // includes/batch.inc
        hash.sha1(0, filesize) == "a229335ab54e2f5a671b7d6835433e34dcac1df3" or // includes/locale.inc
        hash.sha1(0, filesize) == "6e39f4d4b47cc49137e77b5927f8194ebedcda2e" or // modules/system/system.module
        hash.sha1(0, filesize) == "f4dffdc1a14330db9f3a59f14857de5479e331b9" or // includes/form.inc

        /* Drupal 6.20 */
        hash.sha1(0, filesize) == "b698942278cdd380f828bf5e6104c7e37679931d" or // modules/node/node.module
        hash.sha1(0, filesize) == "b16330077711b7735dd205ae651037d85aac3e12" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "41dec55320082ae8d611a2aa626ae54cc4a76d75" or // includes/menu.inc
        hash.sha1(0, filesize) == "4697affab0bafeaf765a62b809a021fdf4068485" or // modules/system/system.module
        hash.sha1(0, filesize) == "3856daf8ab296ce371c22b02baa32e4da90029c0" or // includes/form.inc

        /* Drupal 6.21 */
        hash.sha1(0, filesize) == "1cf1e904fb4338edfee61d91ebb611e5ac034ecd" or // modules/node/node.module
        hash.sha1(0, filesize) == "78e3bd8a85c6f09b0635343791dad50b4c41a58f" or // includes/batch.inc
        hash.sha1(0, filesize) == "4864252a3ead68da46dbe5400f906a8586a1384f" or // includes/locale.inc
        hash.sha1(0, filesize) == "1057ca4a11b268576e69bd111a067eb4c87ad571" or // themes/garland/template.php
        hash.sha1(0, filesize) == "d9d2bd9363cafd8b464d5e82f164a83f3cf23828" or // includes/menu.inc
        hash.sha1(0, filesize) == "fdf231fce40e84493a3f2d3d3a08eecac175f8d2" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "1276ff3bd1677bf2ece8481bfba55cfe673cff55" or // modules/system/system.module
        hash.sha1(0, filesize) == "48d49c860d1904399b6c44cc2660e699f05e52f7" or // modules/color/color.module
        hash.sha1(0, filesize) == "1557e578a59a2b7fc4a241073022c7f4f19d2e5f" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "88956b7193b9d97c387d76a78e67aec948955be2" or // includes/form.inc

        /* Drupal 6.22 */
        hash.sha1(0, filesize) == "21a311cf276dae1528ce8595be4906fc8acf642c" or // modules/node/node.module
        hash.sha1(0, filesize) == "d1f23968f5682341587813b6288e7b3377ab8b53" or // includes/batch.inc
        hash.sha1(0, filesize) == "246b764fbc7047a5245204d40bfe9ff0369e3817" or // includes/locale.inc
        hash.sha1(0, filesize) == "a1c6ca497e8672f9e9cc5dae72229d42d92e7244" or // themes/garland/template.php
        hash.sha1(0, filesize) == "ae212697bbbc8eab36e5c1330b0b9597e236d7d3" or // includes/menu.inc
        hash.sha1(0, filesize) == "23968265dab777455460b72ae62e5e0442153eef" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "099a434e38d8b7463385e50fd67c74cfd955061c" or // modules/system/system.module
        hash.sha1(0, filesize) == "a3fedf58f5ff6d51b1bb4f8692c34b2afddc4085" or // modules/color/color.module
        hash.sha1(0, filesize) == "1e60761b6b1ad271b83a1003709d93bee52c6a0d" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "9c0d518eff915269fe7cce4ccfa8a13931f37fd8" or // includes/form.inc

        /* Drupal 6.23 */
        hash.sha1(0, filesize) == "e60493bdbb199d250a9922ef6a601569bb8de76e" or // modules/system/system.module

        /* Drupal 6.24 */
        hash.sha1(0, filesize) == "7b12a9d929023252e0c1811ae0adcf9e4c774254" or // modules/node/node.module
        hash.sha1(0, filesize) == "dab7c84b2342498a37b0bb73d3d6cf24c0f05742" or // includes/batch.inc
        hash.sha1(0, filesize) == "9be2405ef05e71f30eae6734a9e62b25e6987a35" or // includes/locale.inc
        hash.sha1(0, filesize) == "c20d802bbc52b545e3165331a7cdb9d6bb7b7df1" or // includes/menu.inc
        hash.sha1(0, filesize) == "59a40a4f99d7bc0546721c7761753e74dc3fe3c3" or // modules/system/system.module
        hash.sha1(0, filesize) == "30fbb626155b8b19ad032ffc701088ddf4199b42" or // includes/form.inc

        /* Drupal 6.25 */
        hash.sha1(0, filesize) == "1d2c37df3b426b7be8320b927126dd1539bc57c3" or // modules/system/system.module

        /* Drupal 6.26 */
        hash.sha1(0, filesize) == "0a727f287b856521d59198b9b0573b5aa80434f4" or // includes/locale.inc
        hash.sha1(0, filesize) == "4905160d51618a72d2a58339c88429ada66e5a74" or // modules/system/system.module
        hash.sha1(0, filesize) == "53055651427e6d4a8c202c4250977c36145b9512" or // includes/form.inc

        /* Drupal 6.27 */
        hash.sha1(0, filesize) == "c2cbbc1186ca7b2c8754c2886366b17037ee7486" or // modules/system/system.module

        /* Drupal 6.28 */
        hash.sha1(0, filesize) == "155613ff0e0d2bd61da2bad7734ce22428749c14" or // modules/system/system.module
        hash.sha1(0, filesize) == "7e40d9561d9ab17e7876c397d9f0595e29b9df27" or // includes/form.inc

        /* Drupal 6.29 */
        hash.sha1(0, filesize) == "ec5935d65d04e19accc08a2bc22fd11e64308b09" or // modules/system/system.module
        hash.sha1(0, filesize) == "91f55a3d4b403e0e16e2db693b2965bcbb136dbb" or // includes/form.inc

        /* Drupal 6.30 */
        hash.sha1(0, filesize) == "38d887f720a4cf99fbdb041c481bb4d10cd4f984" or // modules/system/system.module
        hash.sha1(0, filesize) == "ede96ab5b9624c5831ef65c9ea16aaea572a402a" or // includes/form.inc

        /* Drupal 6.31 */
        hash.sha1(0, filesize) == "10a93fe4578303c207a6ebc0535b7f96642f8767" or // modules/system/system.module
        hash.sha1(0, filesize) == "3f4fb8489b104cb120c7fbb7968675c2d236d6db" or // includes/form.inc

        /* Drupal 6.32 */
        hash.sha1(0, filesize) == "2b3300f3c10abeba51ed0aad3b3f9167b6b270f6" or // modules/system/system.module
        hash.sha1(0, filesize) == "12ad1f5e5b3905ecd78abd020d41808f825da68e" or // includes/form.inc

        /* Drupal 6.33 */
        hash.sha1(0, filesize) == "212255d13179c9b80cc1b7ab31d8022a7797730d" or // modules/system/system.module
        hash.sha1(0, filesize) == "3976d9af713a99b0237f6ddeadbb3490b52a7386" or // includes/xmlrpc.inc

        /* Drupal 6.34 */
        hash.sha1(0, filesize) == "b3e28ca900cdbb5e468242b3fa6be6838313e436" or // modules/system/system.module

        /* Drupal 6.35 */
        hash.sha1(0, filesize) == "8aedf452ae91d3a182fdfa9fb606664ee34b689d" or // includes/menu.inc
        hash.sha1(0, filesize) == "7fea22f40d84ac1a622bdfa19ace8fe25c243440" or // modules/system/system.module

        /* Drupal 6.36 */
        hash.sha1(0, filesize) == "3f86504c275d2a09a0136d91508f67707ef7e318" or // modules/system/system.module

        /* Drupal 6.37 */
        hash.sha1(0, filesize) == "5e21f9e3de34e2c1797adc1bd8bcb95c56be1268" or // includes/menu.inc
        hash.sha1(0, filesize) == "e3e7f7d44055a9c21da39e7ea0f88a39ebcc5191" or // modules/system/system.module
        hash.sha1(0, filesize) == "0b6fa630381cd3af7edbf3c4c460c572c0b51f1c" or // includes/form.inc

        /* Drupal 6.38 */
        hash.sha1(0, filesize) == "87473ff28e3c066d20f701e7d793c14ab4f65d65" or // includes/menu.inc
        hash.sha1(0, filesize) == "1fe7978017f44dee7e3200308879c4c0a7ea7c7c" or // modules/system/system.module
        hash.sha1(0, filesize) == "a7281eb545f13d2e5d4d90c4ce2b56ca6116c1ce" or // includes/form.inc

        /* Drupal 7.0 */
        hash.sha1(0, filesize) == "228137e2ec431da9e30e427de8e0aa1aab3d2fd1" or // modules/node/node.module
        hash.sha1(0, filesize) == "a922e0dbc03a425e3bc0fdae80c28ba3ac8d7ffb" or // includes/batch.inc
        hash.sha1(0, filesize) == "0885dda53e94c3960cddf0c16a7ad5416a334cce" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "ab065305452d07211bc7443cd295dc2b780b087f" or // includes/locale.inc
        hash.sha1(0, filesize) == "f4e7855dcde189ad17b70bdbf2df2f51bb7e1a02" or // includes/update.inc
        hash.sha1(0, filesize) == "ad4910fce34a43990e7eaef91f7c95f311d7fa29" or // includes/theme.inc
        hash.sha1(0, filesize) == "2ce4dea1385e3434d4d0724fe2aa2bc5ff963da8" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "2aa37405d4873a2321bc244230ee7a0104365127" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "9259e61d198496004841cb94e10cf218f55c7dd6" or // includes/database/query.inc
        hash.sha1(0, filesize) == "c506c1adb94ef26ffe6c14ec02378b79c910f130" or // includes/file.inc
        hash.sha1(0, filesize) == "00b8473d18ed60cc06f13e4b7922a29bc93088ab" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "501a31b23d5d76d16af32f980124e188f92c1b60" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "adb445d6aaf7cecf9b527978e90353ff1c218729" or // modules/color/color.module
        hash.sha1(0, filesize) == "9b4fb5bb67916de73a3aca80f5f9b6ac6370dbb9" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "627468282dea7a3491757455678d234fdfafb88a" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "f3744b876879f4121030cc40df82de03fe30caa8" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "8c34383c3aa2bd6bb583d91f8867a53157fb2c0c" or // modules/user/user.install
        hash.sha1(0, filesize) == "988c9e1ec349d19a95fdcde9e9e3e334bb672fd0" or // includes/xmlrpc.inc

        /* Drupal 7.1 */
        hash.sha1(0, filesize) == "e35f8489c3863c8c4d4abb0d166b35e1a699d618" or // modules/node/node.module
        hash.sha1(0, filesize) == "4a662f3e0f5a4ed48a8f320800bb6eb1b6c2e173" or // includes/batch.inc
        hash.sha1(0, filesize) == "ee49ec8bf1062ef741ae480e266ff3f41b3bd5bd" or // includes/locale.inc
        hash.sha1(0, filesize) == "e0a5db67328fe2b123bfe68cfe0513f75280dd7a" or // includes/update.inc
        hash.sha1(0, filesize) == "ff3b1d9fcd67edd835da289aa350b3e3c8eab640" or // includes/theme.inc
        hash.sha1(0, filesize) == "22546416a2d99e42799e9c0cc52146d46c2feb7c" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "0e1ae22c4da4bf873136af717d616cb87bcfeefd" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "e5283af09bffe3133ad5aada2d294a1d5402fb75" or // includes/database/query.inc
        hash.sha1(0, filesize) == "fb9cd96830b3482770937479a873064978c151c2" or // includes/file.inc
        hash.sha1(0, filesize) == "2803e88287d2baff8d9e869e275c406ad6b972e8" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "6d501b8bf9450fff051a569c3108477d5f531783" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "6df377260a15d5100167aa49d0c8dc8f333e1e66" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "133831799dc1814e4cb2a18176bc59ed82e5cf77" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "81ee866a49598c6e61011c7aa5992d1a1f2856cc" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "016eb62bc9b5de611b4688f1aaddbae989f3420f" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "7aa89ef96e5a9655436cd670d80a34a76684840f" or // modules/color/color.module
        hash.sha1(0, filesize) == "9c017d1d16426270a4b3bff374b58e2a08100ce7" or // modules/user/user.install
        hash.sha1(0, filesize) == "3ef3764879ae96be700c3ea6e6f18e3699b118f0" or // includes/xmlrpc.inc

        /* Drupal 7.2 */
        hash.sha1(0, filesize) == "34dbcf77a17cda9e6357d813e2b8018d7c5c7add" or // modules/node/node.module
        hash.sha1(0, filesize) == "fc52ef5640845babe48bea230c311e86b5e227f0" or // includes/batch.inc
        hash.sha1(0, filesize) == "23cc0e2c6eebe94fe189e258a3658b40b0005891" or // modules/simpletest/tests/upgrade/drupal-6.bare.database.php
        hash.sha1(0, filesize) == "a00a4810f45e30f72b3b8b649b21acd40aeffc75" or // includes/locale.inc
        hash.sha1(0, filesize) == "907d7d94601c7a03cf32deeb25b0255aadb05f54" or // includes/update.inc
        hash.sha1(0, filesize) == "544e2f10c37c2723e83205e35044d35e96279aa8" or // includes/theme.inc
        hash.sha1(0, filesize) == "baee2c77c68ea3fdb39acb3321789053cd16488f" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "ff60b0b61bbc7b6e7e436ddf3205ed1d3b0778c0" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "c99932104d23747667422639f23b5604b3b627c0" or // includes/database/query.inc
        hash.sha1(0, filesize) == "ab223dcbc96f39de69b0bded8f9b55db6b79e72c" or // includes/file.inc
        hash.sha1(0, filesize) == "a14664f269a4801d956ae9a7f560208902657e89" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "bc2afeb66152b4fc837798753dbb718681930e70" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "b4572b134a6a581677e5c8dc90c58caea3570718" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f248caf89e30f5a628af90ee4bea3a4a876294ea" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "e38ede84586bf22ea788d5df2018f7517360fe62" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "2c82b626fa35c256796cd4b6651f13055d396815" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "7a9472aeda498f93f154b44f90a87a33a709b222" or // modules/color/color.module
        hash.sha1(0, filesize) == "8cb36d865b951378c3266dca7d5173a303e8dcff" or // modules/simpletest/tests/upgrade/drupal-6.filled.database.php
        hash.sha1(0, filesize) == "b78a99f99fde3375da61aad7dc0940bac8d4e515" or // modules/user/user.install
        hash.sha1(0, filesize) == "fd061dceb82cd18b9866d81bc8588c157cfcfdd9" or // includes/xmlrpc.inc

        /* Drupal 7.3 */
        hash.sha1(0, filesize) == "cfbcf70d4553beac63d2cdd67daffb90063bcad0" or // modules/node/node.module

        /* Drupal 7.4 */
        hash.sha1(0, filesize) == "5c1ab3a9fab6119d8b7dd092a9172e392d436e83" or // modules/node/node.module
        hash.sha1(0, filesize) == "8111cfa60d4789710825ba3389e1dd0954410a3b" or // includes/batch.inc
        hash.sha1(0, filesize) == "e317ebde4ea83d825d82f474175af6cbe0d35978" or // includes/locale.inc
        hash.sha1(0, filesize) == "d7b95646f2d390b23f686a579e74a0132d9be127" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "abfb60fb8f4560d55fec097d641d99b17a611127" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "ccd2d749cf9120100761f46564c789a63baaa533" or // includes/file.inc
        hash.sha1(0, filesize) == "c8adac93914d701282fc76b03b68b1d4bcf111f3" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "f497cc0c8d592dfad4f992d2fef96a6ed2fad3d1" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "8523e46e8d42d7ad2795e1972dbe5ab7683fd430" or // modules/color/color.module
        hash.sha1(0, filesize) == "54ab4931fd4153e45b70e40a059b096e8b9f1dde" or // modules/user/user.install

        /* Drupal 7.5 */
        hash.sha1(0, filesize) == "0fe5c9d14de7aa5a6eb90d5ccef639f85af67731" or // modules/comment/comment.module

        /* Drupal 7.6 */
        hash.sha1(0, filesize) == "2f803125bdb3c2c7da6027bd039a06d24c7bf441" or // modules/node/node.module
        hash.sha1(0, filesize) == "5b161c50878bda62cefdb165e361288928a3bcfe" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "c1d065492b96823f09e6ccae43fd2d36e856e4d6" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "b0604abef9f1ad08e75f8f3b49a42d1e4f4e5093" or // includes/file.inc
        hash.sha1(0, filesize) == "8dee21ea769e0a25be89c2d9dec47ca416549f55" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "38e30cecf915663b1b1e9c47d43c559db9fc50a7" or // modules/system/system.api.php

        /* Drupal 7.8 */
        hash.sha1(0, filesize) == "ef540f3d6dfe62e0649a8d9a85fe1f24a03e826c" or // modules/node/node.module
        hash.sha1(0, filesize) == "fa2f8bd721f4ba4432d781cc0dd2a4dad94a3d77" or // includes/update.inc
        hash.sha1(0, filesize) == "d53494036ec1d09b63951ff6372e4da3600981a5" or // includes/theme.inc
        hash.sha1(0, filesize) == "50239d9649de44842b584b5d3498d208839b304b" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "b3560506e463666789a8507354762b4c48e8ff58" or // includes/database/query.inc
        hash.sha1(0, filesize) == "b3c5dd723611d4ecfe59908d6defd7c0b2ce4a1c" or // includes/file.inc
        hash.sha1(0, filesize) == "554df15d8bde0586535f5005cf1357106943e1d0" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "dbe730df886669a0aeeda142e97c1dded6ea94a8" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "e89d20c7efc7c8b66b64858b4e2f4db8f942901d" or // modules/color/color.module
        hash.sha1(0, filesize) == "cfd3a5279057e6a3954cf7f77a60373f6fb1fed9" or // modules/user/user.install

        /* Drupal 7.9 */
        hash.sha1(0, filesize) == "874f20cc4d15d66b16c708e0f5875b5ba7d5a14f" or // modules/node/node.module
        hash.sha1(0, filesize) == "376c733a803cc5fee588b62f2339a3952e3286b7" or // includes/locale.inc
        hash.sha1(0, filesize) == "141851c796279d22ccb4ad8c40694cba0f13c85d" or // modules/image/image.module
        hash.sha1(0, filesize) == "e1de684d85edb24a774880b747acb08bd3b7a898" or // includes/update.inc
        hash.sha1(0, filesize) == "8972898bde23edde98d6de14ff263a75d12ec086" or // includes/theme.inc
        hash.sha1(0, filesize) == "3a754517384a1418312c5f750e90ca94526d7823" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "3620e1eb6ca27a32b4e8881d1364d3540ac0cc8e" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "18ebac575d626411895b12a394be34ed2a844f21" or // includes/database/query.inc
        hash.sha1(0, filesize) == "1190f6d63a28a9b1d8ee858ef9ee18dcd08d8a3c" or // includes/file.inc
        hash.sha1(0, filesize) == "3cd13f1cff9db2adcbdb24f0db798b97fc0f2e54" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "f24d52c0dfc83e77ed99199b488c5c5854bb64d3" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "1b1b3d4e3d153a6daca9730d685b483e779384ce" or // includes/database/sqlite/schema.inc
        hash.sha1(0, filesize) == "802e206777d89fd2c1bff3eebeb14131953059e2" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "62e08a84c9456cb7b2be8323b39e6363330565af" or // modules/user/user.install

        /* Drupal 7.10 */
        hash.sha1(0, filesize) == "f8d160b22569d99bb7ae606d897b5739aba1b4c0" or // includes/locale.inc
        hash.sha1(0, filesize) == "d4bd1976a0d91a872f2ee337adbd0dbd08981328" or // includes/theme.inc
        hash.sha1(0, filesize) == "193f4a8468152cc92568fba79536e8188c026048" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "3776fcae25ce7a1e09afdf16d7af516278d4db90" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "9915a088e3b9be5bab1cf0af896ca5c3ca6f5a91" or // modules/system/system.api.php

        /* Drupal 7.12 */
        hash.sha1(0, filesize) == "6ba7cc7cdbf3ac477cabb29eaa7ec544d38618cd" or // includes/locale.inc
        hash.sha1(0, filesize) == "30c00b4ecc434169129c91a21388e6fa343263b5" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "66c8f012e591b67260b395ae4cd3e55aa63518f9" or // includes/database/query.inc
        hash.sha1(0, filesize) == "5bc8b220886f9127c625521bbea545e9d4e5ecf6" or // includes/file.inc
        hash.sha1(0, filesize) == "9683c49120d00594cc6669d691b3945679f247d8" or // includes/xmlrpc.inc
        hash.sha1(0, filesize) == "3ad0b3de8824928da3f4dadf4969ea7abf1e9e76" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "83bcc07bd2c47f6bd5b21e7686d72606b36f2a97" or // modules/color/color.module
        hash.sha1(0, filesize) == "6e863704c3bd2d18bda76990731797aea26b6e45" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "a6dfab1b914e1f1d4413a5370d2cfba0ca9eccd3" or // includes/update.inc
        hash.sha1(0, filesize) == "a2996d736eef113f602b2b8c9815fdcdf166edd7" or // includes/theme.inc
        hash.sha1(0, filesize) == "ad2ed35be4a5b72d759d80dccd0870023a8b559a" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "6d6bf6fab7bd7e62781e9b3f214e75b6fd0401ef" or // modules/node/node.module
        hash.sha1(0, filesize) == "5a0cb26b63ebfd0a9ab9b6b639c28be96bda678a" or // includes/batch.inc
        hash.sha1(0, filesize) == "873673223fcf2c5ffbb2ee61e46b60e88276bb2c" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "c94089c0c1f7e28099713ac4358361ab6c093b8e" or // modules/image/image.effects.inc
        hash.sha1(0, filesize) == "5e622a61c008ce9e28e1e1ca8c5396c716eec50d" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "f9f2950ec923251f1410c3a010a40bd92e9c1c2e" or // modules/user/user.install

        /* Drupal 7.13 */
        hash.sha1(0, filesize) == "fdc337289dadbc2a4d51d50603b6a1a5cf314a2f" or // includes/file.inc
        hash.sha1(0, filesize) == "9517f7d6b6aafe54b7e70c33f9da3f96b3e30a0c" or // modules/image/image.module

        /* Drupal 7.14 */
        hash.sha1(0, filesize) == "e0e6c50f7a5fef4095d0511db65e489306dd2bc5" or // includes/locale.inc
        hash.sha1(0, filesize) == "559e78ca68c387361a9b205a9eb6ba39de431cd9" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "63661ea9e3f2c0a4300d9110e44ec6eba34d9ecf" or // includes/database/query.inc
        hash.sha1(0, filesize) == "ceaeb8ead71f3f102e0b7eda1704ecf6f752ff1f" or // includes/file.inc
        hash.sha1(0, filesize) == "b9d2e309d9f3879c6aabe12087d2afa117f72e42" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "fc041148a8964db0130e497050a820cd44bea728" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "8c5963e0ebe56652269d97ac155b4750c9268018" or // modules/color/color.module
        hash.sha1(0, filesize) == "7d882fc545e045e486cdec4fbe5137ef604b747d" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "ba874d97c43cae425fcc485d15f8287b0f030f1c" or // includes/update.inc
        hash.sha1(0, filesize) == "9be718159cda03c3872c1b209b5b1fa84fb86283" or // includes/theme.inc
        hash.sha1(0, filesize) == "f3d155a0156229045cd61033373e7404a11730a6" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "b747e7c1ac3239f51551e12c1b3673c4f9b53cda" or // modules/node/node.module
        hash.sha1(0, filesize) == "4f5c656cb1db75129aa75cab4ba0cba4d57f1fa5" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "d1deca550745738a82ce725de78f0661d0081b69" or // modules/image/image.module
        hash.sha1(0, filesize) == "921e4866862f1123f48cb6b51c805933b7eea9ff" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "c112dddc71fb901ebacab6e6f30674e952873ab2" or // modules/user/user.install

        /* Drupal 7.15 */
        hash.sha1(0, filesize) == "89b2e192085ca361a61a8cd7b37852f377885ad9" or // includes/locale.inc
        hash.sha1(0, filesize) == "8eb49bc4f8056989eff06d0fd1027b198151d03a" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "93beff3b71eca68011eb61388a66db2f23c5ee63" or // includes/database/query.inc
        hash.sha1(0, filesize) == "ad03ed890400cf319f713ee0b4b6a62a5710f580" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "73f4bb0c0d1b84887e03815381334b53f13c01f7" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "fbae17fa9997c3a5b2f51ac38519af54c2138575" or // includes/update.inc
        hash.sha1(0, filesize) == "a1d0eb20cec51c12552955ff4ca77cf6f8ec8a0c" or // includes/theme.inc
        hash.sha1(0, filesize) == "6c9c01bef14f8f64ef0af408f7ed764791531cc6" or // modules/system/system.module
        hash.sha1(0, filesize) == "142bf4bc3de00b35a05584ff17cbe7264c017b37" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "80ed887b7589aab47b263a4e92a1dff8e7675156" or // modules/node/node.module
        hash.sha1(0, filesize) == "81a568555885316598cf73fa67660f32e6f6d439" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "1fb1b04c34e55ee113f82adb6fb5cf35b415242d" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "d9a1159df42f8ed46acde0b7ef3dab54dd9276d1" or // modules/user/user.install

        /* Drupal 7.17 */
        hash.sha1(0, filesize) == "87a638d6809ec1740bd206095cbba9473d43134a" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "2ada89b2b4f02665654c637060e6401617421b35" or // includes/file.inc
        hash.sha1(0, filesize) == "e288cbba2d7791014f8d5056f7bc96c0eb2f7034" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "b9e993eb5138a2abe365ee837fa1923a70849721" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "26be86fa997a3d2d560589991a96cad4f96902e3" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "5496e25660589649f4bfcf21441cd34d50461332" or // includes/update.inc
        hash.sha1(0, filesize) == "a21cb2e9f9af380dd414137b31e635826cbe93a3" or // includes/theme.inc
        hash.sha1(0, filesize) == "d94d0ad98ae0348420f4bd6f76b9721ec9f765fe" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "06f2ae2d736cd60b01ba7c58711f9bf78e4dc5d8" or // modules/node/node.module
        hash.sha1(0, filesize) == "b6d4da7d08276c36e6e57300eacd1e7fdc129f82" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "f3f1e8913545884f4e18da979b299b2c31dc4464" or // modules/image/image.module
        hash.sha1(0, filesize) == "07b172f6bae1f3379d80204c986447a16ea3faef" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "1256625518f3bd4e8816265c0a1f50ee8f0e576f" or // modules/user/user.install

        /* Drupal 7.18 */
        hash.sha1(0, filesize) == "b54c24bb2a8be7e46d8565c0d116efe8f76feec7" or // includes/file.inc

        /* Drupal 7.19 */
        hash.sha1(0, filesize) == "0b3443743f466756c108c38ab87ccf4adcf6b403" or // modules/image/image.module

        /* Drupal 7.20 */
        hash.sha1(0, filesize) == "21a79abbf5c58274ed20af6a31c36337b51cf529" or // modules/image/image.module

        /* Drupal 7.21 */
        hash.sha1(0, filesize) == "f5a411da3de18d2c7317c68b4accdd5d639e9c3e" or // modules/image/image.module

        /* Drupal 7.22 */
        hash.sha1(0, filesize) == "a80edc160988720b1e1698cacf7ed9d463ba32b7" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "2c30986a35dbc2cc30677bf1bee693af2d79f29f" or // includes/database/query.inc
        hash.sha1(0, filesize) == "2ff3f5392b01f0863835e9f64adadbbc15e0cf47" or // includes/file.inc
        hash.sha1(0, filesize) == "0d11b0111510c28850bb2da05133288bf68b29bb" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "716849249abf5fa9357c969dc7c469a650cefb4a" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "5dfed6dda5a73aeb68317f4075d207061e00a97b" or // includes/update.inc
        hash.sha1(0, filesize) == "620882ff6d924aebdc623939e9f258cfc280d558" or // includes/theme.inc
        hash.sha1(0, filesize) == "f22075fbd3b250ff34d9bdf3e9e9d65bad41bffc" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "a60ac92515062e34cbd2f6a863f89c5154476ffa" or // modules/node/node.module
        hash.sha1(0, filesize) == "44af4b05bdfb190ff25905516f7e2e6274c7b0f0" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "24d8c75b194eccc163ba34e153cb6bd733e1493c" or // modules/image/image.module
        hash.sha1(0, filesize) == "c6128650f2103c3139af69e69a7c8fd5f7f08f4f" or // modules/locale/locale.module

        /* Drupal 7.23 */
        hash.sha1(0, filesize) == "d3389a9db226a217aa9785cb72b699b36e1e4db4" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "3a4c2eca65105c3248fa6ef1d1f2dc2eb287a313" or // includes/database/query.inc
        hash.sha1(0, filesize) == "4a4a2967b901d7e3ded1dc099388448712a0ed2d" or // includes/file.inc
        hash.sha1(0, filesize) == "4268df3cf19556a7b7d0798dc81977c90acfa0e7" or // modules/locale/locale.test
        hash.sha1(0, filesize) == "bc96ed062a7fad7ebbda32669c3a5daa381575a6" or // modules/color/color.module
        hash.sha1(0, filesize) == "e117ed405022dcc8175d306b96c42a53f7c0410a" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "2b6073b216fb7d5d7ef3465d50e596fc2b6a70ff" or // includes/theme.inc
        hash.sha1(0, filesize) == "89a541888f21d7af626236301ac1f9ae26170e99" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "664d80035143128c50e60bf8396b0b64e62630df" or // modules/node/node.module
        hash.sha1(0, filesize) == "f3b335d92b224f2edc24ad4127c711dbb04df928" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "e3652334ff49ca8032c20a6a32ba6f11eef0af36" or // modules/image/image.module
        hash.sha1(0, filesize) == "5f2e0a670d73bc49a851beeecd2785465664ea7b" or // modules/locale/locale.module
        hash.sha1(0, filesize) == "bdf2b5b33ff442c52017b42e051037dc8b8ce2fa" or // modules/user/user.install

        /* Drupal 7.24 */
        hash.sha1(0, filesize) == "7ab41616f021e4adf111d5680c4c42e029d4948f" or // includes/file.inc
        hash.sha1(0, filesize) == "ae60c814d2cc28baa49e61c7756d0120ef9a728b" or // modules/color/color.module

        /* Drupal 7.25 */
        hash.sha1(0, filesize) == "03b78bcb97010644d79316c3e8d193b50eadf5bf" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "7c0343c14a377faa35bb23e647854f69f4db8218" or // includes/database/query.inc
        hash.sha1(0, filesize) == "af993137f64bfafa4eca1436ab75a2fe8b56cf8f" or // includes/file.inc
        hash.sha1(0, filesize) == "6adee901d4e90e467b331b65a17fbb63a158d201" or // modules/locale/locale.test
        hash.sha1(0, filesize) == "9213eaff09673a2880bca63e3468b53582998181" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "0091ce1a78ad86c100b0fe1e9eeb5fbf53c9c441" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "04e080495f15a6b82b85de9e9897e77e070a4d6b" or // modules/node/node.module
        hash.sha1(0, filesize) == "bac2e33d5cd286c3ffa1bdbfa3aeb5f5ea40e7d7" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "7ff35df8ba2ca76304675d0938e39c2f2f8b9397" or // modules/image/image.module

        /* Drupal 7.28 */
        hash.sha1(0, filesize) == "9a03817a3f21758efd21015e5970f52150931629" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "225b56c05112c540df593bf5fc445c34f21d02db" or // includes/file.inc
        hash.sha1(0, filesize) == "f6db3d23187231bf064baba905186f72c9432252" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "70223710b73c315d1efc4626e7fdd791316ca597" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "0be77ea88557cdf53af7e18c43d68fa5c021f012" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "111e775db99adb9f9478205c3752f968f328a79a" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "34308cbe2ed163534f3b7f867833a2fee8cab163" or // modules/node/node.module
        hash.sha1(0, filesize) == "3b6d9c3db3a7cbebe343a4fd8bfe08fba7a96c36" or // modules/comment/comment.module

        /* Drupal 7.29 */
        hash.sha1(0, filesize) == "0ff5f28b5e0e639d24a2c488f97ded8baf51a9dd" or // includes/file.inc

        /* Drupal 7.30 */
        hash.sha1(0, filesize) == "cfad32d1ec605aa499eec8dc1922c2cd3cad8b46" or // modules/system/system.api.php

        /* Drupal 7.31 */
        hash.sha1(0, filesize) == "29f04965884c8ab2d11f9fd17224a9297b325c0c" or // includes/xmlrpc.inc

        /* Drupal 7.32 */
        hash.sha1(0, filesize) == "a28eb745deebf8a0b557a7acf29886016db68095" or // modules/simpletest/tests/database_test.test

        /* Drupal 7.33 */
        hash.sha1(0, filesize) == "a5a32dbda3cff7d92dfd7345a1d0bfdde388ce87" or // includes/locale.inc
        hash.sha1(0, filesize) == "cec9caac43b728cf84b873c1c534fde1a154d01a" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "649901b834dae9410b945c5a49e8c95d750e713c" or // includes/file.inc
        hash.sha1(0, filesize) == "152c09b9a21b75766ced086dac7231f89061ca13" or // includes/database/pgsql/schema.inc
        hash.sha1(0, filesize) == "19c45985dfee7dc27a3a275542dee7c8fc7ebd6d" or // modules/simpletest/drupal_web_test_case.php
        hash.sha1(0, filesize) == "9867145895dd79c48dab1a3382cb27ed24ea9e23" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "52019f747f744297f17e0f7012a80f8342a16fdc" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "108d5ebef4963fabe342b078a5c209a3175b9099" or // modules/simpletest/tests/theme.test
        hash.sha1(0, filesize) == "0fab9151adf3f689db7a74ce88595a49b01a6c91" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "d2a0a40abf9f252c64e370c9e8682a90039c3746" or // includes/theme.inc
        hash.sha1(0, filesize) == "e4a92eda6a80b64f755217d4ffe41912511610b5" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "e970494cc4a61aa7aed3878f46ee7d628a5e9172" or // modules/node/node.module
        hash.sha1(0, filesize) == "9476e22cde10bde2258f95cd10ad180b5e5af6fa" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "d6cc1f41b9e9dd76236513e584eeb287b6f3c73f" or // modules/image/image.module
        hash.sha1(0, filesize) == "7493b9f78dea9f379fc0b32769859debae47e003" or // includes/database/sqlite/schema.inc

        /* Drupal 7.36 */
        hash.sha1(0, filesize) == "611ded868095f236e0a259bfde372d9f4b469a48" or // includes/locale.inc
        hash.sha1(0, filesize) == "76fb1a3b18da5c1168a719bc636106071621dc4e" or // modules/field/field.api.php
        hash.sha1(0, filesize) == "00e4591f606022cc086341399bf2a1abb264c6e6" or // includes/database/query.inc
        hash.sha1(0, filesize) == "e129b0c980d4ee0143717e334fc094a042dab464" or // includes/file.inc
        hash.sha1(0, filesize) == "09c81d96da6a426c447bc685f1aaef2cff26d3f3" or // modules/locale/locale.test
        hash.sha1(0, filesize) == "24e84aa41c3bebde17f5802439a73477952828be" or // modules/simpletest/tests/database_test.test
        hash.sha1(0, filesize) == "0a86785b7bc285066911536562b8b4c38ca163b6" or // modules/image/image.module
        hash.sha1(0, filesize) == "a1021de42e0f6f2b6d90579154f4d7651e48b3dc" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "d53477366c6fd64a25d6777cc3bfb34f4038a39e" or // modules/simpletest/tests/theme.test
        hash.sha1(0, filesize) == "6a4553e36e499a2d348cf6a9c010d51e0e0bcf06" or // includes/theme.inc
        hash.sha1(0, filesize) == "3ed3f905448dd8d59cc0ca9a82ee02f40435c15e" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "db7a1eec1651683d78dcc8c3d3d0a842e71a2466" or // modules/node/node.module
        hash.sha1(0, filesize) == "ec81a47e662f903b233e0017cb7d876a7af4849f" or // modules/comment/comment.module
        hash.sha1(0, filesize) == "ad7587ce735352b6a55526005c05c280e9d41822" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "93d5259804a022d3a595482dae8b628506915ae4" or // modules/user/user.install

        /* Drupal 7.37 */
        hash.sha1(0, filesize) == "dfa67a40daeb9c1dd28f3fab00097852243258ed" or // modules/system/system.module
        hash.sha1(0, filesize) == "921a9d9d1e3da2b2ca6556003cbc7344729b875e" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "c74d2d4c3d15d5a5b233f79a5ba26030261c4560" or // modules/node/node.module

        /* Drupal 7.39 */
        hash.sha1(0, filesize) == "5bdafc679453dac010f3d200bf60e1723b060563" or // modules/simpletest/tests/database_test.test

        /* Drupal 7.40 */
        hash.sha1(0, filesize) == "5ad23ac95682c3e02e0679c662afe2ab4dc9225b" or // includes/locale.inc
        hash.sha1(0, filesize) == "9b21dd9b1ef24590e8e727c7e06c93acd53653f9" or // includes/file.inc
        hash.sha1(0, filesize) == "1ddde3edf851513b4e87438fa074fe71514cb7a5" or // modules/image/image.module
        hash.sha1(0, filesize) == "65e0cdf7b98ab9a02f1edd98e34e978814c4b397" or // modules/node/node.api.php
        hash.sha1(0, filesize) == "9b6324f437401cc9484d4af0d41a7b6837a83097" or // includes/update.inc
        hash.sha1(0, filesize) == "ee4b12df28ea4349eaa2dd334a187b1cb2bc108f" or // includes/theme.inc
        hash.sha1(0, filesize) == "d3fe04a5f7fe23d1333525334431ed897fbc9c17" or // modules/system/system.api.php
        hash.sha1(0, filesize) == "ca5f964f5ca7eac379f5e4848faead66103b2ba0" or // modules/node/node.module

        /* Drupal 7.42 */
        hash.sha1(0, filesize) == "6ced2c3aafcd17b69d72fb0c6d7a01da16be8d9e" or // modules/image/image.module
        hash.sha1(0, filesize) == "e58f7bcd263e38e6101da654a505fb42dc821705" or // modules/taxonomy/taxonomy.module
        hash.sha1(0, filesize) == "aed7b175e86ba70e75d7b0eb184f07ce8fb4afb0" or // includes/theme.inc
        hash.sha1(0, filesize) == "59810b9f4ea730462c172ee8b7eae08da2b4dbe3" or // modules/node/node.module

        /* Drupal 8.0.0 */
        hash.sha1(0, filesize) == "7753d6142afc9f7df56c3f90aa715c3c71d68f65" or // core/scripts/transliteration_data.php.txt
        hash.sha1(0, filesize) == "8f6dcca398f17d7fc9e9fa43b24ad134f349aa13" or // core/modules/filter/filter.module
        hash.sha1(0, filesize) == "ed182aaa40ae08427fac885a22dbd18556bdd0a9" or // core/modules/system/src/Tests/Theme/TwigDebugMarkupTest.php
        hash.sha1(0, filesize) == "241803b9ce7dc45ddb117e2b637753be71bce856" or // core/tests/Drupal/Tests/Component/Utility/CryptTest.php
        hash.sha1(0, filesize) == "15f5c3913cbf70ae110c69126141f784bc31d1d6" or // vendor/guzzlehttp/guzzle/src/Handler/StreamHandler.php
        hash.sha1(0, filesize) == "11acd095e5aac5b66592f80b1c53e471dda458fa" or // core/lib/Drupal/Core/Database/Driver/pgsql/Schema.php
        hash.sha1(0, filesize) == "ff6b6fc1219047d4ecd51713eea7bcf6877f07f4" or // core/modules/image/src/Tests/ImageStylesPathAndUrlTest.php
        hash.sha1(0, filesize) == "ff850f37457b81677f7ad4d5e96f180dc4efbd8c" or // vendor/twig/twig/lib/Twig/Profiler/Dumper/Html.php
        hash.sha1(0, filesize) == "67c8d48238c085aa5a69a45c2849a9cbd27dab90" or // core/modules/filter/src/Plugin/Filter/FilterHtml.php
        hash.sha1(0, filesize) == "0629f5a202ca921fcc0efad4e87192ab868a85b7" or // core/lib/Drupal/Core/Database/Driver/sqlite/Schema.php
        hash.sha1(0, filesize) == "c3d3a752ac41853573491999c967e9d2f3bf9bba" or // core/lib/Drupal/Core/Database/Query/Condition.php
        hash.sha1(0, filesize) == "c05c86dda9ee0a4fca279336628c66f01e7c3d55" or // core/includes/file.inc
        hash.sha1(0, filesize) == "2945e559212b15a7a689e102655122a8732cf891" or // vendor/guzzlehttp/guzzle/src/HandlerStack.php
        hash.sha1(0, filesize) == "5da6eb43a06886882ad212322fec8c413bbfe07e" or // core/tests/Drupal/Tests/Core/EventSubscriber/ActiveLinkResponseFilterTest.php
        hash.sha1(0, filesize) == "c84192069328ba0643be42e6c7cf635dd9599df6" or // core/lib/Drupal/Core/Routing/UrlGenerator.php
        hash.sha1(0, filesize) == "e1af8525946c0784f1c3e18163ea1ae7f5ff0f38" or // vendor/twig/twig/lib/Twig/Profiler/Dumper/Text.php
        hash.sha1(0, filesize) == "514b2d7e438a37911d198c0af8efa52707734b01" or // core/modules/simpletest/src/TestBase.php
        hash.sha1(0, filesize) == "2cc7fdc4b71072cc62a2183f59ca002384a85020" or // core/lib/Drupal/Component/EventDispatcher/ContainerAwareEventDispatcher.php
        hash.sha1(0, filesize) == "5aa782930e47af64c4953333069d3af316aac65c" or // core/modules/node/node.api.php
        hash.sha1(0, filesize) == "61bb3ecd3ae1ad4178c418787765ae89bae07583" or // core/lib/Drupal/Core/Theme/ThemeManager.php
        hash.sha1(0, filesize) == "abfc22a32cc507308e7be802481b941e5a8bf7a2" or // vendor/guzzlehttp/promises/src/Promise.php
        hash.sha1(0, filesize) == "a4acb1dd03d580981f6fee26e0059879ffad8091" or // core/includes/update.inc
        hash.sha1(0, filesize) == "8954260cbb93f46da59cff358c824679395664c2" or // vendor/twig/twig/lib/Twig/Node/CheckSecurity.php
        hash.sha1(0, filesize) == "b4e5c38a4dba9c2a00d69e42a6796859c5fd09e9" or // core/lib/Drupal/Component/Utility/Color.php
        hash.sha1(0, filesize) == "b417813eb1334792ce2dd9441810dfd538965ffc" or // core/modules/views/views.api.php

        /* Drupal 8.0.2 */
        hash.sha1(0, filesize) == "784060b6f32a11c2bd460e787e9bdcc5064d4b9b" or // core/modules/filter/filter.module
        hash.sha1(0, filesize) == "784e6588f345342345fa8eb060f4f8b47d70bd11" or // core/lib/Drupal/Core/Database/Driver/pgsql/Schema.php
        hash.sha1(0, filesize) == "86236e39416f20c37ec26aa0c33d7e5736ab603f" or // core/lib/Drupal/Core/Routing/UrlGenerator.php
        hash.sha1(0, filesize) == "b5e81d65bfcec0a06cb37223b53cb3500a4c4c45" or // core/modules/simpletest/src/TestBase.php
        hash.sha1(0, filesize) == "3beac5f97e3031e48797a0731e75aec8b619b5c3" or // core/lib/Drupal/Core/Theme/ThemeManager.php
        hash.sha1(0, filesize) == "1c6dba82be1f7eff0fe75afd0bd2775b1efb7857" or // core/scripts/run-tests.sh

        /* Drupal 8.0.3 */
        hash.sha1(0, filesize) == "1bb3291430e0c41019200c53efdf4b6f5a269227" or // core/modules/filter/src/Plugin/Filter/FilterHtml.php
        hash.sha1(0, filesize) == "c26e101151020b63f0bd199d50bc10c5a8114cb4" or // sites/default/default.settings.php
        hash.sha1(0, filesize) == "d38a1297436cd7488db6f35c1e3c65e591fe2daa" or // core/scripts/run-tests.sh

        /* Drupal 8.0.5 */
        hash.sha1(0, filesize) == "854a8b01da0fa52f484453cce6efac16678066d0" or // core/modules/filter/filter.module
        hash.sha1(0, filesize) == "dc99435e1fd9209bcc8e218bb24ba5d3bff4d744" or // core/lib/Drupal/Core/Routing/UrlGenerator.php
        hash.sha1(0, filesize) == "476755f642a71fdadbc964d1401ba25f3a6246cb" or // core/modules/node/node.api.php
        hash.sha1(0, filesize) == "321c3fb11e0c029c1f765545713c0a222a3b28e0" or // sites/default/default.settings.php
        hash.sha1(0, filesize) == "323849dc02380489a19e316be93faf60444737d5" or // core/modules/views/views.api.php

        /* Drupal 8.0.6 */
        hash.sha1(0, filesize) == "51de351fd612d0c864783acd9497c41fa4a096d0"    // core/scripts/run-tests.sh

}
