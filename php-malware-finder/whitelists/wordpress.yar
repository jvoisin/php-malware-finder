import "hash"

private rule Wordpress : CMS
{
    meta:
        generated = "2018-05-29T21:58:54.242806"

    condition:
        /* Wordpress 2.0 */
        hash.sha1(0, filesize) == "bbb86765c1fb77a073e4bb76b97223360a140438" or // wp-includes/links.php
        hash.sha1(0, filesize) == "fbaa6d7843fb7fb1d761fb4e89fd727cd247fe5b" or // wp-admin/admin-functions.php
        hash.sha1(0, filesize) == "dfa0f69cff59b3784ef3ff5aa494291a536af799" or // wp-admin/execute-pings.php

        /* Wordpress 2.0.1 */
        hash.sha1(0, filesize) == "c1e726699d59c7e2e401a8881e19080ffcf9d5db" or // wp-admin/admin-functions.php

        /* Wordpress 2.1 */
        hash.sha1(0, filesize) == "30bafe9b7676fce546e4fd336c736b4c9ff552b0" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "f455b31b339fe9bde065b83557c827a79f3c83da" or // wp-includes/js/tinymce/tiny_mce_gzip.php
        hash.sha1(0, filesize) == "5861ba2b2450b0f0253638b4620296cc0f14e481" or // wp-admin/upgrade-functions.php
        hash.sha1(0, filesize) == "17f2dee4758b8954a3ea530bef32d42c0f788cca" or // wp-admin/admin-functions.php

        /* Wordpress 2.1.1 */
        hash.sha1(0, filesize) == "3d0be10443bcf5da1bda9af01e3f0fa949bbe71b" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "4294be40fa4d4bdc3325a95bba19ce016b16c36a" or // wp-includes/js/tinymce/tiny_mce_gzip.php
        hash.sha1(0, filesize) == "29960dd8a3266618660ca61eedbe621add7b57b2" or // wp-admin/admin-functions.php

        /* Wordpress 2.1.3 */
        hash.sha1(0, filesize) == "0aeea754cd309c6e83d46319321af3287f93aeee" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "f0b82ec7531440a35614f719608fd230343b2a96" or // wp-admin/admin-functions.php

        /* Wordpress 2.2 */
        hash.sha1(0, filesize) == "bf2b70e53ee67b2ae7810a26efd10015007ef35b" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "04f521363e4be1a84ced344b6246a115fdf43680" or // wp-admin/admin-functions.php
        hash.sha1(0, filesize) == "13d44b4fe578ac92865b932116b642553e66138d" or // wp-admin/upgrade-functions.php

        /* Wordpress 2.2.1 */
        hash.sha1(0, filesize) == "a762bc60035fbd07a03395990e3a17225d40c18c" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "ba7c2dabdd8f354805e7954af1dae347af5b2b5b" or // wp-admin/admin-functions.php

        /* Wordpress 2.2.2 */
        hash.sha1(0, filesize) == "1f3ca35fc4f3392e0675d00e7faf2d14454581bd" or // wp-admin/admin-functions.php

        /* Wordpress 2.2.3 */
        hash.sha1(0, filesize) == "8b102045500a90e57816b7c4cec2e013389ffc15" or // wp-admin/admin-functions.php

        /* Wordpress 2.3 */
        hash.sha1(0, filesize) == "a56dd3402d9a6ac7d9c7458de78bb9fe690a4e61" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "c33ad18180e5f214882cfc5089244dd5c1dec904" or // wp-includes/post.php
        hash.sha1(0, filesize) == "d7c2fc6360bbc5e005ad5a2a5bba3f9a6d0c3985" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "1fa290b5a1db0f3c06c4bb677d71e0dace5bc407" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "7b93edca9041240d7dc8ef1c1a8c01f8c06f1192" or // wp-includes/deprecated.php

        /* Wordpress 2.3.1 */
        hash.sha1(0, filesize) == "cfcc7996f4e62dc3ea90a9ec51f8640a237850fe" or // wp-includes/post.php
        hash.sha1(0, filesize) == "5e1660411a9b827f69a918af706f297530d32312" or // wp-admin/includes/upgrade.php

        /* Wordpress 2.3.2 */
        hash.sha1(0, filesize) == "efd2b4896682d3de2c480437f0f30fc4b831a760" or // wp-includes/post.php
        hash.sha1(0, filesize) == "08f74717b55528b53d57ae36ce666fbd1dfd7f5c" or // wp-admin/includes/file.php

        /* Wordpress 3.0 */
        hash.sha1(0, filesize) == "2f17823196a19d5a1ceef3956e3d2eb040cbe94a" or // wp-includes/post.php
        hash.sha1(0, filesize) == "732b23a64894405084d045c1a54c727c3dfff7f3" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "0898f45c014c8498a75f7daf6b0cbdf441bb9117" or // wp-includes/js/tinymce/plugins/spellchecker/rpc.php
        hash.sha1(0, filesize) == "d6ef8c8a1ea02f5c85e50f2eed0a8cbd5e5d0193" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "f73f1e853035a9d762e0a314576c356a96f2b976" or // wp-admin/gears-manifest.php
        hash.sha1(0, filesize) == "5bc32390a960922991aa7ecd3c1a180ae29949a0" or // wp-includes/wp-db.php
        hash.sha1(0, filesize) == "38e877cac581bd695352ff0137edfcad3e3d1bf8" or // wp-admin/edit.php
        hash.sha1(0, filesize) == "da9d42e33e31a89b8e43713fdf6d481a90346b3b" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "6ccb3d84b02c0f61cdeb5cb6aa31074b5f84dc13" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "3726a55657ae60127682814ce08bab8e681846eb" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "81b5123e57455d1c6c7528a0a41900ce1097557b" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "079c1412cf049087ece1dbdce8e6eda255298dab" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "f5cd852cef9b5ddce964576077a9453d5bed6e67" or // wp-includes/deprecated.php

        /* Wordpress 3.0.1 */
        hash.sha1(0, filesize) == "ef830c5ea01d5c987e33a0329586752eff3f8668" or // wp-includes/post.php
        hash.sha1(0, filesize) == "b692ab19c4a4e165247fe5231ac8c9500a6ef332" or // wp-includes/wp-db.php
        hash.sha1(0, filesize) == "5fc135be16eccaf2c57dc0da95afb2595ab38219" or // wp-admin/edit.php
        hash.sha1(0, filesize) == "6fc8176d6e55cfb2d147045f0a3d51e1d18b3324" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "00523ecfaea6728acf8039904689e72fb3db2ce5" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "c02bebd5fed0f29fd757f797ede847290c1b3faf" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "cd9d212000368fdafec7d4de119243468bdb59a3" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "db884c013d52a30d7f9bce0c5ab6b71e727bf3d1" or // wp-includes/deprecated.php

        /* Wordpress 3.0.2 */
        hash.sha1(0, filesize) == "1568c01754122010324c7e54b16d0ee729db7fb8" or // wp-admin/includes/file.php

        /* Wordpress 3.0.4 */
        hash.sha1(0, filesize) == "8c6fd610d0c1011738bc609037cdb20f612c6dd3" or // wp-includes/formatting.php

        /* Wordpress 3.0.5 */
        hash.sha1(0, filesize) == "4b4e2812781b43b230ee8518b41655651c46fae3" or // wp-admin/includes/template.php

        /* Wordpress 3.0.6 */
        hash.sha1(0, filesize) == "b20516753f8b08274f37d0af8ac292fde675ae71" or // wp-admin/press-this.php

        /* Wordpress 3.1 */
        hash.sha1(0, filesize) == "52b72bb5ed4f17ecc9b9eed29a2ea85bc25ccb80" or // wp-includes/post.php
        hash.sha1(0, filesize) == "dce46c28a1e7f873d0690eeebf5599107b5cc9bd" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "afafe4f64f7d03d7c6388376e8e4b95452df0e0f" or // wp-includes/js/tinymce/plugins/spellchecker/rpc.php
        hash.sha1(0, filesize) == "98de0eaa9d98036bc80e72b1cc36df55a2285608" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "4284eb6c751a85a92918ea860c81e918fed4d12b" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "4de3ef74d659fe6a03c6b8eb573a409ec788a786" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "e9eca94390585b1464acf2fe403e8e622017b213" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "1d18eb1761d198bcbcd4483df0d0d6962347fee3" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "46282e82abd01e487214fbe92c18bf91d903540f" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "a22397b4d9c5f1c17b05a16a2bb5a62d18de98bc" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "9416ed9d35945516e0a8a9765da446cfba784744" or // wp-includes/deprecated.php

        /* Wordpress 3.1.1 */
        hash.sha1(0, filesize) == "8a4e3484e8ec2e66688123f99628eed3801d735c" or // wp-includes/post.php
        hash.sha1(0, filesize) == "43f3fb72755eb50a1ce668cfab901596e80d30d4" or // wp-includes/formatting.php

        /* Wordpress 3.1.2 */
        hash.sha1(0, filesize) == "1245a779337ad2848deb784b72c0d5b757897452" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "113e23c7e90755b6eb6a7dfd59ee8dc38ab567ac" or // wp-admin/press-this.php

        /* Wordpress 3.1.3 */
        hash.sha1(0, filesize) == "1bb1e85fff06511daf3fd83199caecdabab6e399" or // wp-includes/post.php
        hash.sha1(0, filesize) == "a74eb72e85391e8b1cc73ab31bbd0e354ac46ddc" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "2fac6d0984fcfdd13e65cb6131a1cf4b3833aa28" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "c1009c13e48211fc4100c3a947a8d4bfc5e416bc" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "8146cc5e953af859b2ffb7f62b88829acdb83db9" or // wp-includes/formatting.php

        /* Wordpress 3.1.4 */
        hash.sha1(0, filesize) == "dfbfa7de5b02c336ec104009d6beb239ca51d37d" or // wp-includes/post.php
        hash.sha1(0, filesize) == "34575033fdc4a88485affd3a22ae16431d14cf2c" or // wp-includes/formatting.php

        /* Wordpress 3.2 */
        hash.sha1(0, filesize) == "ce4bb6419545ddd1ce707d30698872ca57f84289" or // wp-includes/post.php
        hash.sha1(0, filesize) == "9e618bf8db66289bbe562e82cb58d5938a5db0ef" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "0d57e786b77492eb32520d94c8dabc4d4ac305a8" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "f2ee76708f1ff6ccf1359535c9ad2dbce6898ae1" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "d83c053168882c6b15b7f74a804d45b7575749ad" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "1f7ff93c3fab868107914769b605d0def295a6c3" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "edfb987356794111f780504c2229cc3b01afbdf8" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "b4f53b8c360f9e47cc63047305a0ce2e3ff6a251" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "7622efd361b7e6550387413a289c5f5475d0ccca" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "232e4705e3aa28269c4d5e4a4a700bb7a2d06f24" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "ac8298df16a560c80fb213ef3f51f90df8ef5292" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "1c9072768299b183d4857f1885ca82de4bebfb06" or // wp-includes/deprecated.php

        /* Wordpress 3.2.1 */
        hash.sha1(0, filesize) == "c2b547fc0d12ede138e8cffd5b1aa27acbfa29e4" or // wp-includes/post-template.php

        /* Wordpress 3.3 */
        hash.sha1(0, filesize) == "129ef278a99a98ce31f1235cf69bc2cdee267d14" or // wp-includes/post.php
        hash.sha1(0, filesize) == "413aad57841069fc0b0740d1c7c7c2d4d7d988be" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "108330d48a7c61427ccd6a811d06e32068794193" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "cc196ca59fcaa32da38d3232121720c2b66670ef" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "dd6c03117c5be60136154ca6c9f253a2b34111eb" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "5a598c1ad6c0fa1be0220a74f61165fc5cb3ffe8" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "8f2a8da640cca1f6530e856bb0936a522689cafb" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "55afddd06127cacb9921fe97010d6de32fc466f5" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "5de87a28128621172c2472771473f66ceb92f9c1" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "7d32f26d2eaf41cfb3db7aca06564501741f01ef" or // wp-includes/deprecated.php

        /* Wordpress 3.3.1 */
        hash.sha1(0, filesize) == "91761dab0e381623c11d466eb8bbe6473089c262" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "bb611f70db077823eac67668ce0eabb287dcfc32" or // wp-admin/press-this.php

        /* Wordpress 3.3.2 */
        hash.sha1(0, filesize) == "dde98051187dd8980d1c71b238f8f49ac3c01e75" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "4ba4cd920935b9c97934292e8278122c0d1ac54b" or // wp-includes/formatting.php

        /* Wordpress 3.4 */
        hash.sha1(0, filesize) == "ce118a1e4e0e13ec970455c5991a6e3c5587b50c" or // wp-includes/post.php
        hash.sha1(0, filesize) == "fd3b2cc886f96f2ab1b59475463ec8c2794f4a2b" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "7c236e3cb3578caa348b5bad2b69b55c0a8a28ca" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "cc5d596aeed57bdb3fb4cd3e36d51934a7e5b036" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "608fa4bc1a549c23d9b5a84d5b7b5c78f0b657e0" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "0909c3bdf43e04ac56a25ef905dd0b4f53b9ffe9" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "8e774a3fc20846ec483e697df70dd880d7bc6501" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "19716dcd7c07c7f3cf5bd83188722ce353a698e5" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "05d4712b1ca6512eabd5d1f0829002872fe715e4" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "59458078cdf7f72d2973bc9847c2e6abc4fe51c0" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "4db56ae7ff0df0dce135dc048eb61e6eb7f5cdda" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "b4e4b88f2be38ed9c3147b77c2f3a7f929caba2c" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "75e2ec0402e1d4b9e831baa6b9d6f680799f3fad" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "3d6a6cda6cfc2442e9e9b2822f3f610fb9a6da9d" or // wp-includes/deprecated.php

        /* Wordpress 3.4.1 */
        hash.sha1(0, filesize) == "68bdb7929d80b646d48597098d5635baab715f1f" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "b081cb618291aed33c5cdf7a1d0a96092254acc0" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "833281b4d1113180e4d1ca026f5e85a680d52662" or // wp-includes/class-phpmailer.php

        /* Wordpress 3.4.2 */
        hash.sha1(0, filesize) == "033d2a4d4b567bc0675270945c508706d53ad599" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "26c688bdc903314554443253e9c1131f3e96f5f1" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "3351b803ce18ae6044aad29d0a13f83603089822" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "aa35944e09e5f0224ebc8e7092749986c3ddce68" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.5 */
        hash.sha1(0, filesize) == "1b78bfbab457c9d4c323d125a71ffc8a0fbf9567" or // wp-includes/post.php
        hash.sha1(0, filesize) == "59c3672039f391e0eae6404d65be0c2807413822" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "28e0b9240c060cd9931cd13ab9cf4a3ff072b21b" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "e778fd21f4c37cbde6ef51dd698ccf5a86869014" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "41053178dc4f65a6cdaaed828936ecf58b08f64e" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "6061b47bcabfee2dd173a8d7226d5f1de83a3b50" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "79764a44e76d4592b80f81d36ff4afac8c8ef15a" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "32eb59b7604a3c7302d9e99194c94be8f59543db" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "13b7f0b3c81cc7f4e81fb7ed3df7a57ba33fc9e2" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "b6eea88c56a8db31a182353dc4c87e91fca1fa58" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "38c2d4b07a569816ec202277a5ef6b7724857f43" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "676dcf811757529323b6cec162b53ea827f82581" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "412986ba7634bd47b49b217c3f3994c321bb04cc" or // wp-includes/js/tinymce/tiny_mce.js
        hash.sha1(0, filesize) == "cdc24ca5c7bfcd559282559d2fb7edf97d0bb07b" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "d667f8cbda4ae5ff27ebdfbf80460b365f95ad46" or // wp-includes/SimplePie/Parse/Date.php
        hash.sha1(0, filesize) == "61ce791f8e638f784ea78de8aac14542fecde62c" or // wp-includes/deprecated.php

        /* Wordpress 3.5.1 */
        hash.sha1(0, filesize) == "b9772cdb5248c28b63c6fe54061eae3c905ef5d4" or // wp-includes/post.php
        hash.sha1(0, filesize) == "fad8e68cef70e8c88acfbee311fba3e19af686ac" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "dae4d60844af60c4af91022eff915acb40a35eda" or // wp-includes/js/tinymce/tiny_mce.js

        /* Wordpress 3.5.2 */
        hash.sha1(0, filesize) == "58c4fec199374f11a4d25f286310d26f32b34698" or // wp-includes/post.php
        hash.sha1(0, filesize) == "ed42423b4ea804a266b55ee8a43c784b94484db8" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "d2d79f3132131e04da1e65fb745ef8fe17913ec9" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "63150bc5aba51631a7d1173fe6eb1457e746f67e" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "91f418e5bf982e704bdf636e24bbb3544157e360" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "82f82acd2596d052599289d31fffe9b4a7044a58" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "b142d05e08e17cdae63ff3f7d2ba4f52a5220fe4" or // wp-includes/js/tinymce/tiny_mce.js
        hash.sha1(0, filesize) == "0712dbf8d70766e46cec993ccab1516afff9880e" or // wp-includes/deprecated.php

        /* Wordpress 3.6 */
        hash.sha1(0, filesize) == "1c3de7e965a68621ebe391f8c6bdf4a8f0180864" or // wp-includes/post.php
        hash.sha1(0, filesize) == "e6ed991a6a9ca86907ff64fffe3d703ba6cd2c7f" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "3b0f92aceabde1d563890109a9e4010083602910" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "225332f9e5b729fa5559d400d7bb519a742cf754" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "789ebc024dcf585583eeb380d048313dbe638fd1" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "cb6172495e8c3f5188d2a92a7604c2c29590e740" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "bee3dce3c314e3e7bff07a212a1526d705a082b4" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "41be5d2219e9b68d82e5bb389514e7a3d317908e" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "94867d244014a346f7adb305fc6ae266869f5a31" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "4856f6c16233bd80ab3ef38150a869853b0824f6" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "f4f02289d2c5d79cdc1e43f7a85a1bb18c1a57ed" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "546d97581cead4a9174e870fda57509bee7c64a6" or // wp-includes/deprecated.php

        /* Wordpress 3.6.1 */
        hash.sha1(0, filesize) == "ea9c9f658f90dc5ce7949b7fe84c5227ebdcdb5e" or // wp-includes/post-template.php

        /* Wordpress 3.7 */
        hash.sha1(0, filesize) == "25eb4aafa1055bb4073c59c94d8fa613af46bb8d" or // wp-includes/post.php
        hash.sha1(0, filesize) == "b379ed312821de983940d95277ecc8d6c0612cc1" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "8e280fe121b4d80b26f03ab102126be16e8f1713" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "1a279555b3b42acf396c64685fa3609550c50a54" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "5b03f5c0af13e2af46895d9bd44a0051933fc13c" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "e82e992ec0458021e3cac6d29d63ee402a0b6f0f" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "b1933980774e43f9ae0da0ef4864c0eb0075021d" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "090c6a51677e08011819fdfedd66f3d2324c655a" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "410511b419a166099c80c45987f6c58ca6d596dc" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "ebfa83b889d5c78595fbe6b4b7fe979c24c7ebdc" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "7bdc00fe5f1b5de5e3709434bf3068fe0f922808" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "729cfb5974a799dcf03352385016115d53a6c3fb" or // wp-includes/js/tinymce/tiny_mce.js
        hash.sha1(0, filesize) == "2a6efef04595109e9d38ffa63fa239b6a7f48a20" or // wp-includes/js/tinymce/wp-tinymce.js.gz
        hash.sha1(0, filesize) == "b68beee5d6af56d3869410ac6987a07346b3b37e" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "83a5d5b6ee067f0d3ea61a53a00d429300660f2b" or // wp-includes/deprecated.php

        /* Wordpress 3.7.1 */
        hash.sha1(0, filesize) == "cf8020daa2651b9eb70d6f82a76dbe95779acfa3" or // wp-includes/post.php
        hash.sha1(0, filesize) == "aac10c3ce50d3796942005ea7e2d2c266fdf39af" or // wp-includes/js/tinymce/wp-tinymce.js.gz

        /* Wordpress 3.7.2 */
        hash.sha1(0, filesize) == "f7e8fe7a94e29dddf97c75593549a67af5f3d0b1" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.7.3 */
        hash.sha1(0, filesize) == "40874153683b4ddee5b035e0ae8f00969daa17b6" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.7.4 */
        hash.sha1(0, filesize) == "48a3dab94dc548169700bb411148c6fbf30274c3" or // wp-includes/ID3/getid3.lib.php

        /* Wordpress 3.7.5 */
        hash.sha1(0, filesize) == "cfd871860c963b0fc5ab2d8c57bbe5fffd7dcb18" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "216423bf8c4d941eb3b5f40b24238fdc10516617" or // wp-includes/formatting.php

        /* Wordpress 3.7.6 */
        hash.sha1(0, filesize) == "3b81d2dafa7c2f263dcfe18c8ec40adc0c2036a9" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "a4be73c4196559b3a452f083a7c58a17092f0f2c" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.7.8 */
        hash.sha1(0, filesize) == "cba09f833be2259aecac397e1725b2ee1aa8d63c" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.7.9 */
        hash.sha1(0, filesize) == "b8df313b398f8d2a8ae8ca2c1ea87bb0ec3fa630" or // wp-includes/formatting.php

        /* Wordpress 3.7.10 */
        hash.sha1(0, filesize) == "3cdbe2d5884aa7c7ccfd9a63362bd8b551972eba" or // wp-includes/post.php
        hash.sha1(0, filesize) == "469a0400b94c2bbc6a01282cb0a58b5ef7766605" or // wp-includes/formatting.php

        /* Wordpress 3.7.14 */
        hash.sha1(0, filesize) == "50c414aeda8efa51d156742ae87a2ae4e46e9aae" or // wp-admin/includes/media.php

        /* Wordpress 3.7.15 */
        hash.sha1(0, filesize) == "2e8b912d7d8f6776263f6d440139ebf72cb835b1" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "7dd2fcce4f1473ef8d845440560dd61a80fe0736" or // wp-includes/formatting.php

        /* Wordpress 3.7.16 */
        hash.sha1(0, filesize) == "de1ce381b78522854c40d0ed5d6e01ddcaf6583e" or // wp-admin/includes/media.php

        /* Wordpress 3.7.17 */
        hash.sha1(0, filesize) == "fb860c6ac67d10057c6d0fb278790fbb0b3a037e" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "0dd1660527a337e98e4bfa236d236b5c5154ead2" or // wp-includes/class-phpmailer.php

        /* Wordpress 3.7.18 */
        hash.sha1(0, filesize) == "e254fc20dd675a2b96100a5f136999e9381454b5" or // wp-admin/press-this.php

        /* Wordpress 3.7.19 */
        hash.sha1(0, filesize) == "bbfe6f422aa0da18e8c59824b9009bdff2ea6956" or // wp-admin/includes/media.php

        /* Wordpress 3.7.20 */
        hash.sha1(0, filesize) == "6c2e10b76811e395bb04b2fca43788859e91e315" or // wp-admin/includes/media.php

        /* Wordpress 3.7.21 */
        hash.sha1(0, filesize) == "e161b8ff19233616fcbb677c54e67173c9b09ac3" or // wp-admin/includes/file.php

        /* Wordpress 3.7.22 */
        hash.sha1(0, filesize) == "e291505c0ea7b45d4d70aa19de8195750cff3825" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "6b45b6dae7bac47c15a8538ee10582b353fa248f" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "7fa4d3a0d849e5557de04b94d91f91b5cad5ddfa" or // wp-admin/includes/file.php

        /* Wordpress 3.7.23 */
        hash.sha1(0, filesize) == "b059fcf32621657b4e50cffceb8646a37d69b2be" or // wp-includes/post.php

        /* Wordpress 3.8 */
        hash.sha1(0, filesize) == "19e345ce751ddcd3b036252b413ad5cd6d0f127c" or // wp-includes/post.php
        hash.sha1(0, filesize) == "aa07c8cec8a7214c1e1b14eadef6d11f656e858d" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "234cc52d42912c81b494f698499241a784911b2c" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "ef00b087c2944e24ea589f19f6ec17183ccd7447" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "a7a1f9c36bfb60e34620639cca09b1c9198c0cc2" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "079335e8296897d75a97967c248b05171d67f7a1" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "188a34ebe732ee2aa8027af319509b5f352afde3" or // wp-includes/js/tinymce/wp-tinymce.js.gz
        hash.sha1(0, filesize) == "9e4fbae9453aa25551c886a0a127b0f072f7da9f" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.8.2 */
        hash.sha1(0, filesize) == "640d250a9d5e4f2f38afb1b6d07297965ce7c557" or // wp-includes/post-template.php

        /* Wordpress 3.8.3 */
        hash.sha1(0, filesize) == "517daad9762c862a2b8112b0ded22892885c2244" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.8.5 */
        hash.sha1(0, filesize) == "02deec16585c82504767b7335f3a00e5b238dd37" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "f39d1dc39f80d5dc44f6c8db061af352f00e836f" or // wp-includes/formatting.php

        /* Wordpress 3.8.6 */
        hash.sha1(0, filesize) == "82b96060eaf3669d8fdb6633679009657fc30b0f" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "38df98c4279883552cca8d75c582e48fd402a159" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.8.8 */
        hash.sha1(0, filesize) == "5a8f18a9baffe6e13f3b51b3a7ffdbdc29877b9a" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.8.9 */
        hash.sha1(0, filesize) == "5e72416a4b7543296e324a0130cb89c936df80fc" or // wp-includes/formatting.php

        /* Wordpress 3.8.10 */
        hash.sha1(0, filesize) == "397857a549a3bbb72372db4a39b67b0a5b0260ef" or // wp-includes/post.php
        hash.sha1(0, filesize) == "837d3165fdd6fa4bf3d56780a34ab33577fc248f" or // wp-includes/formatting.php

        /* Wordpress 3.8.15 */
        hash.sha1(0, filesize) == "b9c3c902217ba8f3bef52c395f7c0a83e279bd83" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "19cec1b0fffcb657dd976bb06e5b42e19ac2737c" or // wp-includes/formatting.php

        /* Wordpress 3.8.18 */
        hash.sha1(0, filesize) == "b978afc28451154bb7a693c565ef8b19f5bc6ae7" or // wp-admin/press-this.php

        /* Wordpress 3.8.22 */
        hash.sha1(0, filesize) == "6a91923acf188109acc2e5a30fda23881c55cc32" or // wp-admin/includes/template.php

        /* Wordpress 3.8.23 */
        hash.sha1(0, filesize) == "de642bb90ada3f41f206f396313e25816e5d8f7c" or // wp-includes/post.php

        /* Wordpress 3.9 */
        hash.sha1(0, filesize) == "fdade6ea8a0c9c3b7eb1de998985d50e57706329" or // wp-includes/post.php
        hash.sha1(0, filesize) == "d530843be2d501a131ff6b915a85e734cf97db26" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "5059267dfc14937e66f7d851633da471e709157d" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "981639d262d8852f3af27841751bdc47af0ad91f" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3b1f18ebfce502e1ff780869353124f8e906c722" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "b4066590d499d3fbbe16a039c397268044ba2966" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "123756694a70b3173df430c06eb2275fefd3d5c6" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "ade19a24ee69bc819952bc8dd17e9681419bf51c" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "55e6c3a26ff8ec1c9c438b04f434ff8c07ad3147" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "912e1f61a838b655fe2abc79736c99aabd48a356" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "ad34cc6370dfbca4f266cdc47042aa63fce396aa" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "1e5c370e65525383a5e3a7b0cdcb1f11b49c3916" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "30449c531e5b3d4472b05e1563f5dfe0731247cf" or // wp-includes/deprecated.php

        /* Wordpress 3.9.1 */
        hash.sha1(0, filesize) == "fc701bec3a8b4be04b95a54554d5258e9ec53604" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "bdb3011b2d6852961e1526902fb11bdc4ce035e6" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.9.3 */
        hash.sha1(0, filesize) == "0dbcc9f00219723fe83189adb3363117a991a47a" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "ec47de2fe4f43c8854283e306af6527220f10d8a" or // wp-includes/formatting.php

        /* Wordpress 3.9.4 */
        hash.sha1(0, filesize) == "967bb47c3c907d1eb7680d1336038dba72c889b1" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "7f0881182c770cce1e2ed83db5f9bc5d6dbe38c2" or // wp-includes/class-wp-editor.php

        /* Wordpress 3.9.6 */
        hash.sha1(0, filesize) == "b74a69b22dc896d893284007ec39a63f743e758a" or // wp-admin/includes/upgrade.php

        /* Wordpress 3.9.7 */
        hash.sha1(0, filesize) == "43cebf89b4f38592f6132ecea1ba941912a186de" or // wp-includes/formatting.php

        /* Wordpress 3.9.8 */
        hash.sha1(0, filesize) == "4f88a52e8ad9bfc95937c77c8caa5f1f04142f13" or // wp-includes/post.php
        hash.sha1(0, filesize) == "90d6097ca320df378e5479bfec559fee6f55668f" or // wp-includes/formatting.php

        /* Wordpress 3.9.13 */
        hash.sha1(0, filesize) == "fe58d69d790416da4bbdb6a55e323063834f4648" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "6a6a2a2780939a09d5764a3815851ff88d3c9aea" or // wp-includes/formatting.php

        /* Wordpress 3.9.14 */
        hash.sha1(0, filesize) == "56fb3cb81757e66eb09155b6529df8a4366dca58" or // wp-admin/includes/media.php

        /* Wordpress 3.9.15 */
        hash.sha1(0, filesize) == "20beff7a3a3b5644effe66a30a4a209a836661c0" or // wp-admin/includes/media.php

        /* Wordpress 3.9.16 */
        hash.sha1(0, filesize) == "17cf762e729f48b930c929e2c9b5f0fc8621c267" or // wp-admin/press-this.php

        /* Wordpress 3.9.17 */
        hash.sha1(0, filesize) == "62cab072dbad806cc40627261262bf7299caf21c" or // wp-admin/includes/media.php

        /* Wordpress 3.9.18 */
        hash.sha1(0, filesize) == "a899b606190b530dc5f12b1e8cfad8d84ac97285" or // wp-admin/includes/media.php

        /* Wordpress 3.9.19 */
        hash.sha1(0, filesize) == "1b28e79f006324fbe2b300a6ea743405ac438cad" or // wp-admin/includes/file.php

        /* Wordpress 3.9.20 */
        hash.sha1(0, filesize) == "ba73fa0db433dd6181a2ecf075fa634561e2545d" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "c33820caed04d7139d7581dcff20f50a2de25641" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "3c191f8de29dea67e78bfc52c8faf0562ecad260" or // wp-admin/includes/file.php

        /* Wordpress 3.9.21 */
        hash.sha1(0, filesize) == "988f8b36156f09622ac727a68d44e97116c34454" or // wp-includes/post.php

        /* Wordpress 4.0 */
        hash.sha1(0, filesize) == "82e32b63daae46dd047a0aeff5e55182a8a9a247" or // wp-includes/post.php
        hash.sha1(0, filesize) == "4fb0b9d1a9b2e4c03de74095d73457817986b979" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "9304e232507d1bdfd10c2820116ff6f429355411" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "b970f1af7c9836198ed149f6557b53e1595dfc2a" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "0fcd2d0b4b6884e2772e66eb6d078814593a1bc4" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "a983e0c54fabc75aa8eebcf507aaf3dfca8ad9d6" or // wp-includes/media.php
        hash.sha1(0, filesize) == "3c0ef307dc1b32e0f5f916511bc0df217de9d15b" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "fd9e49f9dd5452cf1b2880d9f47be0e303382ef2" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "8fc22fb5f4e8551587d0e311542134b062b5f8a1" or // wp-admin/includes/class-wp-list-table.php
        hash.sha1(0, filesize) == "4cc841961c01b4bd81dbe9972ccf39ec5c043192" or // wp-includes/query.php
        hash.sha1(0, filesize) == "d3332163c0606bec546372e1c94ee9c955522578" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "8b322e6512d24c3ad1893575c39242211b951c4b" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "97a5c2407641de70f7de8459adbacacd6b7edce5" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "07b367d691a9ef5d86c4b9832576ef206f35e625" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "21fc94443bb049bafa1e015bf3c2ec21b55900f2" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "81b49b9680bd7ba29e8b0149f7720103373e4904" or // wp-includes/deprecated.php

        /* Wordpress 4.0.1 */
        hash.sha1(0, filesize) == "1e77eaa3433ae54ee956f363a994a00525b1184f" or // wp-includes/post.php
        hash.sha1(0, filesize) == "10136f1ab8a728e2afbd04f7c80310db1a27239d" or // wp-includes/media.php
        hash.sha1(0, filesize) == "965294df03cc370d027c8ab2a1486a2187f5d8a3" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "09cd0dd0e291121d6d2c7dc319dfdfda7d44a618" or // wp-includes/formatting.php

        /* Wordpress 4.0.2 */
        hash.sha1(0, filesize) == "02a97efa5903ce2e5e0529ba8b8d87f344c289ee" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "0a7c985787c6f70d69a3ca6f6a0879a45cc3a853" or // wp-includes/class-wp-editor.php

        /* Wordpress 4.0.4 */
        hash.sha1(0, filesize) == "c559fe6c1012b8ca3924e9ad6cbf91cd40c1f47c" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.0.5 */
        hash.sha1(0, filesize) == "4b840f4cc3e723e821f8b9a95cd271c529f310af" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.0.6 */
        hash.sha1(0, filesize) == "65baab493816da86c38caac0f04f5c58e207513d" or // wp-includes/formatting.php

        /* Wordpress 4.0.7 */
        hash.sha1(0, filesize) == "9efaa8054acbf7558bb9458a5ab0e3f37c7a45bc" or // wp-includes/post.php
        hash.sha1(0, filesize) == "9f51202e0861eb5f47f6f158f65fec001ebafe2c" or // wp-includes/formatting.php

        /* Wordpress 4.0.8 */
        hash.sha1(0, filesize) == "6191ae4a4b1a6668f51aeba1f70e66ea1d379e26" or // wp-includes/media.php

        /* Wordpress 4.0.12 */
        hash.sha1(0, filesize) == "05aa0203e606fb851d263a7c3e5f55f5a0c95987" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "a59284e4a4dd8b95a31c7b2ae88db5b6f0bb46ee" or // wp-includes/formatting.php

        /* Wordpress 4.0.13 */
        hash.sha1(0, filesize) == "d4132a2626922fe059e64165b7151b71f13d4584" or // wp-admin/includes/media.php

        /* Wordpress 4.0.14 */
        hash.sha1(0, filesize) == "7f4c950f496d7411ca2685757f7ab843e940143b" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "cb11c7c8e84314a2500056d336eb58b7cf49a498" or // wp-includes/functions.php

        /* Wordpress 4.0.15 */
        hash.sha1(0, filesize) == "50b3e8e4e5238f6ef35f0c9441d62426238ffc0b" or // wp-includes/query.php
        hash.sha1(0, filesize) == "5dddd212c03cdd421e5a5f26cf83d0736ee4e8a5" or // wp-admin/press-this.php

        /* Wordpress 4.0.16 */
        hash.sha1(0, filesize) == "17d61ac47259e04c0a51de80c75bada5421e0af7" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "ef87ad9057d69c14d1bc57b32df2fdc51b419996" or // wp-includes/media.php

        /* Wordpress 4.0.17 */
        hash.sha1(0, filesize) == "87386ef00398bc95dcf0ea565784829b92e32c73" or // wp-admin/includes/media.php

        /* Wordpress 4.0.18 */
        hash.sha1(0, filesize) == "eca79312a2989d0a1292fb7e265568c41ea74be0" or // wp-admin/includes/file.php

        /* Wordpress 4.0.19 */
        hash.sha1(0, filesize) == "1d7f8e66bc7b7ba0f95ccf71827f0a075f2ec749" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "ce46dbe00ec0acd2e160c0070e171fc23d47e5eb" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "53cbff6d382ce43f29938e72cba0110b9b982596" or // wp-admin/includes/file.php

        /* Wordpress 4.0.20 */
        hash.sha1(0, filesize) == "ba71063229da2c60ff12b8421ee0a95412b4784a" or // wp-includes/post.php

        /* Wordpress 4.0.21 */
        hash.sha1(0, filesize) == "5047d373b97e062634d783b498345a25fea4cf00" or // wp-includes/functions.php

        /* Wordpress 4.1 */
        hash.sha1(0, filesize) == "02cee043d87d284344c66762deecea657356e781" or // wp-includes/post.php
        hash.sha1(0, filesize) == "1d3fceaeb67737f3f992da755353eedfba12e4b9" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "8f3c3c29001162345137ddea56a93498b6cad46a" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "00ae2858df9a4a13c353b3bcfadf63f3086f21d0" or // wp-admin/custom-header.php
        hash.sha1(0, filesize) == "c5bae0f590efd22edec293c66fac52b276893a04" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "354076ec60e30aeb0cae833f7ec583795fa114b0" or // wp-includes/media.php
        hash.sha1(0, filesize) == "fcb78dcbf115880ae060ef0c21d3dcb4f1cb74f6" or // wp-includes/meta.php
        hash.sha1(0, filesize) == "3e75c0e0099fe3f7ae71d837b304a11f7e572859" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "ae7515e3609d2779ab8e8fc7db7514170d56bb7f" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "899d816f539bd30aa42dc2bc0bfacee66b049e6b" or // wp-includes/date.php
        hash.sha1(0, filesize) == "b855e2330dd28c8923a88b6329752690bba5d16e" or // wp-includes/query.php
        hash.sha1(0, filesize) == "4076aef534a5cc026932aaa6d46790482935ff03" or // wp-admin/press-this.php
        hash.sha1(0, filesize) == "eb819418e10a78871f4ae134644b031b1421e112" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "e243d6e0a0d3b1a354a14f9c8180ae654c73219f" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "dbcdf3fb3abd85ff8691204e868a0d326327d3ee" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "170fcfea64689020dfb31af46193b02108858a97" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "d8ba2ffb89d8e6fd1a9a8dabe1cc9558c37f58e6" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "5183fdbeac6f4d0c83c17f60a72308b3dc3a5d43" or // wp-includes/deprecated.php

        /* Wordpress 4.1.1 */
        hash.sha1(0, filesize) == "e934a4b0f9cb2ba47cfa428cb10343d7d48d8431" or // wp-includes/date.php
        hash.sha1(0, filesize) == "458d3517e602b97008185d0cc49f0ffaaa0bf28c" or // wp-includes/taxonomy.php

        /* Wordpress 4.1.2 */
        hash.sha1(0, filesize) == "fa376bf871e4e90a78995a24d5b8dfd6329c2034" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "625e89b44b46c3a9a5793e2bc1fb978140f66095" or // wp-includes/class-wp-editor.php

        /* Wordpress 4.1.4 */
        hash.sha1(0, filesize) == "f1c6460e538e677661c279ef0ce65b0bc18eb913" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.1.5 */
        hash.sha1(0, filesize) == "8b32b2a0dec44bbd0d5d97e4f1b26efd20d61f9b" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.1.6 */
        hash.sha1(0, filesize) == "aa31ad3b27e8b7b037b2aaff685ef3fd48f5c600" or // wp-includes/formatting.php

        /* Wordpress 4.1.7 */
        hash.sha1(0, filesize) == "092dc4b0af1285499f15d13c8765bfe94a12c287" or // wp-includes/post.php
        hash.sha1(0, filesize) == "cc2fa51146cc136cfb0a2dcd84084f7a7297f977" or // wp-includes/formatting.php

        /* Wordpress 4.1.8 */
        hash.sha1(0, filesize) == "f6abf8f0104252dee182b1c8ba5a22eaeec98620" or // wp-includes/media.php

        /* Wordpress 4.1.11 */
        hash.sha1(0, filesize) == "d1067c4ca6343710c2c01426c5dd601a27108230" or // wp-includes/taxonomy.php

        /* Wordpress 4.1.12 */
        hash.sha1(0, filesize) == "f882a04b5dd0b8ade98ac751dc400c72de08fb4a" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "a34ef14ee5c1b3d94dadf7cd98c774565c77b523" or // wp-includes/formatting.php

        /* Wordpress 4.1.13 */
        hash.sha1(0, filesize) == "f74a1c5e34ac02cde591fc7de997247f4ee2ad06" or // wp-admin/includes/media.php

        /* Wordpress 4.1.14 */
        hash.sha1(0, filesize) == "53bce74420948c2b1448de107fbd960b2ea7e925" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "d089ae5d3be70327a03fe19ca65bd08eef522f23" or // wp-includes/functions.php

        /* Wordpress 4.1.15 */
        hash.sha1(0, filesize) == "0c436ad9b21445656967b841e2377fb91d5eaef9" or // wp-includes/query.php
        hash.sha1(0, filesize) == "15872b26705de36cfa3bca17311d46bed8a26cb3" or // wp-admin/press-this.php

        /* Wordpress 4.1.16 */
        hash.sha1(0, filesize) == "cb79f6dc730fb8556b930f214f91552e1e88b487" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "71a4e6b43192944d30eb317aa534e6ac66b0c4d6" or // wp-includes/media.php

        /* Wordpress 4.1.17 */
        hash.sha1(0, filesize) == "b9f3626b12baac5497ca8c085ae378ba2e88a2bf" or // wp-admin/includes/media.php

        /* Wordpress 4.1.18 */
        hash.sha1(0, filesize) == "9eadd29eb5e4ac074fb0aa2d79ba75a6f8abec32" or // wp-admin/includes/file.php

        /* Wordpress 4.1.19 */
        hash.sha1(0, filesize) == "dde667c7b2d2dfb486b717029fa2e5b231e98343" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "6356e9f524f519c44487be463568b25afbe0994f" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "143e73ae0357a0753b0100cd3faf1337b2bbeeeb" or // wp-admin/includes/file.php

        /* Wordpress 4.1.20 */
        hash.sha1(0, filesize) == "a32f064225cf2204e5cba0809710fd5beeb6bc99" or // wp-includes/post.php

        /* Wordpress 4.1.21 */
        hash.sha1(0, filesize) == "9c240b8e97bdfcadd9161e28925ecf5490c6211c" or // wp-includes/functions.php

        /* Wordpress 4.2 */
        hash.sha1(0, filesize) == "76e12317ec1285adcdc492efe71f898ccd76cc4f" or // wp-includes/post.php
        hash.sha1(0, filesize) == "8c897ac93db0620c7a4a5bba2bbc3a6d5ee1a741" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "98042c16520129851ab0ad515f7f0d7c8a04bc97" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "7b0e29a942a5d6e9541c4eff5ba4e3fc5ad2f180" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "4eb961932a223428dbb0354cba7a109d4f082069" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "8a060c75a4e994b89ddd8dd0b11393f34f7c49b5" or // wp-includes/date.php
        hash.sha1(0, filesize) == "ebe698479d1434e7afb3da1370519742e64e178f" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "9ddcac4aa1d7b51a518e83d399a66675a2758752" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "19cdb09b16b10165a92d21382eb6703f89ef20ab" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "c6de0a53dbf301eb529826b824f6537f08e51dd8" or // wp-admin/credits.php
        hash.sha1(0, filesize) == "dfc724c94a5d2b96442d7a7c311de38e30b10952" or // wp-includes/default-widgets.php
        hash.sha1(0, filesize) == "a7735baf35c981deb7ea85336cbb56f437fe2dad" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "4f2bad51df6f336ea3d0a3d3591bd2b4d6cedd71" or // wp-includes/class-wp-editor.php
        hash.sha1(0, filesize) == "1c91876e8ef415bc46eb7784df192d1c4394d591" or // wp-includes/meta.php

        /* Wordpress 4.2.1 */
        hash.sha1(0, filesize) == "a06f2699c21268a9b2b1e5c1f2880ac037f206f1" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.2.2 */
        hash.sha1(0, filesize) == "51803cf19e419ce2c3702939acbefedf0d5607db" or // wp-includes/post.php
        hash.sha1(0, filesize) == "a88ec5f8fea806472d87b8b4fda68cd6a84e31f4" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "7e3f36fbb6b69f921b27ebec9bc7ff02dc016158" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "e7689e0b3b3dec898fe1a647a9dc3b34f96761e1" or // wp-includes/formatting.php

        /* Wordpress 4.2.5 */
        hash.sha1(0, filesize) == "57861a47a63f7ffdbfb257cd52925f0019c3e516" or // wp-includes/media.php
        hash.sha1(0, filesize) == "c5a495823473f47ae0ba451665270ee7e717de52" or // wp-admin/includes/ajax-actions.php

        /* Wordpress 4.2.8 */
        hash.sha1(0, filesize) == "f85f407e66a6dd8b1a3ec2a2a3b1a8e791f422ec" or // wp-includes/taxonomy.php

        /* Wordpress 4.2.9 */
        hash.sha1(0, filesize) == "1df1bfa4b6984284479901424a469df48e63e322" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "8e9e78a23eb3865e5578a16dcde048227ed51a91" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "00d52b0e666bf35211ebbad67a264f02e66984ad" or // wp-includes/formatting.php

        /* Wordpress 4.2.10 */
        hash.sha1(0, filesize) == "ae3064d1f5c1a4161c3d6f02d045c544e845fef0" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3d75e6312f084dc7b9967e9ebd2456d79e0eea0d" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.2.11 */
        hash.sha1(0, filesize) == "8110425395226f04718882986374edcf058e8071" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "1082a6b2b4f09f19191eafb79f715a2356a17c96" or // wp-includes/functions.php

        /* Wordpress 4.2.12 */
        hash.sha1(0, filesize) == "2cf8d3dc23df2912e44f80d8fe0c28e2be990a97" or // wp-includes/query.php

        /* Wordpress 4.2.13 */
        hash.sha1(0, filesize) == "925e66ad92240ab58627a499b669b4a24c4e6e3b" or // wp-includes/media.php
        hash.sha1(0, filesize) == "80fbeb35c51a6a9b5ab110d9712179b4e89f8bb2" or // wp-admin/includes/media.php

        /* Wordpress 4.2.14 */
        hash.sha1(0, filesize) == "362f722769715178d58b40e9115c930c841c2f9a" or // wp-admin/includes/media.php

        /* Wordpress 4.2.15 */
        hash.sha1(0, filesize) == "524eefb11aec7a44e797146019b15f651af6abfd" or // wp-admin/includes/file.php

        /* Wordpress 4.2.16 */
        hash.sha1(0, filesize) == "59045c43cb0c3efdc9c4e8f8baa8d8012368a299" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "a50148f6e2bfab5141ec38a99a963fe779ecae85" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "1dbeae546c632435e05021b5952856ebb148ad85" or // wp-admin/includes/file.php

        /* Wordpress 4.2.17 */
        hash.sha1(0, filesize) == "3d38f79fc4d9647b5e246293e1ae9e6d30ad3866" or // wp-includes/post.php

        /* Wordpress 4.2.18 */
        hash.sha1(0, filesize) == "9cddb65051a3957b9d9df08e0d4dbcc8904401f1" or // wp-includes/functions.php

        /* Wordpress 4.3 */
        hash.sha1(0, filesize) == "9ac361b7a5f7b4bedfa401105430ad4bbc42d703" or // wp-includes/post.php
        hash.sha1(0, filesize) == "be3ce06026587ce523757aa1b250641a7b372dc3" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "7d3d75d75f52d5c65f1e662f4df08ccb98ecdc89" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "1621e2b54e4e6662fd91f62ebe4b1faa7919db2b" or // wp-includes/media.php
        hash.sha1(0, filesize) == "41ce7e5dcc5e900cdbad71e32e178f3e4e343331" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "4a1897a9f8a35b872af6710a715d8a951735e25d" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "0ff072081cac324fcec8f1673c48d0050cf889fb" or // wp-includes/meta.php
        hash.sha1(0, filesize) == "eca907eb041cbd279f81668a8ccd94199b9f885b" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "7e35b47d3fb712e063811249ed40b4bccd679ef5" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "6cf363c76248948ba36d62d247f9d0341efc7fb7" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "c4dc6b1193ebe75ab6a3dbbb685edbbacc35e072" or // wp-includes/query.php
        hash.sha1(0, filesize) == "3be43a3712d0729b506b38b5517e8e26840231ca" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "eb5a5794ca54733861b717d99c44668fdf6f542a" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "93a22e63c422a6e8dc83299f4774559422479cc1" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "0e7b4e9dcf6b9fc737a524271f0a7297691e41bd" or // wp-includes/default-widgets.php
        hash.sha1(0, filesize) == "9701a951e8e21545a2be97302d1d234e0772f29d" or // wp-includes/deprecated.php

        /* Wordpress 4.3.1 */
        hash.sha1(0, filesize) == "b3110df406c6c4a2694c97e38122e39c7ec6577a" or // wp-includes/media.php
        hash.sha1(0, filesize) == "f97d139bdc73107b361a9e3ac728a6d9742bbcb3" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "4e49ee459af033622b44846cf7e93b3d24e5c719" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "22df02ddfc4d28064ac4008fb9f416941465ecb5" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "f29a9710ba563d5b197acf6eb815e5eb5a96981d" or // wp-includes/default-widgets.php

        /* Wordpress 4.3.4 */
        hash.sha1(0, filesize) == "145f0dfb8c9ea70c32a446d3b4cc3814d9efc865" or // wp-includes/taxonomy.php

        /* Wordpress 4.3.5 */
        hash.sha1(0, filesize) == "e140bb6105dbc39d2a84c7734b5748ba98f97d0f" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "2b6c539cf7c96e86751e7845cfb749ba5b0ad268" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "a945290f46ae8f0386e8cb8e1d052a179b7607a2" or // wp-includes/formatting.php

        /* Wordpress 4.3.6 */
        hash.sha1(0, filesize) == "1e3fe00ea43a55e0499d6485037aca6868490bd6" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "c40c86e2906587d7a94ca48505f7a01b78e73d75" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.3.7 */
        hash.sha1(0, filesize) == "275331ea9d076c0d9c89616373a3e07a12ee8206" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "a5985105432f4669f865ed3f56209f5d28106801" or // wp-includes/functions.php

        /* Wordpress 4.3.8 */
        hash.sha1(0, filesize) == "e6315cf0672b295d772c25e08ed55d557f4722fa" or // wp-includes/query.php

        /* Wordpress 4.3.9 */
        hash.sha1(0, filesize) == "826cd281357fb27bcf3e1217c1f9b36e62315b6c" or // wp-includes/media.php
        hash.sha1(0, filesize) == "30877e873e61e6d4ecb9aa608e6b05d1607c3e09" or // wp-admin/includes/media.php

        /* Wordpress 4.3.10 */
        hash.sha1(0, filesize) == "663c4f356e45a72715fcdb5f863a03f007855314" or // wp-admin/includes/media.php

        /* Wordpress 4.3.11 */
        hash.sha1(0, filesize) == "7bcba0af268e5fab44ebcb1e0ec5883e9804df79" or // wp-admin/includes/file.php

        /* Wordpress 4.3.12 */
        hash.sha1(0, filesize) == "d9978f6e12240814982c90f6972ecdf58f9fb59d" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "ab037fb84ec5bdee286a97a1aed72ab69e710427" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "34ec6168c4aa8e9369d5c5bc49f09dfd83d20879" or // wp-admin/includes/file.php

        /* Wordpress 4.3.13 */
        hash.sha1(0, filesize) == "2c351d173b7ac77f56f0626d1da6430809037c09" or // wp-includes/post.php

        /* Wordpress 4.3.14 */
        hash.sha1(0, filesize) == "7e68cbc4594bec9a37268be0a3153bc327964650" or // wp-includes/functions.php

        /* Wordpress 4.4 */
        hash.sha1(0, filesize) == "b7e5febb44afe5438ab5cf733bd0a02fc4f4b2a8" or // wp-includes/widgets/class-wp-widget-categories.php
        hash.sha1(0, filesize) == "7f9be8f15d5f0212376ecc0633fba1b7986e09c1" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "f0fa0a65ec23e011672c0c25a1130365bfc4dc35" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "d1c839dfbaaf2ddc4e4ae57d8bdb4316cd25c1a2" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "6eff1fd4e45d11c2785fd0be8cceb8e07269a072" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "9a6f07102ccc8c0c842f7e08441aa1f2d0500214" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "9180550308e961482e28a372f5c7eba70210295b" or // wp-includes/date.php
        hash.sha1(0, filesize) == "d679ead3f70be8642ee36c5d249fba8d7539eadf" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "d2a35d9a571975f972e28a5b5cc77e1370ada007" or // wp-admin/includes/class-wp-ms-themes-list-table.php
        hash.sha1(0, filesize) == "2fdf93ae88735d062a8635ac1d22a6904cb89ab8" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "086986cdf03ede58494034661d38c4842af38fe3" or // wp-includes/SimplePie/Parse/Date.php
        hash.sha1(0, filesize) == "9d6b7298c4724385732d3512526eb8e7a0f59d79" or // wp-includes/deprecated.php

        /* Wordpress 4.4.1 */
        hash.sha1(0, filesize) == "17659465ca029164a3cfa15517a5e0358cb59a6b" or // wp-includes/random_compat/random.php

        /* Wordpress 4.4.2 */
        hash.sha1(0, filesize) == "45ed235ed268d289665f8d0866cbbdbc46e1b25c" or // wp-includes/random_compat/random.php

        /* Wordpress 4.4.4 */
        hash.sha1(0, filesize) == "bb0ab626d7d5ed3fef7ea910d73f02b3159d8b31" or // wp-includes/post-template.php

        /* Wordpress 4.4.5 */
        hash.sha1(0, filesize) == "9076a0939127bd082bb9fd20099c243ee64d6c7e" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "65d8091dabdce10fddf855aa86994e7f6c206678" or // wp-admin/includes/upgrade.php

        /* Wordpress 4.4.6 */
        hash.sha1(0, filesize) == "bb5871932b7db7af34deefc2fa3e1c2c39ebfaac" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "0a6321cc5a95ba50ac065be6f863e410d4c753e6" or // wp-includes/functions.php

        /* Wordpress 4.4.7 */
        hash.sha1(0, filesize) == "324da3de8c2e95d4f1c833de7bb969cce65017a1" or // wp-includes/query.php

        /* Wordpress 4.4.8 */
        hash.sha1(0, filesize) == "f23c04db16a26cfdd7698354b5b5e4e5ba8d2c3c" or // wp-admin/includes/media.php

        /* Wordpress 4.4.9 */
        hash.sha1(0, filesize) == "b81c17d5bfb2223f69db377436590e475668d2fb" or // wp-admin/includes/media.php

        /* Wordpress 4.4.10 */
        hash.sha1(0, filesize) == "6dcfcae19ae1dfcef701a7c503819da7f5a5e462" or // wp-admin/includes/file.php

        /* Wordpress 4.4.11 */
        hash.sha1(0, filesize) == "d150111d53bb9b5c3b206dd20bbab4aa6392c535" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "0568c09891c5373289adf8edddbe9315f3191e43" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "e96fad2bedc2f6b16db3ca35c6fda177c7fead4a" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "4a65846751a2fd28d1580eec7c8f44a8e13765ee" or // wp-includes/embed.php

        /* Wordpress 4.4.12 */
        hash.sha1(0, filesize) == "8febc587284d4883ff685ba8e82cd4aa834dc054" or // wp-includes/post.php

        /* Wordpress 4.4.13 */
        hash.sha1(0, filesize) == "b9a2912fb6fbb5c0955a652988f0f0d16bde9b7d" or // wp-includes/functions.php

        /* Wordpress 4.5 */
        hash.sha1(0, filesize) == "acfaa92b755ecda6ee1d1e7ee5bb5c3376b8a6be" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "fba38139c928803094190dc600b81e99aa5589fc" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "87f8099b00084af257135f4bee2b0d70d9e367a6" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "e049dd771d6b3abf7c4e65413e32de744b42ccef" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "1ad46b79725d495bb5aa40325325caa206c14fc8" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "73740e2cfb355a7eb7b1044c7d44135b40b01fa6" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "7978619626d7ba0022430be3fd697664203d5154" or // wp-includes/date.php

        /* Wordpress 4.5.1 */
        hash.sha1(0, filesize) == "0b952ece357cf396d9df043f852d9c5c4e0b8a3e" or // wp-includes/post-template.php

        /* Wordpress 4.5.3 */
        hash.sha1(0, filesize) == "9ee0b7f989f1776c6cee94beca98bb4a68760a16" or // wp-includes/post-template.php

        /* Wordpress 4.5.4 */
        hash.sha1(0, filesize) == "682c5bdb4f42bc1b45311cb061e86a7f73d1b851" or // wp-admin/includes/media.php

        /* Wordpress 4.5.5 */
        hash.sha1(0, filesize) == "eab6afde1cb93b4a88970848df53394c9bed0106" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3b83dfdfdd3740b7153fa89f563da0585fcdd39d" or // wp-includes/functions.php

        /* Wordpress 4.5.6 */
        hash.sha1(0, filesize) == "b37095354be3483d3bde870aa1312993c197d433" or // wp-includes/query.php

        /* Wordpress 4.5.7 */
        hash.sha1(0, filesize) == "fc11c12de9b20b22adbd0c3dd757717bc24b6f1c" or // wp-admin/includes/media.php

        /* Wordpress 4.5.8 */
        hash.sha1(0, filesize) == "216425da339d17a4a3460a8e4e20c05f2dd9dcbb" or // wp-admin/includes/media.php

        /* Wordpress 4.5.9 */
        hash.sha1(0, filesize) == "ad7ebe534455b42c7c437878546ec7dbebf93ae6" or // wp-admin/includes/file.php

        /* Wordpress 4.5.10 */
        hash.sha1(0, filesize) == "939dda60ddad0b8d7aa74bf91b328cd501c1c132" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "b4be10610ff0649c48b9dba091656a7e479defe2" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "b50677d1200c0b7af34b94d7df071cd45435c5ee" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "7ff8a0bc84a84b31101630fc723f8b7c5df2b207" or // wp-includes/embed.php

        /* Wordpress 4.5.11 */
        hash.sha1(0, filesize) == "a244b842832525f376e9b0d0f4df4e56ed4302cd" or // wp-includes/post.php

        /* Wordpress 4.5.12 */
        hash.sha1(0, filesize) == "21bd227ab97fec4144bd7aad7bc400e3f51ab03d" or // wp-includes/functions.php

        /* Wordpress 4.6 */
        hash.sha1(0, filesize) == "a422a0e8243e8311d30bc01c2d7b9c283e61bff2" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "348c3a60d99768041be690b65b008628f53badb7" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "0c06bd6cf0a6658732efe87ff5640cd11c65f7f1" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "c06a15f4869c5459a782b714572eacea5c82d570" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "b10d12a372e6cffdc7d216f8a5136e3c093159a4" or // wp-includes/class-requests.php
        hash.sha1(0, filesize) == "0451d399ccfbf7dc1de0edb9f745da2b34b18fc5" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "d032ad82ff52219f3615da437c1b76b8f280aa12" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "b92aefa2917fc319ca7ceab092e183cafc651a6d" or // wp-includes/bookmark-template.php
        hash.sha1(0, filesize) == "4f89ccb066e38c1737c12b0617b2fb12da1ba049" or // wp-includes/date.php

        /* Wordpress 4.6.1 */
        hash.sha1(0, filesize) == "b1f9eb94fb54febccee7334620905adb4400aa9d" or // wp-admin/includes/media.php

        /* Wordpress 4.6.2 */
        hash.sha1(0, filesize) == "07d18fc3d5e5b0fd61ccf5bd2da8ac2e15b097e4" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "a53db6d4db11a0abb7e1fabfa6d25f5a993ebd53" or // wp-includes/class-requests.php
        hash.sha1(0, filesize) == "100410700eb586886eb21325f81e1b2294e56ac6" or // wp-includes/functions.php

        /* Wordpress 4.6.3 */
        hash.sha1(0, filesize) == "dc98c549dcb2cef2f59dd220d314db3ad0a17ba0" or // wp-includes/query.php

        /* Wordpress 4.6.4 */
        hash.sha1(0, filesize) == "6449e83f570f22b5379269f4ea131d32c402bed9" or // wp-admin/includes/media.php

        /* Wordpress 4.6.5 */
        hash.sha1(0, filesize) == "28be75a851213f0898383747a7d67b8ef2036c2f" or // wp-admin/includes/media.php

        /* Wordpress 4.6.6 */
        hash.sha1(0, filesize) == "1f50ee8f46458e2ea17326223d84ec51610dfe36" or // wp-admin/includes/file.php

        /* Wordpress 4.6.7 */
        hash.sha1(0, filesize) == "5db799480d4fd6ad9cdf32fdabb2ffcef9b283bc" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "ed7fd5cbc7cd9dd98fbaeb984278a96825174472" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "ba377822d0f3a65b6b7684b1ec337335155df119" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "7080f68308c148e7cded897ce169d4ebfee04bec" or // wp-includes/embed.php

        /* Wordpress 4.6.8 */
        hash.sha1(0, filesize) == "beaa64b3bdfa508a8b2ecadecbcbbeeed775c990" or // wp-includes/post.php

        /* Wordpress 4.6.9 */
        hash.sha1(0, filesize) == "1b924521222d5bdc75aac9c323901584c3c05d04" or // wp-includes/functions.php

        /* Wordpress 4.7 */
        hash.sha1(0, filesize) == "d39e8749e6e15b6fa86270381420cf4f4cc02ed4" or // wp-includes/post.php
        hash.sha1(0, filesize) == "12a18329072bed94b6f9c4d9f16d7a079ca64655" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "64e5d98fbeb07994f0d712ada765190656d4c0cb" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "9835d10a7561deeef1f8381da065b4b45d7f2662" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "aa6a12a0325056b9649f58f8072fa02a1e264551" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "aee1d3ce95ffb5f1c7da03740c5328f35360b24a" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "82d279098626105b1019d68da8290a6c385781e7" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "2ef50e790fdd42daa8ccd64d4c7c4be75d21742d" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "455273700bc455f1ff36822affc94108dc3d9df7" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "1479b874ad86ce3b865ba34048a20b86d8aa0087" or // wp-includes/load.php
        hash.sha1(0, filesize) == "040ef40d245242723de200e494a27545ea0b121b" or // wp-includes/IXR/class-IXR-date.php
        hash.sha1(0, filesize) == "e11f0c01452b686bd7e144ce165dfc5c3a616461" or // wp-includes/media.php
        hash.sha1(0, filesize) == "e777699f876953380f9a1ce013a1ba55f838ab0b" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "da748d8ac26bd4148bb8972b93efbb5f808474aa" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "b77ca8384b23346d003c07d23f05b8161ab6c688" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "c8c9182aa25fb92ca91fcc96c3419847acdcf6e0" or // wp-includes/date.php
        hash.sha1(0, filesize) == "c2530a7cdb250bf4825a5c112cd26aa3ef7db1b8" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "81b1ae432ba765a43c6d81fb6d6c35ce72efd0e8" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "6bccf04c8b46c8d6cdf79db8b509f4b76689f3bf" or // wp-admin/includes/class-ftp.php
        hash.sha1(0, filesize) == "5877695771fbe7a5667f4a06f4d897a37ef3fceb" or // wp-includes/deprecated.php
        hash.sha1(0, filesize) == "e4f0694bc96f99d5e30201171a3e7fc86e9e5ae4" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "3d365a162b340d34d5294b60ae547d99b6d1a999" or // wp-admin/includes/file.php

        /* Wordpress 4.7.1 */
        hash.sha1(0, filesize) == "5ddc1e5c5c6302211b1aecbf930f76417b65d678" or // wp-includes/post.php
        hash.sha1(0, filesize) == "0aab95245b9668f954151f4312b678fb0ee798cf" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "abcf1a0801694db4774cd2abb29b5392e10dd632" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "cb0c5a355409d807202bbf52749a3e74a9967a6a" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "f53f80c4ee7446f0b605443b6d2f05acd8064d13" or // wp-includes/load.php
        hash.sha1(0, filesize) == "b6de3af806166117e7bba3eccbb0428a1616b52d" or // wp-includes/media.php
        hash.sha1(0, filesize) == "8e46ab4eae3aac3295b24f4aaf4e57931817e49d" or // wp-includes/functions.php

        /* Wordpress 4.7.2 */
        hash.sha1(0, filesize) == "72dbc1d4f2bbc8efdcdd834ecaf3771cbf17f64e" or // wp-includes/class-wp-query.php

        /* Wordpress 4.7.3 */
        hash.sha1(0, filesize) == "806d2872676ea22e0a6fa6b32fbd4652298023ee" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "bea5ea598f537e7acb20b77a1421f819c0a9ec75" or // wp-includes/media.php
        hash.sha1(0, filesize) == "3e73204644f0ce7b0971aad885fdcbcabba629fc" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "3083b9a58e76d42455935811a457f29f57620145" or // wp-includes/functions.php

        /* Wordpress 4.7.4 */
        hash.sha1(0, filesize) == "b29188f218f4c5a829885acda14b0311a3c49976" or // wp-includes/media.php
        hash.sha1(0, filesize) == "314b1dc97aa00586a3252d3628cf229e65091340" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "ec167428ad6275ff373976847c37fca99b9a485d" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "f0944ef1c459ddb52365c3825b09063b323eed92" or // wp-includes/functions.php

        /* Wordpress 4.7.5 */
        hash.sha1(0, filesize) == "165ad1321538d1b599923f0757f7d7e21671e155" or // wp-admin/includes/file.php

        /* Wordpress 4.7.6 */
        hash.sha1(0, filesize) == "b152b4bf6a81a3ba3564ae276a34bc6b4877735b" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "e527a7eae5b3465b00087fa7c333e9606ae5783a" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "e59258f4773caf6fda6c99e125436ad4a18ce486" or // wp-includes/embed.php
        hash.sha1(0, filesize) == "235a7ad0f3f8478e652def99d8e1f4307dc51da2" or // wp-admin/includes/file.php

        /* Wordpress 4.7.7 */
        hash.sha1(0, filesize) == "eb855acc1c8666a70f3d7dfe4a95c00149b5ce7d" or // wp-includes/post.php

        /* Wordpress 4.7.8 */
        hash.sha1(0, filesize) == "ac0958364783141c5a1cbba8e12ed4ff78ee8bbd" or // wp-includes/functions.php

        /* Wordpress 4.8 */
        hash.sha1(0, filesize) == "77313344a17eade5030fdca8d10eccd135969369" or // wp-includes/post.php
        hash.sha1(0, filesize) == "173fbee8c74055b574ed0aa3c46e259197c67863" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "125c1f096353629f73beea143e2deca0df1fb7d4" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "1e2c69cb9905adf368b355ca9364b5e837dd9081" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "5334c1a43da016ec1c29a51004e026080691b1bb" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "b9fa254d7c067cef7bad75e0b29fbefa7e413b57" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "0e7fa010303cd090cbe016b77e277927d1d6c810" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "cd711fb5b3bae492508beb9074a03046f7b1e308" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "ee46ecb6fde0592f9b7659e3d3484343d324b5b1" or // wp-includes/load.php
        hash.sha1(0, filesize) == "36602ee5cdab5a4d3823eb6059309905198f4f36" or // wp-includes/media.php
        hash.sha1(0, filesize) == "ded6a7a07bced8e6499e88fb7b9d6db280851772" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "d72fdb3558631f5b120d04a2cad627751ae7d0f6" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "c241afff5aee586d3158386d7d8afb0eda43ffbc" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "4ebfcc988918b5a97671d505181036ae2d1c32ab" or // wp-includes/date.php
        hash.sha1(0, filesize) == "dcdecd2367dc9a0cc60e678064803e6d93abcc6f" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "f87e60432a7bd51476335bcb0f734f47b3ae1dc7" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "d330b08f706d98368b5a1acdcf2c8cdc72a0da4f" or // wp-includes/deprecated.php
        hash.sha1(0, filesize) == "2d68a100b60b49de00319e4787bf464007629fa4" or // wp-admin/includes/file.php

        /* Wordpress 4.8.1 */
        hash.sha1(0, filesize) == "1ec72b6f528082afbbadbf276a2dc438d1d594d5" or // wp-includes/media.php

        /* Wordpress 4.8.2 */
        hash.sha1(0, filesize) == "dfb85f5bdca223d49ecf73e6c9ca200abf937f51" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "dedbeabb84a350640f07a06ec4c50cff9ffa0d38" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "8aaa1c4bf15cd3abd78b91832fbbb4f0c6f31105" or // wp-admin/includes/file.php

        /* Wordpress 4.8.3 */
        hash.sha1(0, filesize) == "ae6db64375d5093431624468c91cfeaf3c71e1de" or // wp-includes/post.php
        hash.sha1(0, filesize) == "cf9b905e6559cb063e8472a8ae6de3a1ac4fa5bb" or // wp-includes/formatting.php

        /* Wordpress 4.8.4 */
        hash.sha1(0, filesize) == "bc5c48ca6e599f5891caf8a73608cdae9e01f478" or // wp-includes/functions.php

        /* Wordpress 4.9 */
        hash.sha1(0, filesize) == "752dbdfd22d3f940d8973d26923ca4a464f7e232" or // wp-includes/post.php
        hash.sha1(0, filesize) == "d1d684a2acbbd7f6660702e45d34ad96bdeef730" or // wp-includes/class-wp-tax-query.php
        hash.sha1(0, filesize) == "352be1f3bf3401a75eacdec37f1b5d48910043e8" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "9e19ca132977845fb0ba0950a507c16579093209" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "18620d3e3b0b1f5b211ebc45ac5842eca7ee52ca" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "b9e78dc47e999b2b043e905c8a569e82a3bf7c0b" or // wp-admin/includes/class-wp-plugins-list-table.php
        hash.sha1(0, filesize) == "0b8cc5ee744280b8ed7f7e3b303e64b37a425cc4" or // wp-includes/ID3/module.tag.id3v2.php
        hash.sha1(0, filesize) == "f6033d27f76e4c5c974baa9936ab81d962558669" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "d0db3bdbb33277faa392f0d242125af1f761afc4" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "dee6af2c81118c5021e1ee40e2d4b5c54934b167" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "7a4a73acfa113b77119c1daa6d67dfb83b2f463a" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "554b828b64160c6e56a5bebb1726efc72582005f" or // wp-includes/load.php
        hash.sha1(0, filesize) == "2d26a3a13fe4bcacee99b03ff96e06940a496744" or // wp-includes/ID3/getid3.lib.php
        hash.sha1(0, filesize) == "54a8fa6a2f55c29b9904b15ee276faeb200941c2" or // wp-includes/media.php
        hash.sha1(0, filesize) == "bede201836018278fa19d1f42bd564090c7a8b82" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "4108ea39a8332614c72e49b3ddf7a22c91e579ed" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "c172576a5a72e64e5af86820e11c02cfd334c654" or // wp-includes/class-wp-meta-query.php
        hash.sha1(0, filesize) == "8da575eed6ff6828cb2aad8953ae51c52a272c36" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "126d1d46140d5d92d115af6e5d04c622f5d0d982" or // wp-includes/date.php
        hash.sha1(0, filesize) == "f7d34d486258a152d508b4872a0775fe7b54d23b" or // wp-includes/ID3/getid3.php
        hash.sha1(0, filesize) == "f9a6d17f8369d9a8ed6929ae5375f860d834d70d" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "dc19f236b6276ae5e82f31d78e4fcf77aae0676b" or // wp-includes/ID3/module.audio-video.quicktime.php
        hash.sha1(0, filesize) == "1a68d18ab476fd71e2bafc26221a83758f51e899" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "47c8c9b48ab200312544c744ccc4433c09e4b29f" or // wp-includes/embed.php
        hash.sha1(0, filesize) == "8506b66d830fe43c07bd8ba92b98059db9c4d609" or // wp-includes/deprecated.php
        hash.sha1(0, filesize) == "bb59faf1d6d247561348a2d6da76b3c9916fc5f6" or // wp-includes/widgets/class-wp-widget-categories.php
        hash.sha1(0, filesize) == "60956e23f5124ff4d78a37845478bdef17323234" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "6ea29825bd6ecc006db5b9f8fea84b08094adf01" or // wp-includes/ID3/module.audio-video.matroska.php

        /* Wordpress 4.9.1 */
        hash.sha1(0, filesize) == "a9a0d360e92828392b4fd1088b8f6b3b5edbd38a" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "c34674dbded99cf27a8389266d9b7cd4cd1c1cae" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "b0530df4cb23cb9e7a0f8ff0afbc83d6762ec5c3" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "cd178c8d3a504a61bca31531983d8c3b9f720fcd" or // wp-admin/includes/file.php

        /* Wordpress 4.9.2 */
        hash.sha1(0, filesize) == "aa07d8be20c7d0274c723b9eb2f91cccb509329c" or // wp-includes/media.php
        hash.sha1(0, filesize) == "96fbd31e8c8116942100359cac8c719db1c8d79c" or // wp-admin/includes/media.php
        hash.sha1(0, filesize) == "fa8001bcc5ead72411b9de4f881d62f5fcdbad80" or // wp-includes/functions.php

        /* Wordpress 4.9.3 */
        hash.sha1(0, filesize) == "61c41a1fb7e12833749388f3973f1847151e3ca9" or // wp-includes/post.php
        hash.sha1(0, filesize) == "fda1e4f919ceb16b7884c9082a55dc9791d30864" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "4099e5ef9c7f0611be320412159e1897f7d4d0c2" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "d227ce33979c44e23f44e33c4d8966de21108098" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "7424b9306888a80c3450b7ddb206e73a7a3065c6" or // wp-includes/class-wp-query.php
        hash.sha1(0, filesize) == "b9efb83b07e47085458433840a5000fdfa4bc9aa" or // wp-includes/functions.php

        /* Wordpress 4.9.5 */
        hash.sha1(0, filesize) == "023c18ac2ff6dfd5e1e33e607e04101be41a56e1" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "d8ebdd1c5582034ea6462cfb44a2a6938317e87e" or // wp-includes/general-template.php
        hash.sha1(0, filesize) == "c3e9b219e53ed65e0a975b40167c387e67e93118" or // wp-includes/media.php
        hash.sha1(0, filesize) == "a6d9800de8df95ed52ea3eacb55596d424612429" or // wp-includes/functions.php

        /* Wordpress 4.9.6 */
        hash.sha1(0, filesize) == "edfc9e842657332c3c89ee70124bfe21f52b6846" or // wp-includes/post.php
        hash.sha1(0, filesize) == "2ecb5fc57fdc7a2bbf77abc2ffef836077b4a3be" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "4a1d1becfb1bbbf88d6ebade13534f792c5545bf" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "1ca5556cba039dda41863834d66192260d567e1d" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "8fac5dc40941a1d266064deaa7a7874a0c382c7f" or // wp-admin/includes/file.php
        hash.sha1(0, filesize) == "517b24c44416efd9869ce4fefb0091c610b15cfb" or // wp-includes/media.php
        hash.sha1(0, filesize) == "f3de6a4510385cc8db3f653c1a4adcae99f68691" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "f1b8f6b703f5a3e52cdeb44e9d4dd259e5f2d5d5" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "51e02f58216c17b6267f5e958498d493a6bcc40d"    // wp-admin/includes/schema.php

}
