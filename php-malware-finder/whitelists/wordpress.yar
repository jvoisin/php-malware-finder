import "hash"

private rule Wordpress : Blog
{
    meta:
        generated = "2016-07-27T18:00:53.795037"

    condition:
        /* Wordpress 2.0 */
        hash.sha1(0, filesize) == "7d564f9b4be82f140438a8c5b701e52d7b7315ba" or // wp-includes/template-functions-post.php
        hash.sha1(0, filesize) == "be2aaeec117527a8313212266783c3695b28e58e" or // wp-includes/classes.php
        hash.sha1(0, filesize) == "ae13490fcb5f307b0b9b033ffdcf070528db7827" or // wp-admin/import/mt.php
        hash.sha1(0, filesize) == "7fc3c48f756257f4b98f77e3dfa890fbaa8f98de" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "5b27925fa87eb21270853bc143fb37bbaf9fc8d8" or // wp-admin/import/textpattern.php
        hash.sha1(0, filesize) == "7df03ff12409d1ccfdefd3291d668d127c973190" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "7fdeb4e7ac44229aa3350b2f6b3954f4dac8de8c" or // wp-content/plugins/wp-db-backup.php
        hash.sha1(0, filesize) == "7c6033dd1fe700b03792e4b7e077db913f12b6c7" or // wp-settings.php
        hash.sha1(0, filesize) == "0ec6ca8071cd8feb90e32e258287657ce231bbf7" or // wp-includes/functions-formatting.php
        hash.sha1(0, filesize) == "9c4d657a27a0df11e4ebc68e21969b6bb4a2aa48" or // wp-includes/kses.php
        hash.sha1(0, filesize) == "f555ae3cb120b60e73c545e3845a4f0f001c3d27" or // wp-content/themes/default/functions.php
        hash.sha1(0, filesize) == "3b356fc15f96164e2447e289a778480b0b352cc3" or // wp-admin/import/rss.php

        /* Wordpress 2.0.1 */
        hash.sha1(0, filesize) == "dbac1bdeb8d43dfde1fb43db5a0605cacc3f98ac" or // wp-includes/template-functions-post.php
        hash.sha1(0, filesize) == "ec3d8704bd705b66375fd3973ae65d8875b3c0c1" or // wp-includes/classes.php
        hash.sha1(0, filesize) == "141df3708b3baed90e103249c1865ff7f26644ad" or // wp-admin/import/dotclear.php
        hash.sha1(0, filesize) == "7c70bbfd6c11b80190cd40ac2d4997f21b4bb138" or // wp-admin/import/mt.php
        hash.sha1(0, filesize) == "b312bf295f0c0212b1e76c16c472e5c3873c349f" or // wp-admin/upgrade-schema.php
        hash.sha1(0, filesize) == "71fd83652c516b3390a81bc011a36c468ff40294" or // wp-admin/import/textpattern.php
        hash.sha1(0, filesize) == "a7a731d1e6c8d878f9c5937649e5965c93495e6a" or // wp-includes/cache.php
        hash.sha1(0, filesize) == "e9a400f011531fe0df04a14575c51b0f9bfb13b9" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "54b435636cf682e6c016f186546f70323bd2207c" or // wp-content/plugins/wp-db-backup.php
        hash.sha1(0, filesize) == "f6344841904ae6ae36bb601b83c8ccb2773367e7" or // wp-settings.php
        hash.sha1(0, filesize) == "5d5e5024b5b4a99b8ca1a8468ad733359104535b" or // wp-admin/import/livejournal.php
        hash.sha1(0, filesize) == "76deacb2c6114d0dcfdedf1d826cc50b7256067f" or // wp-includes/functions-formatting.php
        hash.sha1(0, filesize) == "110a0cae457027069bcb119700b8fb05ee8902c8" or // wp-includes/kses.php
        hash.sha1(0, filesize) == "581832b37477f41262c5d390a9bdb9a355531803" or // wp-content/themes/default/functions.php
        hash.sha1(0, filesize) == "e5c3e9efdb2a998843fa1f839abc4a9730dbf8b9" or // wp-admin/import/rss.php

        /* Wordpress 2.1 */
        hash.sha1(0, filesize) == "9f4f0d639529d0401068bd383118c725af37ad58" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "b9c56dd96760c71c14cd8976d7f75cea1d35d0c8" or // wp-admin/import/dotclear.php
        hash.sha1(0, filesize) == "b79beb4f254de5d582073e1cbfb053326776b320" or // wp-admin/import/mt.php
        hash.sha1(0, filesize) == "675a6a790de1d4bbe587e92d113f96629ac4c04c" or // wp-admin/upgrade-schema.php
        hash.sha1(0, filesize) == "fedccf0d3759d016e16415143130fc38ee09d070" or // wp-admin/import/wordpress.php
        hash.sha1(0, filesize) == "c1fcd224b5d09cb9a36b869a6effcbbfd4dcab63" or // wp-admin/import/textpattern.php
        hash.sha1(0, filesize) == "52fd7cad68d04350352a33e84d83d574642291d9" or // wp-includes/cache.php
        hash.sha1(0, filesize) == "7724103990514140f60eea348c1a5e1a8ddc4d50" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "9549fc63a8ec8981bdf5ce34ca77a0013aa3b471" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "f928ea4f26058acfea442a3ca1afbeb9946192e5" or // wp-settings.php
        hash.sha1(0, filesize) == "59fdcdf93c5e85c1d48661092171cc24b30a9163" or // wp-admin/import/livejournal.php
        hash.sha1(0, filesize) == "74ef008022d86bdda75dd93d4a3f924343868cc9" or // wp-content/themes/default/functions.php
        hash.sha1(0, filesize) == "08a6997f8f11d6bd63f46912c78c0e301f2c036e" or // wp-includes/kses.php
        hash.sha1(0, filesize) == "db216bcb16198dc9c793aec13f89e58d9d3966c1" or // wp-admin/import/blogware.php
        hash.sha1(0, filesize) == "299f3abf5f9056628d1ff154cf139a0f932bbd35" or // wp-admin/import/rss.php

        /* Wordpress 2.1.1 */
        hash.sha1(0, filesize) == "fe43529b52a5a1bb99c86ef722c641cad3532d78" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "a05512a05587f71edf491c91a7b18d9fc298e0e6" or // wp-includes/cache.php
        hash.sha1(0, filesize) == "d79f1f2ed14dcf262e7d28929f043831b8314c4b" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "00fec50697bbfb5ac7749c5bb568401c33fec934" or // wp-includes/formatting.php

        /* Wordpress 2.1.2 */
        hash.sha1(0, filesize) == "de2b6795e253cedc5005e5debf2bce58a62aa087" or // wp-includes/functions.php

        /* Wordpress 2.1.3 */
        hash.sha1(0, filesize) == "c1638d36e080c9fb5ccc6dae2038b2324b272413" or // wp-admin/import/dotclear.php
        hash.sha1(0, filesize) == "09f580a6a0ad8ad8e02661601083445c19bf2430" or // wp-admin/import/mt.php
        hash.sha1(0, filesize) == "6a1b919e2438cd4ac9cf77ca6b6022ab49c8215a" or // wp-admin/import/wordpress.php
        hash.sha1(0, filesize) == "d25d5616c8425a1c2c4de654045569c843fdce2f" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "7f955bdb6458fdb71b79610fa620ce9831ad00aa" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "e2ad5b326459b8cdb47e9479d27fcb2d1eebe697" or // wp-admin/import/livejournal.php
        hash.sha1(0, filesize) == "008ebd6839946ee90fb6027fb81daa4a78e3e4d9" or // wp-admin/import/blogware.php

        /* Wordpress 2.2 */
        hash.sha1(0, filesize) == "5597bfd5338fd301fe48fbc6c53f922230598dbd" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "f51dd567d49a188e792af2fa9d09c2fb4e43cf78" or // wp-admin/import/wordpress.php
        hash.sha1(0, filesize) == "e9c4c43cc62637bc2d377cccd73946158c000d0c" or // wp-admin/import/dotclear.php
        hash.sha1(0, filesize) == "1afe3c39290814da7b4283229ed5091c4626e678" or // wp-admin/import/mt.php
        hash.sha1(0, filesize) == "baff7cfd9bef4ecacab4cff69a2f138de04a8f2a" or // wp-admin/upgrade-schema.php
        hash.sha1(0, filesize) == "eb901b52302dc3c56d40a692d361f6556a8bce50" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "bc99eab3c954ca3de24f537cce05fd40e7a8e64a" or // wp-admin/import/textpattern.php
        hash.sha1(0, filesize) == "81ff65b86c5e0705cf25b76ea9dc647775030c69" or // wp-includes/cache.php
        hash.sha1(0, filesize) == "f18800acd192ea96b59565d3145355db8e617955" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "0d396e10a3a3e03a5fb426ce0c49fd59c1316229" or // wp-admin/widgets.php
        hash.sha1(0, filesize) == "e780adc27aae0fee49b7f79ec87272bc0a3801ec" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "3abfb2bb0912651db1cbd66252fa7baa0bfce9bd" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "50057b77c3631af0f933014364299b24a337d53f" or // wp-settings.php
        hash.sha1(0, filesize) == "c63c4029ede3aeb805d1a92af95672596dbd9813" or // wp-admin/import/livejournal.php
        hash.sha1(0, filesize) == "09a68f33e0057771d31d81fc2e8d3125eca3e63c" or // wp-content/themes/default/functions.php
        hash.sha1(0, filesize) == "ba6deae9f8bdf24417605c6a116c9f6a228d7b3d" or // wp-admin/import/rss.php

        /* Wordpress 2.2.1 */
        hash.sha1(0, filesize) == "e3e4465338abfd1d0ac8a34c553faef1b8e23023" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "0e19e89003407488396610e5339d7d2230286cef" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "d7b5a1e86e3877484e9ee00a96404d8daef2ef1f" or // wp-admin/widgets.php
        hash.sha1(0, filesize) == "222808ccc88d05098403c5c1e49a55fa506f87e4" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "0e53a7d1b74e057963d4bb3b347ee5ee48c6cde5" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "480037030263fc22946b24e45284b454f894dcfa" or // wp-settings.php
        hash.sha1(0, filesize) == "2769eb37346aeaf5cb02150053267b0df6669c86" or // wp-content/themes/default/functions.php

        /* Wordpress 2.2.2 */
        hash.sha1(0, filesize) == "4d4c004434f10d28152728f20fa5f36050e73d4a" or // wp-admin/import/wordpress.php
        hash.sha1(0, filesize) == "9926c9fad1583cecf7ea67cc63f63eddab0d2e26" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "576257d5ab59c4589fc56311762d634cbcecf4c9" or // wp-settings.php

        /* Wordpress 2.2.3 */
        hash.sha1(0, filesize) == "71b187bd8227cde46edab8487aad492b50832e82" or // wp-includes/formatting.php

        /* Wordpress 2.3 */
        hash.sha1(0, filesize) == "a3771e0965c35cf1cc7ce410bd0542914cecf05e" or // wp-includes/post-template.php
        hash.sha1(0, filesize) == "4bcfaa43be4facc4084e0653247a53cc40834a8d" or // wp-admin/widgets.php
        hash.sha1(0, filesize) == "e359d996db9e59d51506816c0b7022b6b4cfaf6a" or // wp-admin/import/dotclear.php
        hash.sha1(0, filesize) == "fd45f67a717f94b3ae594a63bb30467365abbc74" or // wp-admin/import/wordpress.php
        hash.sha1(0, filesize) == "3d65d628b1bf955f7a357dc3102bd9ef22ccfc82" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "4b2988050ee832f809385d9324abd6582d160e10" or // wp-admin/post-new.php
        hash.sha1(0, filesize) == "da630e586ffe4d9166e99f75ed8117ccbe6f709d" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "7de5eb5a860002cabcbb4d6e84132df48c181795" or // wp-admin/import/textpattern.php
        hash.sha1(0, filesize) == "99ae1ef3df6c231bd455345c462e24957d266b3d" or // wp-includes/cache.php
        hash.sha1(0, filesize) == "e0c21ee616119b36202f8cd16b042714b5d68e78" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "e6ffb51b65d566a7e8b1bdf75fcd2b8a38fc2c97" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "3a93ef00a239ea72a8e7aa40b20f9b6858b5b1b8" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "4d8aede1ea8589303535818ca255d834791b32e5" or // wp-settings.php
        hash.sha1(0, filesize) == "b9501167812c97104d47c5cd63d82f3f5194d6a4" or // wp-admin/import/livejournal.php
        hash.sha1(0, filesize) == "207cbcab43ff250b4f1d40fa84dcf9d13c11437b" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "fb8f17a2b719b477ca78e9d8dc81b0fe834377c0" or // wp-includes/kses.php
        hash.sha1(0, filesize) == "072623e2c3da259f2b87a2ac0dbba41e1a88ff89" or // wp-admin/import/blogware.php
        hash.sha1(0, filesize) == "baf45e61ddf839a4f42f9547442bfbdafd869ded" or // wp-admin/import/rss.php

        /* Wordpress 2.3.1 */
        hash.sha1(0, filesize) == "cb496e44254cef77c59c3152c4c2a9eca636cfe7" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "604ba321511c37f4d3e97dc23a526cfa953c57c7" or // wp-includes/formatting.php

        /* Wordpress 2.3.2 */
        hash.sha1(0, filesize) == "eea8eaf59d88e17f36e499e83e20073be0b83eee" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "1d0bdfa0b7116651a98593121e212a83509d95f9" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "9848b6c0dbd41b300bdd9e69890b733ddac31225" or // wp-settings.php

        /* Wordpress 3.0 */
        hash.sha1(0, filesize) == "665445dde51bc4e75d4ef07dc14b09101db4de7b" or // wp-includes/class-http.php
        hash.sha1(0, filesize) == "9cccb7cf5d0e092717c3a5356de559e10526ad60" or // wp-admin/plugins.php
        hash.sha1(0, filesize) == "8d862d2b4b9afc28d9ca8ca75fd62770181d9ca6" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "4b110ce87d5b3ad5c3fe9fd9f985aa0a86415cec" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "7342ff8b1e5c61e6231f8319e25a1bfebac17f93" or // wp-content/plugins/akismet/akismet.php
        hash.sha1(0, filesize) == "f17d7ee55dde452e98e18705fd5dd286dfe8a5e3" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "f7518c4651ccd758239ffde50c6e7644223e7a07" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "23d24d524ada37f5e49e09119be7bd4ceaae4c5a" or // wp-admin/menu.php
        hash.sha1(0, filesize) == "8c30d09371a38b82a454f86a624bde4e78dfc699" or // wp-settings.php
        hash.sha1(0, filesize) == "76100ad963c79f11d35161a946edc0b41ecd0580" or // wp-includes/load.php
        hash.sha1(0, filesize) == "c563fdfeb827e419797b7face7dccffcb172e0b1" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "d88cc1fdccdc5e4d2344e00b02444808041f68b7" or // wp-admin/includes/class-ftp.php
        hash.sha1(0, filesize) == "7fc7f30501eafb9abfe052914573e1bd04539d48" or // wp-includes/js/tinymce/themes/advanced/img/icons.gif
        hash.sha1(0, filesize) == "a23672e7059e416a194aedece707ac106c9398fb" or // wp-includes/class-simplepie.php

        /* Wordpress 3.0.1 */
        hash.sha1(0, filesize) == "f8e9266733fb53cb2b9d25a5bae5b0f1b0630598" or // wp-includes/class-http.php
        hash.sha1(0, filesize) == "b8e94c6a2f0bcd0c281cd140fb3c8fc9fc250e3e" or // wp-admin/plugins.php
        hash.sha1(0, filesize) == "349623d138bc2275fc78bfe6431759655f31c9b3" or // wp-content/plugins/akismet/akismet.php
        hash.sha1(0, filesize) == "a5768fd6c0ea3d86364935ecb295229debefda88" or // wp-admin/menu.php
        hash.sha1(0, filesize) == "941ed9928948c10c60fcf119cab038b35b867c83" or // wp-admin/includes/schema.php

        /* Wordpress 3.0.2 */
        hash.sha1(0, filesize) == "24257acdcb9853926064c47360b2bfdeb3eb524f" or // wp-admin/plugins.php
        hash.sha1(0, filesize) == "95aa3900ca9b08a76d75ea97b44af6c0c137f884" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "e55a995543f54b5fb45babe7cc2fb8bd7be05e9c" or // wp-includes/load.php

        /* Wordpress 3.1 */
        hash.sha1(0, filesize) == "fff90e60a907203d93aa498e90fd0e0d94eb530b" or // wp-includes/class-http.php
        hash.sha1(0, filesize) == "bce7816e7142f9b293ca0bb26b2838f12b559bd4" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "adeb0a7be4aea8274226895eb607940a21783541" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "2ba36dba2b1679b11c907aebf279f849ca7d7819" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "83ca0da58eb8cfdc1f4bc46e97b3a5be173b6388" or // wp-content/plugins/akismet/admin.php
        hash.sha1(0, filesize) == "531528c5f2665cf40ad7467ec908a0e4d617c210" or // wp-settings.php
        hash.sha1(0, filesize) == "10de9fd704ab1926cb261ae128db352a23a68d50" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "d04a043f32f7fdfe706ef9b301e7aa72aed7c2e0" or // wp-includes/js/tinymce/themes/advanced/img/icons.gif
        hash.sha1(0, filesize) == "77675e04d4f0b4caff046faadfabfba5e42c3526" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "4e217981091a905e1481198b8a8d560f1b33dcd0" or // wp-includes/load.php
        hash.sha1(0, filesize) == "e5c5ad575faf96327770bb22d77e27ba5ece94f7" or // wp-includes/class-simplepie.php

        /* Wordpress 3.1.1 */
        hash.sha1(0, filesize) == "d52240ded3f041290c51efbeb8dd131e1d43b569" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "7e56318b655f5a7f52e17c15caf8f851497536bf" or // wp-includes/functions.php

        /* Wordpress 3.1.3 */
        hash.sha1(0, filesize) == "893708ce74ad01fef0f823af981de4be37169e7f" or // wp-includes/functions.php

        /* Wordpress 3.1.4 */
        hash.sha1(0, filesize) == "36b34aaa315a6ab831956beb9c158ce3e3d62d10" or // wp-settings.php

        /* Wordpress 3.2 */
        hash.sha1(0, filesize) == "ddafc9a566ed0301bd0e994056a9aad8a76a4793" or // wp-includes/class-http.php
        hash.sha1(0, filesize) == "327d05b299205e530a512ec34fe7e65de1210485" or // wp-settings.php
        hash.sha1(0, filesize) == "2def1ab8c9102926f0fca0647e56580e02f441ff" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "8fbe2fdf95a813305c7719a85e57d58070b052d0" or // wp-includes/load.php

        /* Wordpress 3.3 */
        hash.sha1(0, filesize) == "df25eb2aa95b082a3285017ff022b0647c4c8357" or // wp-includes/class-http.php
        hash.sha1(0, filesize) == "0d6ffc142a93cc7d955cca1e64fddfd77c209bf1" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "bc81865032a285194f7c3210b1458442d55c0ea9" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "d26f5e20390e9141d7a1ecf8d259536db8bba5c3" or // wp-includes/js/tinymce/themes/advanced/img/icons.gif
        hash.sha1(0, filesize) == "4491044f5f58b2368b521282dabac6b3c1e69a9a" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "3bfc1974c27e45fa98b4d49de6ff470cbadfd8d5" or // wp-includes/load.php

        /* Wordpress 3.3.1 */
        hash.sha1(0, filesize) == "675e6b63de9a8e2dfefbce5576b16f47befc7c8b" or // wp-includes/functions.php

        /* Wordpress 3.3.3 */
        hash.sha1(0, filesize) == "f22a80eca9659542f169cca62537e1a20b1260f4" or // wp-includes/functions.php

        /* Wordpress 3.4 */
        hash.sha1(0, filesize) == "31859161f82a9dcd18be47dbf610e426a4195739" or // wp-content/plugins/akismet/admin.php
        hash.sha1(0, filesize) == "d1012acfafb982510e64791c2d88527627308b59" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "3474165d04fd37843be7ea331e8b983aefb5e50b" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "2e23d3a0e48d12dab0b56fe58819126290c21778" or // wp-includes/class-wp-customize-control.php
        hash.sha1(0, filesize) == "c87ea9fdc48d8ee3a68a9c5f4642be00246483a8" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "ea17bc33d8152511147f58fa5806b58c3dbd94ee" or // wp-admin/includes/class-ftp.php
        hash.sha1(0, filesize) == "083edc5ebd5f8357700427bd68933a4a92f28c0c" or // wp-includes/load.php
        hash.sha1(0, filesize) == "5a992b21ed1741eacc54350e65847903feb2b3f9" or // wp-includes/class-simplepie.php

        /* Wordpress 3.4.2 */
        hash.sha1(0, filesize) == "6044453f8940243badb025352dd321a62fbec02f" or // wp-includes/class-wp-customize-control.php
        hash.sha1(0, filesize) == "de56eda60ea144093bfa49d471c995aeae2eb827" or // wp-includes/load.php

        /* Wordpress 3.5 */
        hash.sha1(0, filesize) == "326c0ce5d2428ed6766f74c73011199684278cf2" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "6cc875b9d4974a2004d6ecb8f6c13e5ef9467b54" or // wp-includes/class-wp-customize-control.php
        hash.sha1(0, filesize) == "2592df1c1a7213218efa64518178a69b870ded22" or // wp-includes/js/tinymce/themes/advanced/img/icons.gif
        hash.sha1(0, filesize) == "e77f52c001ced7cd6cf674c7cc459436ddb60147" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "ae9027e66008e5930c08ebfdf68326c0ea9800a2" or // wp-includes/load.php

        /* Wordpress 3.5.1 */
        hash.sha1(0, filesize) == "cbe802300a0441c72a5e026eed20b53478ac20d3" or // wp-content/plugins/akismet/admin.php

        /* Wordpress 3.5.2 */
        hash.sha1(0, filesize) == "0b901f5f853a25e10e8f2682c323c99e3ae8ff1a" or // wp-content/plugins/akismet/admin.php
        hash.sha1(0, filesize) == "95825dbbf8e9ab861253831e49908d452a0d2670" or // wp-admin/includes/schema.php

        /* Wordpress 3.6 */
        hash.sha1(0, filesize) == "a9937016b124ceea599feed1c9208120b9a09165" or // wp-content/plugins/akismet/admin.php
        hash.sha1(0, filesize) == "5431e98768bf066c168c4738107850b00d7e5846" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "fb9ca56084e659e2752e2e2f078ab6f49e262581" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "4fd7c870fefb3d65d724cdd04afd3b6d7a6badf0" or // wp-includes/ID3/module.audio-video.matroska.php
        hash.sha1(0, filesize) == "8e6c54d7039cf3520bfd64ef8d0b2179098830a3" or // wp-includes/class-wp-customize-control.php
        hash.sha1(0, filesize) == "019098726f3ae41cc4d904ca6bbb48d901421a2a" or // wp-includes/ID3/module.tag.id3v2.php
        hash.sha1(0, filesize) == "965165ebc95689241e288a7a1dc7d13b4cc57a1e" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "130f6185b489b330500aba9ad2317a412de9a274" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "cad165dcb790e65df4afca9b50f7aee5c81293c5" or // wp-admin/includes/class-ftp.php
        hash.sha1(0, filesize) == "ddfd138d6874301cf215783169d582253334822e" or // wp-includes/load.php
        hash.sha1(0, filesize) == "6d68d391ed8018d36d953c89b51b9a4144815dd8" or // wp-includes/ID3/getid3.lib.php

        /* Wordpress 3.6.1 */
        hash.sha1(0, filesize) == "7826fad4cbffac23ddb1dd8cc150b7e0b99f3ac4" or // wp-admin/includes/template.php

        /* Wordpress 3.7 */
        hash.sha1(0, filesize) == "c8f5ea8b286b11b8af96b625da7542801c639030" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "d21ec1b245410ec5d9d45876c1390fd93a0021ef" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "fa71ee03371cbe2ea6b979f917b10f5d12d33931" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "10af2f264159d072b89a404c4243bc1b177f4b22" or // wp-includes/load.php

        /* Wordpress 3.7.2 */
        hash.sha1(0, filesize) == "a675ab102c1e889d167a7b6ae65c48d84dee8d64" or // wp-content/plugins/akismet/admin.php

        /* Wordpress 3.7.4 */
        hash.sha1(0, filesize) == "94a5a8bbd4695db282798dc947538584cfa2954c" or // wp-includes/class-IXR.php

        /* Wordpress 3.7.6 */
        hash.sha1(0, filesize) == "54ddbacfcb8f60021ca926fcf415ac870e025dfc" or // wp-admin/includes/template.php

        /* Wordpress 3.8 */
        hash.sha1(0, filesize) == "8bd51a5649f5fa9762cbc116212f35eb444fd4ef" or // wp-includes/images/spinner-2x.gif
        hash.sha1(0, filesize) == "8bd51a5649f5fa9762cbc116212f35eb444fd4ef" or // wp-admin/images/spinner-2x.gif
        hash.sha1(0, filesize) == "bffabaf729c8922e53af4cefac61b2a2f6bc4889" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "8ccb888a8230e675bb968d4aee7a8b06e7181a50" or // wp-admin/includes/schema.php

        /* Wordpress 3.8.6 */
        hash.sha1(0, filesize) == "f1b1ef424167974e77de771b2e14611f19b52396" or // wp-admin/includes/template.php

        /* Wordpress 3.9 */
        hash.sha1(0, filesize) == "674103e9be90964eeb0976d1eb8a389536bd4a0e" or // wp-includes/images/spinner-2x.gif
        hash.sha1(0, filesize) == "66e190e129136b9cc01fab3277c3675ca414a3d2" or // wp-content/plugins/akismet/class.akismet-admin.php
        hash.sha1(0, filesize) == "eb97a3e94bd576d7e18b86eda34dd5fb52ca581a" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "999034fc7d1aee5c45b63511e91ec57ce29709e3" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "e4e7a298eaa8383c7d3ae8e084600bc73c5a5d79" or // wp-includes/class-wp-customize-control.php
        hash.sha1(0, filesize) == "67c7d31d7eefb838131767f7470d85ad2fac8041" or // wp-admin/includes/menu.php
        hash.sha1(0, filesize) == "cc91aae9a752176317b3e22f915899a46e4b8612" or // wp-includes/load.php
        hash.sha1(0, filesize) == "a2ab86b24ff3d23fe056db007a083bfe99714ba0" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "1a4e6932523c34d95f050960e7c3d082adb28156" or // wp-includes/ID3/getid3.php
        hash.sha1(0, filesize) == "b20e3d401b0ab935ed6401392233b36966523e20" or // wp-includes/class-pop3.php

        /* Wordpress 3.9.2 */
        hash.sha1(0, filesize) == "5f238f6427ec6c992233866304ae6ef697d0b227" or // wp-content/plugins/akismet/class.akismet-admin.php
        hash.sha1(0, filesize) == "3e3c1c4ebefdada1759ec45355a8d94c08a2b594" or // wp-includes/class-IXR.php

        /* Wordpress 3.9.4 */
        hash.sha1(0, filesize) == "44e7d23bf7470c98fd232d7e7a04e1f68bd04af9" or // wp-admin/includes/template.php

        /* Wordpress 4.0 */
        hash.sha1(0, filesize) == "16270033d7ae3ed2c76f9ec41a9b976fbc61064e" or // wp-content/plugins/akismet/class.akismet-admin.php
        hash.sha1(0, filesize) == "93b1ae2cfac4d89cd0bbdc4ca5f3ea2084df4495" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "b77c56f76507611b337e3f0e775c22588c9632cc" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "7b85c502fa925cd50727a4038145d90eb6eb0bad" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "309e673bc04e1c310bfccccd9888c006e13722be" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "d79f7c2d920f383cb0e6f4083939c32a140319c3" or // wp-includes/class-wp-customize-control.php
        hash.sha1(0, filesize) == "acfb5a32bf5e8e829eaa3c56f7ef0fcb4420b73f" or // wp-includes/load.php
        hash.sha1(0, filesize) == "1558cb5edf91b4dec5b5dc542579326f55fcc28e" or // wp-admin/includes/schema.php

        /* Wordpress 4.0.2 */
        hash.sha1(0, filesize) == "2ecb411612d5b1530a9c2ffef1fc5e1326cf6027" or // wp-content/plugins/akismet/class.akismet-admin.php
        hash.sha1(0, filesize) == "adae9e0270d21835f329a4dfb857ab10133436f8" or // wp-admin/includes/template.php

        /* Wordpress 4.1 */
        hash.sha1(0, filesize) == "e01ac1f8cbe8ab64e84b334c58b5c8af2cf41509" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "ab6161dc4c50d19e9d201634ca8ba2d96fb80fc3" or // wp-includes/ID3/getid3.lib.php
        hash.sha1(0, filesize) == "b6ba1a1419e5773360e0872a93c24b9d67698731" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "5fa674e723dbaee40d4a219fcd839064c7182082" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "b769e6f073ea525e2465b605abb7e6e3e5b77c25" or // wp-includes/ID3/getid3.php
        hash.sha1(0, filesize) == "6064b351860ea8d382f96346d819a52148e086c1" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "7c55402493792abbed050d2e8cc494152ff073af" or // wp-includes/ID3/module.tag.id3v2.php
        hash.sha1(0, filesize) == "81f3f71e108f3bfca2cf7a30bc7e3035e42f733d" or // wp-includes/ID3/module.audio-video.matroska.php
        hash.sha1(0, filesize) == "170419966151e4e6bd60c87744b3880dc8b50f84" or // wp-includes/load.php
        hash.sha1(0, filesize) == "b83f659cd09f0d4e5e6485a92751d580d56c1160" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "3a43a64de9462ccddc18d05faf3e8bb42a2a9440" or // wp-admin/includes/class-ftp.php

        /* Wordpress 4.1.2 */
        hash.sha1(0, filesize) == "d64e8b491e88e8c8fcdbc6bcf73c4b14378dd6ac" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "2e863bf3dc516fcdb811362c1b4cbdf501070265" or // wp-includes/functions.php

        /* Wordpress 4.2 */
        hash.sha1(0, filesize) == "30e63faf926f3ec391afabaa9c296b65e149981a" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "aff70e3c53d9ee97d3870144cca84869117f51c2" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "a97f0a85009f7e19e7e3edaba2dc084845f11c09" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "ea45e00502ee030229a2940ad297ff7d6fc71d0c" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "fa12d10bdc4af9abf572dfdd3d7e752c7d2fd2df" or // wp-includes/load.php
        hash.sha1(0, filesize) == "f00abe48357b10eafbf1a40855a330436633c831" or // wp-admin/includes/schema.php

        /* Wordpress 4.2.2 */
        hash.sha1(0, filesize) == "e350431c90bd2ae81d244b2efc6d3844eb43959d" or // wp-includes/js/tinymce/tinymce.min.js

        /* Wordpress 4.2.3 */
        hash.sha1(0, filesize) == "f1c4697ae04da5eb19847c8f1296edce2ad3cec9" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "e7caf1f66c38bb119fe709ade012a989d8610f07" or // wp-admin/includes/class-pclzip.php
        hash.sha1(0, filesize) == "8ddb9eff06105b9699c6b03db54472291abcb823" or // wp-includes/taxonomy.php
        hash.sha1(0, filesize) == "9dd666651f57ef6e704310fe37ffce7dfd2322e4" or // wp-includes/comment.php

        /* Wordpress 4.2.4 */
        hash.sha1(0, filesize) == "20176473436fa9be554659f5f921a2b08fc66c9e" or // wordpress/wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "4be1c9f6825b163668c5c9084032f058379e9d25" or // wordpress/wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "aae4e9c2ad0bfa7cebe4e19fdddba3119197dc6f" or // wordpress/wp-includes/post.php
        hash.sha1(0, filesize) == "85f1d5a71013a3e75b88ab1a6679c02df01179b5" or // wordpress/wp-includes/default-widgets.php
        hash.sha1(0, filesize) == "ddc3c60de72339299e91aba2ccd4f31d931f8be5" or // wordpress/wp-includes/deprecated.php
        hash.sha1(0, filesize) == "4bdf423a6e85a54f72f12f75ffbf4cd1db13a0eb" or // wordpress/wp-includes/query.php
        hash.sha1(0, filesize) == "005f02927a6904c4e7f3b88ebdd9feaa6221790b" or // wordpress/wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "659c78aafc334c6076c1543202bca090a1eedf2b" or // wordpress/wp-includes/media.php
        hash.sha1(0, filesize) == "71f2de7b22628efdb6074ad44aa33dc10de1c473" or // wordpress/wp-includes/formatting.php

        /* Wordpress 4.3 */
        hash.sha1(0, filesize) == "2d97f1953b9cc70c72a53515d5339ad46875bba8" or // wp-content/plugins/akismet/class.akismet-admin.php
        hash.sha1(0, filesize) == "f563d6766a7ef4812132ccb6964faff2f565c4b4" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "2cfb4df95ef1aefdcdf066fc950ada9216d44748" or // wp-includes/ID3/getid3.lib.php
        hash.sha1(0, filesize) == "2a0b24a1b350abb18830bddb751b7bd93871eb65" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "2772b68e7fe30dfdc26116b5354269cce326a26d" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "122959dd4ed4809995e343cbe136f380b9a2f4ec" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "3601bb01eabe1d97f9befc11171f72aa498acaf7" or // wp-includes/ID3/getid3.php
        hash.sha1(0, filesize) == "a63036a84eaa6832eb48b53d94f18506bea9f5a2" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "1d4cac818edf491d0c3136ba3d87c2975a8f1835" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "f02356312d8dac3c78ec23857822afd1ef5d7256" or // wp-includes/ID3/module.tag.id3v2.php
        hash.sha1(0, filesize) == "059599a5f5d0ae41faba440598986e647a5b18c4" or // wp-includes/ID3/module.audio-video.matroska.php
        hash.sha1(0, filesize) == "8018b24f7a8f601dc95652b6a349aef134e6523f" or // wp-includes/load.php
        hash.sha1(0, filesize) == "150c1b94dd4362bc8486d4d7d8341eeabda67517" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "0e08bb94db2c61fa2a0568c483c949e66388e877" or // wp-admin/includes/class-ftp.php

        /* Wordpress 4.3.1 */
        hash.sha1(0, filesize) == "f5a651a0956940708bd301aa51e678fc75920692" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "9b0d14049d987d3799f55a187fff28490907bd73" or // wp-admin/includes/template.php

        /* Wordpress 4.4 */
        hash.sha1(0, filesize) == "e5895a9b2fb87f973bcb61c1d261b333af601f4a" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "0794b593c9e46b04d4a59fee9033eb48b1fd6ec2" or // wp-includes/class-pop3.php
        hash.sha1(0, filesize) == "beb694e678f0f5f932ab0b379a0b8ea23d115ff4" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "ade3248a6ea9fd09cca12fb1ca1ee4795a33c0c9" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "6f0d159007dd930e9d626f439375b8bbcfc605e3" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "ccc4f836aafdf9d7323eb3b83902edac23e66250" or // wp-includes/load.php
        hash.sha1(0, filesize) == "8e82a4af96877e60d6e0c768171f19b36ac60196" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "4bfa19d7a879df5ee8cf3b22e4900661c0759fea" or // wp-admin/includes/class-ftp.php
        hash.sha1(0, filesize) == "b7fd39d2ac1f13973569e5feff5e17b64e247a0e" or // wp-includes/post.php
        hash.sha1(0, filesize) == "c605d1224cf4b24ad2457dd87885de9030e20731" or // wp-includes/SimplePie/File.php
        hash.sha1(0, filesize) == "eca359bf91e9f7ad1539417bbe7dab5ebfe0bcf5" or // wp-includes/media.php
        hash.sha1(0, filesize) == "8b5ce8366686fe524bcba135c4b6ffc03480769a" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "8c5ba6d965dbdb2b3e16e59f72e5a0b6559994f1" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "2d344715841e1762e65f34a4c63f9d13f517b084" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "879a7bd2948313764c701864fa065db5d20fbf2a" or // wp-includes/query.php


        /* Wordpress 4.4.1 */
        hash.sha1(0, filesize) == "bfbd2845d3c931b6db059d9e968aa8ba86e6a92c" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "b101b029420f3a93bf81c806be728863462f4898" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "d07798ef2f94bf0d1d34287378013e67104d0f89" or // wp-includes/class-phpmailer.php
        hash.sha1(0, filesize) == "64c328619d8ea6a21a04e55a500f4e05af718bf7" or // wp-includes/post.php
        hash.sha1(0, filesize) == "fc8a9e33a671118a69d36352bcd1e66e0c55516a" or // wp-includes/media.php
        hash.sha1(0, filesize) == "38217628cce1d6a52f17afc3ca6bf204e13fd26b" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "c312ae274a2b110de70fd767ccfcafc3231dcf31" or // wp-includes/query.php
        hash.sha1(0, filesize) == "7db1719874b1415e54981c6f1ed698274abffd28" or // wp-includes/formatting.php

        /* Wordpress 4.4.2 */
        hash.sha1(0, filesize) == "0248f8986d459efe56f888258f3588b1ab3f5c3e" or // wp-includes/load.php
        hash.sha1(0, filesize) == "6e99d2964ccc25e6c1cbec018acfd8e71d361b58" or // wp-includes/query.php
        hash.sha1(0, filesize) == "4e63ff8623f0b0e5f0f016711d0fcd3fd4dad7fb" or // wp-includes/formatting.php


        /* Wordpress 4.4.3 */
        hash.sha1(0, filesize) == "d5b3eb3d5606a6deff3df44b21c1a0b72ea3db22" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "ef1193d1b4dbf9d8d7ff46f0c91da73fb8b26530" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "ec6a2d6f19ba0020383097a0368e8905fbfd832f" or // wp-includes/query.php
        hash.sha1(0, filesize) == "18596b04313c48a4d5f83e0f79adb393b9f9e682" or // wp-includes/formatting.php

       /* Wordpress 4.4.4 */                                                   
        hash.sha1(0, filesize) == "a8970bf00185e6f515dd5a461ad3ba97a409fbeb" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "e4c1f5bfd8b4551d32b2b966bbc20a67c333e4b1" or // wp-includes/formatting.php


        /* Wordpress 4.5 */
        hash.sha1(0, filesize) == "d7b08235a591289efbb34dce747655e7bf3eb8a0" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "4d7941a92e9d54fa93ac2c32d845b815c2888b97" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "86046badfe80345980d012b2b17f15893a61fd4a" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "48834716595aec19ebdc740f084d6c162b2216bc" or // wp-includes/random_compat/random.php
        hash.sha1(0, filesize) == "e1e2beae1fd39713a557f3708712648b13a55594" or // wp-includes/load.php
        hash.sha1(0, filesize) == "559be10bef70c9a098eefc7d858ec568b803e34b" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "3f5c09257f346218dcbc424e68cb7f7536e9c415" or // wp-admin/includes/class-ftp.php
        hash.sha1(0, filesize) == "f4581cc5d8d6f537f01929377186dd4276359b2d" or // wp-includes/post.php
        hash.sha1(0, filesize) == "268f4606d2309a9f5996410cae17c7adafc84fd3" or // wp-includes/media.php
        hash.sha1(0, filesize) == "7754fb3e64d575d78fb222eb1ee876a90104fbb1" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "97a611917ce4c3f8e11f2e763d894a3e1e2bba45" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "6f241327941dcfc47bc9560e64840030fa33082d" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "c6679fc46c084dac514238d5bee7c998470407e6" or // wp-includes/query.php
        hash.sha1(0, filesize) == "02b7d1b238568bd1d5c27950187e014b66ad84fc" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "333f00a13cc2930a62d2297cbd768cf1b998bd55" or // wp-includes/deprecated.php


        /* Wordpress 4.5.1 */
        hash.sha1(0, filesize) == "39ae0d6483c7e6dd5591f65291902d531a46d212" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "097037e0796d61d62497c7112067baab49efb7e3" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "55bb1de0036e3d648e77c0680f472bc59223103d" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "640144656d09b8dbd02bb50b26b3731721e1b519" or // wp-includes/formatting.php

        /* Wordpress 4.5.3 */
        hash.sha1(0, filesize) == "f3cc06e022008a67f5f29359ef886bd164d2b5b3" or // wp-includes/load.php
        hash.sha1(0, filesize) == "b8202b8801fbc236cb2baa52e95f845acdaddfe5" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "90168c265f327bbf1fa0a03277559252535193b5" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "bd4825cdd9770c2a56285f1a943405aac5d3f8b7" or // wp-includes/formatting.php

        /* wordpress-4.5.4 */
        hash.sha1(0, filesize) == "ccd23ef96a588840943fba081bfa6f88531c4abc" or // wordpress/wp-admin/includes/class-pclzip.php
        hash.sha1(0, filesize) == "78f2e24abfdd3a9aa7860cd5a3ecf3a0c3e72599" or // wordpress/wp-includes/widgets/class-wp-widget-categories.php

        /* Wordpress 4.6 */
        hash.sha1(0, filesize) == "8a187078730ca4fc59c62ee7733b03bd6f820066" or // wp-includes/widgets/class-wp-widget-categories.php
        hash.sha1(0, filesize) == "01b00537f8ea6c0e7d567ce0cb85adafc0766293" or // wp-includes/post.php
        hash.sha1(0, filesize) == "73971e6d086c60ee8706fe3672427baf36cbfc47" or // wp-includes/media.php
        hash.sha1(0, filesize) == "40ecd46843d363a5b972b7fb58f5c7501f828bd3" or // wp-admin/includes/ajax-actions.php
        hash.sha1(0, filesize) == "620448d18321742dd574d3cc90b284d898d2c881" or // wp-includes/comment.php
        hash.sha1(0, filesize) == "98cf7396f0e2fe49f20363ae524d4bacbf1e6b7a" or // wp-includes/js/tinymce/tinymce.min.js
        hash.sha1(0, filesize) == "6e1c4904233c9e7cccabef93130cae63515d121f" or // wp-admin/includes/upgrade.php
        hash.sha1(0, filesize) == "dab050dcb7b3e879aefb6512711890e36235f60b" or // wp-includes/deprecated.php
        hash.sha1(0, filesize) == "a59a22eaf8fe475582932ded5d78941abb987f63" or // wp-includes/class-IXR.php
        hash.sha1(0, filesize) == "4d9ac49f01d52386b2a1008a89665f8d009b48f3" or // wp-admin/includes/template.php
        hash.sha1(0, filesize) == "1d045097928a420aa2b0bdded2858e06103eff12" or // wp-includes/query.php
        hash.sha1(0, filesize) == "3c872daa02b246f059db6f2ccf4861bf2c0fc71e" or // wp-includes/functions.php
        hash.sha1(0, filesize) == "4d14f4a0e6dee443781f8a4d0dcc179f05cb7508" or // wp-includes/formatting.php
        hash.sha1(0, filesize) == "dfe0e8b745d516ee953c36a91f5e381868d1d9ee" or // wp-includes/load.php
        hash.sha1(0, filesize) == "42f94321c15d9d03ef6b108beebabf20a5e36f9e" or // wp-admin/includes/schema.php
        hash.sha1(0, filesize) == "ed16b47ec6fbe3786d62fa0648a87ab225a5b498" or // wp-admin/includes/class-pclzip.php

        /* Wordpress 4.6.1 */
        hash.sha1(0, filesize) == "8f20d9558a6f5dfd5366acfc0f2b8ac454d50365" or // wp-includes/load.php
        hash.sha1(0, filesize) == "841e5834cef1bafb9ff11ac6b122567fe7be58be"    // wp-includes/functions.php

}
