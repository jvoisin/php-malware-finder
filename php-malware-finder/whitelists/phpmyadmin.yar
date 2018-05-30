import "hash"

private rule Phpmyadmin
{
    meta:
        generated = "2018-05-30T12:35:38.661805"

    condition:
        /* Phpmyadmin 4.0.0 */
        hash.sha1(0, filesize) == "1055b5023001d995d1a42e9e25731b621b3a1b78" or // libraries/plugins/auth/swekey/swekey.auth.lib.php
        hash.sha1(0, filesize) == "df4108af17881e331feeeeef9ec35ef4b2fff87c" or // libraries/select_lang.lib.php
        hash.sha1(0, filesize) == "534f0c81f69b78a3c0cd64748f55d86effa94d96" or // server_databases.php
        hash.sha1(0, filesize) == "1f1d01182cf376eb7cc463cb67334c98166f3033" or // libraries/build_html_for_db.lib.php
        hash.sha1(0, filesize) == "ca17eb55ded8f62e7339e20d699f1e43a52df778" or // pmd_relation_upd.php
        hash.sha1(0, filesize) == "82cff5aa0109bab26bd5e53f9928fa8cb1d21d18" or // locale/da/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "0401e8fdf617610e6da72c8a75c7ff0bf0e2a1e7" or // pmd_relation_new.php
        hash.sha1(0, filesize) == "be3ea7a4f914387dc71531c2479867ee65dfe947" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "8b2f9bb37f25ed57bb7497d4dc9c98a042dd367e" or // gis_data_editor.php
        hash.sha1(0, filesize) == "0e76cbda3599c8139f6a8a5c6c17f6abc3835397" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "a4e970da05605cfe12b0897c111e475bb1ceeea3" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "2905b3fe33a09435b76675a8728e461f3ac5f9e0" or // doc/html/_sources/faq.txt
        hash.sha1(0, filesize) == "68c477fe016abd4236ee25717c7c736d400f1b58" or // libraries/DisplayResults.class.php
        hash.sha1(0, filesize) == "2905b3fe33a09435b76675a8728e461f3ac5f9e0" or // doc/faq.rst

        /* Phpmyadmin 4.0.1 */
        hash.sha1(0, filesize) == "8a47d5c1f34e15094d4a6264cda406b943e021c4" or // locale/sl/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "75f8ad7de654ad3bbc274528996a954bcc1785bc" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "833ccf4a4016a1b9594db0469f22e08688ef345a" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "40d47a7e9786f77e63ffeb444cd529e88e22498f" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "4e93c2797c64b3754694b69d3135e7a09f805a86" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.2 */
        hash.sha1(0, filesize) == "9354e4058a1efa8aa73918eb2bd45f5cd8777485" or // locale/ko/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "7aa5c4d0e51d219ebba86ddc644dca0355e5f6cd" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "73efef4f340f00aa2823cf575c30d5fd63d571cc" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "ee8b1d455efa66a92ce3025d7c79758cb2767e76" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.3 */
        hash.sha1(0, filesize) == "72e309407d3a741f9345cc252d8853013909c1cb" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "70ab1c6ebdcc383fa12e68b24dff205cc313761a" or // doc/doctrees/config.doctree

        /* Phpmyadmin 4.0.4 */
        hash.sha1(0, filesize) == "ba8247bedab84b62d23998eb96be6f2a92d4d1bc" or // libraries/select_lang.lib.php
        hash.sha1(0, filesize) == "6feca5c241e41d8fdcfb0f9104f06fc27414206e" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "5d01bc6404187356a5428ea392dda0304f5a06be" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "dfa5d49a57c3849589d7db123850fe22efe0e421" or // doc/html/_sources/faq.txt
        hash.sha1(0, filesize) == "dfa5d49a57c3849589d7db123850fe22efe0e421" or // doc/faq.rst

        /* Phpmyadmin 4.0.5 */
        hash.sha1(0, filesize) == "8690e479b31ee1705de8fd654eed504ea86255d6" or // libraries/plugins/auth/swekey/swekey.auth.lib.php
        hash.sha1(0, filesize) == "0fa37a1808b87318af1c8b909515926ea908e20d" or // server_databases.php
        hash.sha1(0, filesize) == "08b9be901a1cad1910f909b0c3308c80179faea8" or // locale/pl/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "1a39333456f3ed00f78c434cd2260aa1f6055d28" or // locale/zh_CN/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "086cf75edbc7a84d7e2da7acd4ef449414b04a30" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "5d941f85a5364e609fc1e772df46b11cd53a31ce" or // locale/it/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "38a06d88278ce2d049c27861f1065f946aee5fdb" or // locale/zh_TW/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "d8209cbed693cbfab4e49a20d2b72a545eff09d7" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "fb04115aa12c7ba54adcc64b20255b3e93916e94" or // libraries/DisplayResults.class.php
        hash.sha1(0, filesize) == "e80ac17842b54c099836c04e4eebf72f09c36559" or // doc/doctrees/faq.doctree

        /* Phpmyadmin 4.0.6 */
        hash.sha1(0, filesize) == "178edee119fd53a1ca87f289213faf34c6e23065" or // locale/it/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "89137874313404331edd64dd561ee72c1e90a966" or // locale/pl/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "21ace5bcde26b98a381091fc3dda588115bff565" or // locale/sv/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "819cfe3120478406300d5fc446d258df9790db10" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "5c0ba64f2f6f4de362cb2a227325194283edd64b" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "5993a60e0f14ef9d898b3f82e7bb5faf410084c9" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "5bf1ebc6cd395fc8cc084f2b2ce45ad31a2e847f" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.7 */
        hash.sha1(0, filesize) == "23590f9a72fd45409b79f238e6a32d394268d484" or // server_databases.php
        hash.sha1(0, filesize) == "f9b7639cb78d11bd6f55a89a4630409b1f0b4ed6" or // locale/zh_CN/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "6790cd3b963f31c4706689564bb3a758868e25e2" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "0c7b68640f071c0a7cf2d5c27b1ab1a557778c35" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "c9d24ecbe33a5a9bed089be06008d5ace9fe8022" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "28d2a89687bf1ab53d52180043635f0290d3e848" or // locale/en_GB/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "2747f18959d06cadac8cd8d8a16b95ff8ef0fd25" or // locale/nb/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "8eb466ea26d87c9a5b55c8349b106f5b621d8347" or // libraries/DisplayResults.class.php

        /* Phpmyadmin 4.0.8 */
        hash.sha1(0, filesize) == "47b80bc9f6a053cbd794e349bf7c81e1ac523780" or // doc/doctrees/config.doctree
        hash.sha1(0, filesize) == "75f3774629d8bb599b4111a36a5b813e800b61bf" or // doc/doctrees/faq.doctree

        /* Phpmyadmin 4.0.9 */
        hash.sha1(0, filesize) == "1db96b0f2bab1a326255a271c190859ca0d2fd15" or // locale/ja/LC_MESSAGES/phpmyadmin.mo
        hash.sha1(0, filesize) == "5dc82742fbbe5b2322321995474a0a1a784736a1" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "f8ed7a657101c83ca24761111dfcf8298818ea84" or // doc/doctrees/config.doctree

        /* Phpmyadmin 4.0.10 */
        hash.sha1(0, filesize) == "3cb1858da44833ca8bca16c2651881d5d899a1dc" or // doc/doctrees/faq.doctree
        hash.sha1(0, filesize) == "cabf489740e6cf929cc6641dc68caac9b7a402a1"    // doc/doctrees/config.doctree

}
