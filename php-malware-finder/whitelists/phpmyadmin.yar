import "hash"

private rule Phpmyadmin
{
    meta:
        generated = "2016-07-27T18:00:53.795037"

    condition:
        /* Phpmyadmin 4.0.0 */
        hash.sha1(0, filesize) == "9947802a97a9c265bdf5209a2b4b03e4897d3819" or // import.php
        hash.sha1(0, filesize) == "13b9bdea5990a2105c7438574e4935062c89f88d" or // libraries/DBQbe.class.php
        hash.sha1(0, filesize) == "4ca3a6ea8816dc3cddd460d99694bcc235c3705e" or // doc/setup.rst
        hash.sha1(0, filesize) == "55e152b410eca610f2dcdc54cd75f6335bf0d8cb" or // prefs_manage.php
        hash.sha1(0, filesize) == "027633c8a6f14355ad0a66b4a8d8b96bb90eb2d2" or // libraries/tcpdf/tcpdf.php
        hash.sha1(0, filesize) == "f75b5155e55cf69b83fdc046a4f70f1861fc7d3a" or // libraries/sqlparser.lib.php
        hash.sha1(0, filesize) == "fdfe4c742df3925616f07939d5cad3b932f97a50" or // libraries/database_interface.lib.php
        hash.sha1(0, filesize) == "7ba1fca4654dbcfce4ea289c1570e181cd86d28f" or // doc/doctrees/setup.doctree
        hash.sha1(0, filesize) == "4ca3a6ea8816dc3cddd460d99694bcc235c3705e" or // doc/html/_sources/setup.txt
        hash.sha1(0, filesize) == "2d162d8637f30da6e7c07d4d72eb310b98a67bb3" or // libraries/plugins/auth/AuthenticationCookie.class.php

        /* Phpmyadmin 4.0.1 */
        hash.sha1(0, filesize) == "285e32978c85283b3eb60dc8622376ff625b0863" or // import.php
        hash.sha1(0, filesize) == "9ee02b385fcc2bbfd7f135cea21eb25f26dbb31a" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.2 */
        hash.sha1(0, filesize) == "c8cc27ffb129d02f346e21dbe365c7c7d8e45e89" or // import.php
        hash.sha1(0, filesize) == "71adc462b0a212e23863b3423928ec98bec8934b" or // libraries/DBQbe.class.php
        hash.sha1(0, filesize) == "7857f155634e4837665f8d27579fbf866725d5f3" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.3 */
        hash.sha1(0, filesize) == "4360afbf0b092e2f1d9630eb6b6967c243d2b2c9" or // libraries/database_interface.lib.php
        hash.sha1(0, filesize) == "87b8fe7d28c2c0f71f28d76f86f9d2f36431ba70" or // doc/doctrees/setup.doctree
        hash.sha1(0, filesize) == "c4e4f20e324ebd00bb95a9e76bfe0c27852e7651" or // libraries/plugins/auth/AuthenticationCookie.class.php

        /* Phpmyadmin 4.0.4 */
        hash.sha1(0, filesize) == "3edc241b5ff6effc001181a84a25fba9b554282e" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.5 */
        hash.sha1(0, filesize) == "8a92831c458b2ccfd68f470d2852a0276208a383" or // import.php
        hash.sha1(0, filesize) == "78de4ed948310063e083264396faf1e4e9eab1ed" or // libraries/database_interface.lib.php
        hash.sha1(0, filesize) == "0f75a26e15014bda7ce92e98e1856aa3e45b1140" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.6 */
        hash.sha1(0, filesize) == "2cb0c93cafe9ed060dc3f2c8246e21b3ba6f055a" or // import.php
        hash.sha1(0, filesize) == "20b30953db8f4e75748c6e26aff9495dfda41181" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.7 */
        hash.sha1(0, filesize) == "437b19687a4a1f7f5acd2c05c3ab3aba02f1efa7" or // libraries/database_interface.lib.php
        hash.sha1(0, filesize) == "7051c9127d5188c9b38e0a39129fa563cf12d35f" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.8 */
        hash.sha1(0, filesize) == "9c7aba43bf2657426de0031932f9e692120afba5" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.9 */
        hash.sha1(0, filesize) == "34dddb060e39472f1ec13935fca3119dda880744" or // libraries/sqlparser.lib.php
        hash.sha1(0, filesize) == "830693d6d2aeb1079918af2efdcb097fa677d2cf" or // doc/doctrees/setup.doctree

        /* Phpmyadmin 4.0.10 */
        hash.sha1(0, filesize) == "7a4b5cc17045f6bc9332a26958200c34c3882f97" or // doc/setup.rst
        hash.sha1(0, filesize) == "0c64f07f7b870341821ac6146f5cd7ed582a2d0b" or // doc/doctrees/setup.doctree
        hash.sha1(0, filesize) == "7a4b5cc17045f6bc9332a26958200c34c3882f97" or // doc/html/_sources/setup.txt

        /* Phpmyadmin 4.5.3 */
        hash.sha1(0, filesize) == "0fbe71d58549f29cc3e81b756fe97162384b6511" or // libraries/plugins/auth/AuthenticationCookie.class.php
        hash.sha1(0, filesize) == "06f8260b4e0302f835aa5699e62a295a5942e558" or // libraries/server_variables.lib.php
        hash.sha1(0, filesize) == "b386a09aca019b66053ba7c891cd13609b43c247" or // libraries/server_privileges.lib.php 
        hash.sha1(0, filesize) == "df1fb0222a0f59cb8d828d67d1d83209b2cb2a2e" or // libraries/tbl_columns_definition_form.inc.php
        hash.sha1(0, filesize) == "d39e650c83f132d8d8a833dd9db0899e93d9f8c2" or // libraries/DatabaseInterface.class.php
        hash.sha1(0, filesize) == "54e8cd6ebfec8b917b6b8e3585b20f9bf6aa189b" or // libraries/Config.class.php
        hash.sha1(0, filesize) == "94209a3aa443025568d0845897d9409590b50ade" or // libraries/DBQbe.class.php
        hash.sha1(0, filesize) == "fd2d16a06ce1600f48b084f3ad3b6b414281ba8b" or // libraries/tcpdf/tcpdf.php
        hash.sha1(0, filesize) == "25da74af348f8afa75796d1bb1f58598bcbc4560" or // libraries/tcpdf/include/tcpdf_fonts.php
        hash.sha1(0, filesize) == "e8927cdc56f41106ae991766573753c8d0024868" or // libraries/tcpdf/include/tcpdf_static.php
        hash.sha1(0, filesize) == "357e6fa6dd90b04416dc768f6799e7750b0fedd3" or // libraries/Util.class.php
        hash.sha1(0, filesize) == "1bbb5361596c0df84bde3447e2410adaa85212bb" or // libraries/tbl_info.inc.php
        hash.sha1(0, filesize) == "0f8308e5973c5cda89965725b3782043d848dfcb" or // import.php
        hash.sha1(0, filesize) == "65e0b5f3ceae1edf5db287bfbb3cfccb18616bc6" or // prefs_manage.php
        hash.sha1(0, filesize) == "928cdc208fdbadd99b15141056cc127925e08cfa" or // doc/setup.rst
        hash.sha1(0, filesize) == "e92c303fecc093066dc36774f03af3667035e403" or // doc/doctrees/setup.doctree
        hash.sha1(0, filesize) == "928cdc208fdbadd99b15141056cc127925e08cfa" // doc/html/_sources/setup.txt
}
