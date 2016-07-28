import "hash"

private rule Drupal : Blog
{
    meta:
        generated = "2016-07-27T18:00:53.795037"

    condition:
        /* Drupal 4.0.0 */
        hash.sha1(0, filesize) == "afb55274b55f41a9b6933cc7c31c53a8b94ad1f8" or // includes/xmlrpc.inc

        /* Drupal 5.0 */
        hash.sha1(0, filesize) == "d0c845636f4b8863223c8cf702b269e487a91b6a" or // includes/common.inc
        hash.sha1(0, filesize) == "c3cd0e0eaf1fd7e2e5d41fac63d7065e9bd4327c" or // modules/node/node.module
        hash.sha1(0, filesize) == "6b3429750aae649ae70394a0be0c5957ad1e62b0" or // includes/locale.inc
        hash.sha1(0, filesize) == "c3529c439525f776aa6d8437741f8570d03dae9d" or // includes/unicode.inc
        hash.sha1(0, filesize) == "c6ca419676f14a5b7fa6a3c8719064e83f8680c4" or // includes/file.inc
        hash.sha1(0, filesize) == "c0161d4139b8eb2b59c6522acf339b5ec6f138ea" or // modules/system/system.module
        hash.sha1(0, filesize) == "e5a0c299937ac30ebe89eab9ce259b6db04531e4" or // includes/bootstrap.inc

        /* Drupal 5.1 */
        hash.sha1(0, filesize) == "b81bcd14215b5595c67421c009fc528a0047446e" or // modules/node/node.module
        hash.sha1(0, filesize) == "cb6e5be201590318759d1b2e073d6aeac8419ee5" or // modules/system/system.module

        /* Drupal 5.2 */
        hash.sha1(0, filesize) == "8ba05ae5681c8c83c35357bf9b371c3147f5905c" or // includes/common.inc
        hash.sha1(0, filesize) == "24facc881d1c3d914f97b228c03ad62efdfb05a0" or // modules/node/node.module
        hash.sha1(0, filesize) == "b3306c111b0cfe93d0e71929aa905ce63f2bb9c1" or // includes/locale.inc
        hash.sha1(0, filesize) == "998f31dde1afd4b0541f8d54b062309cb965d4d7" or // includes/unicode.inc
        hash.sha1(0, filesize) == "fb0416296610837cc361d39ebdab0eb5f4310e47" or // includes/file.inc
        hash.sha1(0, filesize) == "1b5196fae9c0dff68a5dd14f3e1025c5fae20146" or // modules/system/system.module
        hash.sha1(0, filesize) == "be4f6bbdcbb18cf04637ca0c57f63ea3c9954282" or // includes/bootstrap.inc

        /* Drupal 5.3 */
        hash.sha1(0, filesize) == "578e84aa652fcbe1c5befd887555955854229e5d" or // includes/common.inc
        hash.sha1(0, filesize) == "3aba588d6cbe99242465ccde649f92d796b1be80" or // modules/node/node.module
        hash.sha1(0, filesize) == "9b282e5fd0f4f2f4eaef359eb24e33490eb5428e" or // modules/system/system.module

        /* Drupal 5.4 */
        hash.sha1(0, filesize) == "0e47ece2adc768f75a20ecf3b94a796ccc2b30f5" or // modules/system/system.module
        hash.sha1(0, filesize) == "a059899823a8d8bfb89b7c63ed16a71885bcf5c9" or // includes/bootstrap.inc

        /* Drupal 5.5 */
        hash.sha1(0, filesize) == "ca845a4106de54907aaf08c35a9db90c41039721" or // modules/system/system.module

        /* Drupal 5.6 */
        hash.sha1(0, filesize) == "fbd087e8991d1e432a0a9fffb546fcdfa3c5ecc5" or // includes/common.inc
        hash.sha1(0, filesize) == "8863428e2b7b1493bd6d6579851a55bcf8dd71df" or // modules/node/node.module
        hash.sha1(0, filesize) == "849b9b16d2e435c5b4ad73e583c293c6beea96c5" or // includes/locale.inc
        hash.sha1(0, filesize) == "37de42e2a1e46206350460fac45534703f572467" or // includes/file.inc
        hash.sha1(0, filesize) == "6a8408f883f8fdef5f34d9a32f33c0359449b2ab" or // modules/system/system.module
        hash.sha1(0, filesize) == "a2f385c2a68598b2c1c2f1dc20262eb22e1d2fd6" or // modules/system/system.install
        hash.sha1(0, filesize) == "1f8ec2f60cdbb93c131e8f36902b96980d33c776" or // includes/bootstrap.inc

        /* Drupal 5.7 */
        hash.sha1(0, filesize) == "68c6740ba2ca12543535b81ef4fd18510d563a28" or // includes/common.inc
        hash.sha1(0, filesize) == "9599f652ae52a33e2cc44cd284aca8db27e30740" or // modules/system/system.module
        hash.sha1(0, filesize) == "a0af4165e9a0c76b81054aa69894024539c2f85c" or // modules/system/system.install

        /* Drupal 5.8 */
        hash.sha1(0, filesize) == "a6cf873557689f4b6c83c5f33a46c2735cfe2ecd" or // includes/common.inc
        hash.sha1(0, filesize) == "af14f62d5afebcaebd958a8896c516bd18dc0844" or // modules/node/node.module
        hash.sha1(0, filesize) == "6d20b935e3fa50821ffa512d58932ede412ac9c7" or // includes/file.inc
        hash.sha1(0, filesize) == "9edbdfa54857da46a605289c974919a5ceef6dcc" or // modules/system/system.module
        hash.sha1(0, filesize) == "8688b46f0860caf2794353e7887e0f229db7caa6" or // modules/system/system.install

        /* Drupal 5.9 */
        hash.sha1(0, filesize) == "81cd6c06add63110c30bf7022366d5ce634b69ca" or // modules/node/node.module
        hash.sha1(0, filesize) == "f915ed706ac46e386b21af46bca2058242c73539" or // modules/system/system.module

        /* Drupal 5.10 */
        hash.sha1(0, filesize) == "17dc0b9a196d7df4b03f1ad620eacd1d4e336543" or // includes/file.inc
        hash.sha1(0, filesize) == "1fc44b4075519d39cdb56e2f506a451be7599c27" or // modules/system/system.module

        /* Drupal 5.11 */
        hash.sha1(0, filesize) == "6c40f2dc596038e986abb49cb0d6177e62475de7" or // modules/node/node.module
        hash.sha1(0, filesize) == "42396974c8592b11eab61b77c968c640d6ad053a" or // includes/file.inc
        hash.sha1(0, filesize) == "73f95e256e3234f32c03808234a5e412bc831ce5" or // modules/system/system.module
        hash.sha1(0, filesize) == "5e25d3f606eaf7cb9593cc2713a87f47b8d5d330" or // includes/bootstrap.inc

        /* Drupal 5.12 */
        hash.sha1(0, filesize) == "4bdf2b305b0ab4e49a6bcfb90adcaee38ab22372" or // modules/system/system.module
        hash.sha1(0, filesize) == "280037c3481007464556293e18ccb353534925d7" or // includes/bootstrap.inc

        /* Drupal 5.13 */
        hash.sha1(0, filesize) == "43013bfd0c762f9b8d778b2b7d8240fb363a9403" or // modules/system/system.module
        hash.sha1(0, filesize) == "1b57b5d0522d716b180748d6267990c583972a60" or // includes/bootstrap.inc

        /* Drupal 5.14 */
        hash.sha1(0, filesize) == "8a69a32f6592491577f0ab2d47314b3a26639703" or // modules/system/system.module

        /* Drupal 5.15 */
        hash.sha1(0, filesize) == "007a8471eaf71acee38c9573ea1c8deeb9edd65b" or // includes/common.inc
        hash.sha1(0, filesize) == "9cbe16556934c798e414633f1255d4a8703a841f" or // modules/node/node.module
        hash.sha1(0, filesize) == "9b48e3a16f6905a323803f5b3b8392ed55f8247a" or // modules/system/system.module
        hash.sha1(0, filesize) == "db6dde1e073356bec12ad19bfa435888195de344" or // includes/bootstrap.inc

        /* Drupal 5.16 */
        hash.sha1(0, filesize) == "6336e41bcc71e037390dd6638905138f79ff6279" or // includes/common.inc
        hash.sha1(0, filesize) == "064b443a2ffb20310f439a0f64144badf8234d14" or // includes/file.inc
        hash.sha1(0, filesize) == "f8857943b1b3e2e36d2d384e89500ec49b4d1d2b" or // modules/system/system.module

        /* Drupal 5.17 */
        hash.sha1(0, filesize) == "5056a43a1e85dd7ffa9c4bc087d9d38fc5e6c67a" or // includes/common.inc
        hash.sha1(0, filesize) == "b293a4b8eab7e49663ab5e6b6876edb9148a54d7" or // modules/system/system.module
        hash.sha1(0, filesize) == "fcfcf61bebd2c39d32d7fd3b6974deab1e86c7d8" or // modules/system/system.install
        hash.sha1(0, filesize) == "e8978e75a6126d3ba86bc2d52b4ed74d58080436" or // includes/bootstrap.inc

        /* Drupal 5.18 */
        hash.sha1(0, filesize) == "42d94756f6b710be4fa6943dc95f8531bcd7e4ee" or // includes/common.inc
        hash.sha1(0, filesize) == "3b0b20f84d040f01cec68262c7f3ada25699d635" or // modules/system/system.module

        /* Drupal 5.19 */
        hash.sha1(0, filesize) == "7e347a2ae11d1d89c4a09d76036e48756f2600e2" or // modules/system/system.module

        /* Drupal 5.20 */
        hash.sha1(0, filesize) == "03173694bbab3548415b6b67778468eeb6d28bf3" or // includes/common.inc
        hash.sha1(0, filesize) == "f1951378bc52db77248635b038ad0d483b003936" or // modules/system/system.module

        /* Drupal 5.21 */
        hash.sha1(0, filesize) == "c4f26ef7020074c10c71dbb23b30b2cb2d20d15e" or // modules/system/system.module

        /* Drupal 5.22 */
        hash.sha1(0, filesize) == "38987668f8ce77391211bcb6574aeac35b14a24a" or // includes/common.inc
        hash.sha1(0, filesize) == "cf9d30b2bd06536e9c120a21bfe3312dd1430c95" or // includes/locale.inc
        hash.sha1(0, filesize) == "b0eb18f4576af3fc446b78b04eaca1e39d24b91d" or // modules/system/system.module

        /* Drupal 5.23 */
        hash.sha1(0, filesize) == "4542182800018704d7454501c1937425204efac1" or // modules/system/system.module

        /* Drupal 6.0 */
        hash.sha1(0, filesize) == "3141d8b9b717e0d189b4f92aa640d1dc5721ec7a" or // includes/common.inc
        hash.sha1(0, filesize) == "44b551920fcf42bd135625c6eb7e58bebc0ccf69" or // modules/node/node.module
        hash.sha1(0, filesize) == "3f049cd18e2669df594798a6d36e7cbd7ecfb857" or // includes/locale.inc
        hash.sha1(0, filesize) == "38b7434e2f3fac5da0f53f9122ef522bf1a674bc" or // includes/unicode.inc
        hash.sha1(0, filesize) == "7f64ca7570fad903456e861a3c35084aeef0b6da" or // includes/file.inc
        hash.sha1(0, filesize) == "db83de63b4edd7de1f77b8f75a2b25cbfd317dc6" or // modules/system/system.install
        hash.sha1(0, filesize) == "5dddadcd03f676cbb7462c5f889a023627700e86" or // includes/bootstrap.inc

        /* Drupal 6.1 */
        hash.sha1(0, filesize) == "053772831f37c405c01f5526f22340e7f0120daa" or // includes/common.inc
        hash.sha1(0, filesize) == "f78bba4a52c32f27a8364ffd30a4c1b7372483ae" or // modules/node/node.module

        /* Drupal 6.2 */
        hash.sha1(0, filesize) == "09a3fafaa05ef8b5425781aef4cffa78ac23160b" or // includes/common.inc
        hash.sha1(0, filesize) == "2079867cb7290b0d8e083985580b95bd567c9c7b" or // modules/node/node.module

        /* Drupal 6.3 */
        hash.sha1(0, filesize) == "58c50c0874ed69e8fce88cf7571de1accad77f50" or // includes/common.inc
        hash.sha1(0, filesize) == "edcc4f031db96f1cd6270b748e49478315ad6d5a" or // modules/node/node.module
        hash.sha1(0, filesize) == "5fae0ce3d0a230f070586e5b74ce07212a56ce49" or // includes/locale.inc
        hash.sha1(0, filesize) == "b9f30de42dcbfd0f5bfb86648e4680fcbe1926be" or // includes/file.inc
        hash.sha1(0, filesize) == "b8cebbfcd57c42ce79154977d16d1f21a0cbd7d5" or // modules/system/system.install
        hash.sha1(0, filesize) == "8a5fbd9ffda4292290868adc44990c1879a90a38" or // includes/bootstrap.inc

        /* Drupal 6.4 */
        hash.sha1(0, filesize) == "fd095f8d7442f8715eb970d0d64f8213de1c2994" or // includes/common.inc
        hash.sha1(0, filesize) == "10bfc446415bbb864352b0bb433d238bcfa707af" or // includes/file.inc

        /* Drupal 6.5 */
        hash.sha1(0, filesize) == "ca009d24b48e27765920ac9d37c5670626f138b9" or // includes/common.inc
        hash.sha1(0, filesize) == "406717acb5a9c590e5a3099cace595b784c07924" or // includes/locale.inc
        hash.sha1(0, filesize) == "69c618939291ae41b64a89ce710ecbbbac5d110a" or // includes/file.inc
        hash.sha1(0, filesize) == "56f37efdecc1a211a019533725d61c138f88b0f1" or // modules/system/system.install
        hash.sha1(0, filesize) == "50d685d2ff7ba3a95bb19ed9ca3044100b5f7777" or // includes/bootstrap.inc

        /* Drupal 6.6 */
        hash.sha1(0, filesize) == "7ee9f1c71e3d6649dea636ddb49297f4a6e9d3e9" or // includes/common.inc
        hash.sha1(0, filesize) == "62c3a3784824d2d10e5f3d90f34cfcb7c7b30d89" or // includes/file.inc
        hash.sha1(0, filesize) == "c2521c9e7ad874c0c638577e94a2452836ed11a3" or // includes/bootstrap.inc

        /* Drupal 6.7 */
        hash.sha1(0, filesize) == "5553202f013bd4f99ae28bc0edcd4c6b16945655" or // includes/common.inc
        hash.sha1(0, filesize) == "6f2fc739e68913e1f326e7447e31e65d8bb8f011" or // includes/locale.inc
        hash.sha1(0, filesize) == "3b84ad29cf81bc7eb42c1be2b3642c0323894811" or // includes/bootstrap.inc

        /* Drupal 6.8 */
        hash.sha1(0, filesize) == "89ff4d7b988bcf9550a3033d1d5b1ea0d354baba" or // includes/common.inc

        /* Drupal 6.9 */
        hash.sha1(0, filesize) == "f339cebfcbaea40a08d485b8ffe588b027f65ddf" or // includes/common.inc
        hash.sha1(0, filesize) == "0dc2cd9a0d3be21a208e790e872ce4b96ae66879" or // modules/node/node.module
        hash.sha1(0, filesize) == "96e38ce56bf9e01b43f79c11fad0e1efd645106c" or // includes/locale.inc
        hash.sha1(0, filesize) == "7551dd87d166e312f58e851b5281cc5f3804558f" or // modules/system/system.install
        hash.sha1(0, filesize) == "3b24c515274a259f3a750bce6f95a8e33e6b45ab" or // includes/bootstrap.inc

        /* Drupal 6.10 */
        hash.sha1(0, filesize) == "90e09dc0a5817c4c519d99c23d081d69c27487ae" or // includes/common.inc
        hash.sha1(0, filesize) == "fa70d0fa88582210df0dd59b8a9ded45b0e6684c" or // modules/node/node.module
        hash.sha1(0, filesize) == "b41bb675c6a8e1ea7655efa84314dba7a72be098" or // modules/system/system.install
        hash.sha1(0, filesize) == "9aca18f1e1c587794e7a757bafad948ab3f23154" or // includes/bootstrap.inc

        /* Drupal 6.11 */
        hash.sha1(0, filesize) == "12d787ac3d26974abae0d82f71f459dddd67e7d7" or // includes/common.inc
        hash.sha1(0, filesize) == "9ef040fcd846dcf36fd093047d0127db445c16ce" or // includes/locale.inc
        hash.sha1(0, filesize) == "cdab165fd7d26ddeadf92ca0f0e7f4ce82e97da5" or // includes/file.inc
        hash.sha1(0, filesize) == "2182dcced1d044abc9275c6cb6f5881725b29393" or // modules/system/system.install
        hash.sha1(0, filesize) == "1ac406abc0813d6e0d7f4b29842e3478d659079d" or // includes/bootstrap.inc

        /* Drupal 6.12 */
        hash.sha1(0, filesize) == "1f3b73d4cd2ba55d8f96249e9b6775bf418fcfb9" or // includes/common.inc

        /* Drupal 6.13 */
        hash.sha1(0, filesize) == "02b74a6e20dafe2e04e42f295e268fe3bab7df7c" or // includes/common.inc
        hash.sha1(0, filesize) == "07ac7c9c6f9846280c7784ac78cfc901369578a2" or // includes/locale.inc
        hash.sha1(0, filesize) == "cf531282715ea3ec22130c1beeddaf9d39ab3bc4" or // includes/file.inc
        hash.sha1(0, filesize) == "d66669fd525f023f03cb407817b98a0cbb5a4b65" or // modules/system/system.install

        /* Drupal 6.14 */
        hash.sha1(0, filesize) == "d258d8dfae921e0c84d5228db17f2071da4cc245" or // includes/common.inc
        hash.sha1(0, filesize) == "3f350c0a96b05970eed2bb80b678b55b911840cc" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "943f94842d305cb2157e699354fff6efe0bb04d9" or // modules/system/system.install
        hash.sha1(0, filesize) == "1b102cf14c8c2059c5ef8498403a1f12ecd4e45d" or // includes/file.inc

        /* Drupal 6.15 */
        hash.sha1(0, filesize) == "748018319a945fca89a42be51e4f2f567aee59a7" or // includes/common.inc
        hash.sha1(0, filesize) == "7824be7e2175958f0bce64885fd9c10c00a50c5f" or // modules/system/system.install

        /* Drupal 6.16 */
        hash.sha1(0, filesize) == "4dc5f0aa26ce50e53f2d5782c0baa53bc14049f1" or // includes/common.inc
        hash.sha1(0, filesize) == "66167afbb08bf7d521fec9ce7583c7f78e57667d" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "a3f9b7d84b4de203b8da42a55715932a639c5157" or // modules/system/system.install
        hash.sha1(0, filesize) == "1f96e7a2ea49c23469e868b99797d82b73854a70" or // includes/file.inc

        /* Drupal 6.17 */
        hash.sha1(0, filesize) == "787a9feab6ab8de10e9638dd778d577f8acba861" or // includes/common.inc
        hash.sha1(0, filesize) == "a26798f37ae6409850d3145fa09e486ae55ecdb2" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "ec6a944bb7bd428e0dfe55451881affcced17ebf" or // modules/system/system.install
        hash.sha1(0, filesize) == "a2970fba917171206bc5ac171f0029ab483d767b" or // includes/file.inc

        /* Drupal 6.19 */
        hash.sha1(0, filesize) == "569315098bd14559b8871deb1e549648a2ce9699" or // includes/common.inc
        hash.sha1(0, filesize) == "a05623009569efef0c8f17d70878cc81db4f6cfb" or // includes/unicode.inc
        hash.sha1(0, filesize) == "dafbcf35f1413501b0ac2f8698abb3b9b7ee00b7" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "21c1f69ef707db7bcb8542102ebc329a3ca47fb3" or // modules/system/system.install
        hash.sha1(0, filesize) == "51d0c0ad6c24e029ae2f0e969c5ae43896b0f75d" or // includes/file.inc

        /* Drupal 6.20 */
        hash.sha1(0, filesize) == "4f8f3ea96f91c624e00089ba4fb189a4e629f3d6" or // includes/common.inc
        hash.sha1(0, filesize) == "b84fe799ed930c7d9692fc1368dc0d1adcc4259c" or // includes/unicode.inc
        hash.sha1(0, filesize) == "489e7eb0d0bec65ed37621f1a35ae6c92157fa89" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "ee440fd00b949944b02899c3e8cd88101604cc41" or // modules/system/system.install
        hash.sha1(0, filesize) == "a29414e1b97287db2bdcdbc090f1a977982ee4ec" or // includes/file.inc

        /* Drupal 6.21 */
        hash.sha1(0, filesize) == "819187a58f986db9b4e9a69ffd90aded2488170f" or // includes/common.inc
        hash.sha1(0, filesize) == "a4558ebbc57e126d2932f0eafa14d39b5d55e53f" or // includes/unicode.inc
        hash.sha1(0, filesize) == "921327d4956b3d0f804dbc040b3efd8bd7ee4e91" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "71a7e26f095801a2f976dbaf264edcc648c62021" or // modules/system/system.install
        hash.sha1(0, filesize) == "5600fb7cc4286479cd2f87a95fa64af89e72e5f5" or // includes/file.inc

        /* Drupal 6.22 */
        hash.sha1(0, filesize) == "92428ddd34c0a66353457b984bf313871bc918a2" or // includes/common.inc
        hash.sha1(0, filesize) == "251d99f71c2bfabab5eceb140f9206615aef75e8" or // includes/unicode.inc
        hash.sha1(0, filesize) == "72d69d2a89c3e19845fde2245c38a1493a366778" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "c21e203f417922d4e0e8c0e6ab92643959c4c682" or // modules/system/system.install
        hash.sha1(0, filesize) == "5bab679e45a489c2475857e8b60a2c1358b1e01e" or // includes/file.inc

        /* Drupal 6.24 */
        hash.sha1(0, filesize) == "cb5eed9225197d74627e2fce0dd4458f337945e2" or // includes/common.inc
        hash.sha1(0, filesize) == "bfa39d2d7ed0d4fd9008b43d90ee911d309088fc" or // includes/unicode.inc
        hash.sha1(0, filesize) == "4a5a4f3582f1390506e0b246ae7665afe0e942ac" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "bf4964ccb3f3197e0ced30e8eb7ad18f46957bc2" or // includes/file.inc

        /* Drupal 6.25 */
        hash.sha1(0, filesize) == "26c3faffe7f4b8fdc348fce2c9bbc9b223b81dce" or // includes/common.inc

        /* Drupal 6.26 */
        hash.sha1(0, filesize) == "2a58e76f7ab7f1e7829abe6068d141ecdf1b3c3a" or // includes/common.inc

        /* Drupal 6.27 */
        hash.sha1(0, filesize) == "4e9ba19ea5026aa3734018af4cb24a15e311192a" or // includes/file.inc

        /* Drupal 6.28 */
        hash.sha1(0, filesize) == "3d70e328dc48eb4f45220bfee06ccce798539045" or // includes/common.inc
        hash.sha1(0, filesize) == "267f996e1a6d69a40b0af5d1690690d315f3cbe5" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "65ce711207491b8973d81a683c1a01951c19ddc9" or // modules/system/system.install
        hash.sha1(0, filesize) == "9a160015df1fdcbde1f60315a986faa71248f48c" or // includes/file.inc

        /* Drupal 6.29 */
        hash.sha1(0, filesize) == "69416d0d452c26cfb737c19b7110291b77776d40" or // includes/common.inc
        hash.sha1(0, filesize) == "d1f0c64192e579f45605d2a37c69b2aad08a3eb1" or // modules/system/system.install
        hash.sha1(0, filesize) == "d622100a160c7b541d707dae5ae9e5a783dfe5e0" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "0e2fe41483ad9c3fe58c79c990d6fd035fcf5326" or // includes/file.inc

        /* Drupal 6.30 */
        hash.sha1(0, filesize) == "3576cf648e593b8e64037392b6534e3b39a8d191" or // includes/common.inc
        hash.sha1(0, filesize) == "d8289be07c1eac2c3625dcff7325328d9f8fa0a3" or // modules/system/system.install

        /* Drupal 6.32 */
        hash.sha1(0, filesize) == "f7e604c51c1027dfe05aa153f981ba827a977228" or // includes/bootstrap.inc
        hash.sha1(0, filesize) == "4bc50419a4b98f3699f47ccf4aebc3e7538cd545" or // includes/file.inc

        /* Drupal 6.35 */
        hash.sha1(0, filesize) == "a91d655da76ecba1fe4e5c3229d04201d158d376" or // includes/common.inc
        hash.sha1(0, filesize) == "447a6f3cc0c392fb7d36e9443f272ed167ab19bd" or // includes/bootstrap.inc

        /* Drupal 6.38 */
        hash.sha1(0, filesize) == "a316f9ccde13a0f0037af72e1107f65e7f9b728b" or // includes/common.inc
        hash.sha1(0, filesize) == "5f5fb0e3341c34e0c996c8d32c071c0300ca0871" or // modules/system/system.install
        hash.sha1(0, filesize) == "24d09773c16f1b93b8c7d7832433450ad3a76118" or // includes/file.inc
        hash.sha1(0, filesize) == "324b03f7cd54759ba507253b90634dec69c70dd9" or // includes/bootstrap.inc

        /* Drupal 7.0 */
        hash.sha1(0, filesize) == "a08159b9d4f5e7381c3e79f4f106e1dccd477c91" or // includes/common.inc
        hash.sha1(0, filesize) == "6e5bbb75497c41215434585fa79477372c439333" or // modules/simpletest/simpletest.install
        hash.sha1(0, filesize) == "c87c6ec968c6ea09be0fa77da8dbe0be1c902188" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "2630eb13eecea786c9c1ab96162c7ef0e18adc0a" or // modules/simpletest/tests/upgrade/drupal-6.filled.database.php
        hash.sha1(0, filesize) == "f49132348b7fd3c841c298c2af2d0fbefb0157d7" or // modules/search/search.module
        hash.sha1(0, filesize) == "43a953e8a353974045b1affc25e8bcf0a80e4a1f" or // modules/simpletest/tests/upgrade/drupal-6.bare.database.php
        hash.sha1(0, filesize) == "01020dd2d335e2f938121907af16a5556709ea00" or // includes/menu.inc
        hash.sha1(0, filesize) == "315b39b038f8cb7c110efdfcb63eb7377d1f0dcc" or // modules/system/system.mail.inc
        hash.sha1(0, filesize) == "c5a0fb311be6b326881ba201d47ee5a024f68ebc" or // modules/system/system.module
        hash.sha1(0, filesize) == "e67b52699e0e14293dd9156d8e10a9590eba8ea9" or // modules/system/system.install
        hash.sha1(0, filesize) == "5cd0c73f15eb542f998013af7d0da656b0bd387d" or // modules/system/system.tar.inc
        hash.sha1(0, filesize) == "717cf88349ea103d9f601df92711694cc7263a86" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.1 */
        hash.sha1(0, filesize) == "b6678c7d44a0b58d7f1c17764b27968bb307b17a" or // includes/common.inc
        hash.sha1(0, filesize) == "d9c1391e647b4d50c2434815fe6bef33c9db73d4" or // modules/simpletest/simpletest.install
        hash.sha1(0, filesize) == "8ee9d7f48410b692db1e9007a204ad0b9911f3ca" or // modules/search/search.module
        hash.sha1(0, filesize) == "567b1a1ba62ecbadb7e90d4fbb5821525881b529" or // modules/simpletest/tests/upgrade/drupal-6.filled.database.php
        hash.sha1(0, filesize) == "270c09af5a747d366e9716ed67f3671cd53fcb87" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "f4b8b176310bd4b1d3a92b7c70638bc5ebfbe01b" or // modules/simpletest/tests/upgrade/drupal-6.bare.database.php
        hash.sha1(0, filesize) == "3d1484f559a238abe5ac83e7e38c18aaff511c0b" or // includes/menu.inc
        hash.sha1(0, filesize) == "1fd4d402cadb2de64cb7d8e594a309fad4b19cd8" or // modules/system/system.mail.inc
        hash.sha1(0, filesize) == "4c64cec74c8013b41ae2743eb2f4c2e31b761395" or // modules/system/system.module
        hash.sha1(0, filesize) == "e81f62db3341cd0498d8fd327a7f9da76fe4a075" or // modules/system/system.install
        hash.sha1(0, filesize) == "6a745fc90e67478ed82ad7435aa84f209d24c88b" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.2 */
        hash.sha1(0, filesize) == "3c81fb9e5b3f3429ae951705622d354688ec0328" or // includes/common.inc
        hash.sha1(0, filesize) == "87cf0691ac20fe6064d5c7ab32c1610a6c0517ac" or // modules/simpletest/simpletest.install
        hash.sha1(0, filesize) == "a491ee5f60310e4c02403c1c130c78282105c27d" or // modules/search/search.module
        hash.sha1(0, filesize) == "6dd6a120dd0e301a76a3a83da2cb8f64cba8f5a1" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "96b157e64eefabf2766bb946676120a97eba10b1" or // includes/menu.inc
        hash.sha1(0, filesize) == "0f7d80572bf94c34b570ad410416f7763ca4161e" or // modules/system/system.mail.inc
        hash.sha1(0, filesize) == "5c602fa8bd6f466559df97660c5f43f2846e9801" or // modules/system/system.module
        hash.sha1(0, filesize) == "56866b187af8346a904cca6851e498599c1ea9c6" or // modules/system/system.install
        hash.sha1(0, filesize) == "4d63ad98a7508266aba8461a7678a6af24d5be46" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.4 */
        hash.sha1(0, filesize) == "67d459dac55b7c39f854adcc37e2ce95008a01bb" or // includes/common.inc
        hash.sha1(0, filesize) == "fa5741818eeeb2fe41ae3ac98632c269d97e90e7" or // modules/simpletest/simpletest.install
        hash.sha1(0, filesize) == "b7d038d888fd873fe6f9bc6ee3101b621e1c67c7" or // modules/system/system.module
        hash.sha1(0, filesize) == "0b5b8272a6079c032cbe10d4cc4f489a632c4458" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.6 */
        hash.sha1(0, filesize) == "901b4edbc4b48f94938b07af7f26f240beb3f2dd" or // includes/common.inc
        hash.sha1(0, filesize) == "240cf969149d43b8f9156037a73fb333023010df" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "f67c2d9a24d867d29fc67b044e38e1f8637400fe" or // includes/menu.inc
        hash.sha1(0, filesize) == "9cc1edbccd03d36f1f7e7bc88a65a2ab70c1c65d" or // modules/system/system.module
        hash.sha1(0, filesize) == "dc6641807f3336b140bfa43b7167af9d2e5e5809" or // modules/system/system.install

        /* Drupal 7.8 */
        hash.sha1(0, filesize) == "d11e79bf918a7763c74768fddd7d2918592b7e8d" or // includes/common.inc
        hash.sha1(0, filesize) == "776b2bcf9abcb553dcb9db4b6a6792fa30f08e73" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "c0ae915d505f8ea331a69e8aa50b77ce557f161e" or // includes/menu.inc
        hash.sha1(0, filesize) == "d9d463849928eb100269e3b51b1790d140026cbe" or // modules/system/system.module
        hash.sha1(0, filesize) == "c393fd9acf8346159946dbaab29daee344487fce" or // modules/system/system.install
        hash.sha1(0, filesize) == "5bf39d8d13626936aef396f30c7e438e5d7e678f" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.9 */
        hash.sha1(0, filesize) == "3dc9d3dc15c048efff0dae58627f6f54c8398ce6" or // includes/common.inc
        hash.sha1(0, filesize) == "1aa51db389bfda3daec9853bdbbcdffd867ffafc" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "79acd01f2ff44e2c36022ad414e2de06abcc12d9" or // includes/menu.inc
        hash.sha1(0, filesize) == "bb2857f935aeb1f45138883b607ead68d01c19d6" or // modules/system/system.module
        hash.sha1(0, filesize) == "b9f06619439679b9b1b36736ae25789ac2af2c0f" or // modules/system/system.install
        hash.sha1(0, filesize) == "4a44b9f985524c6748d8f8c5e4ffb51e274cd1da" or // modules/system/system.tar.inc
        hash.sha1(0, filesize) == "7cd0c78cca0a11206c7d8ef46f4f27d4571b6934" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.10 */
        hash.sha1(0, filesize) == "1ad4246199d09a994595b6b5a1e750b25587a464" or // includes/common.inc
        hash.sha1(0, filesize) == "782353a41cb49386e6dead3540ecbe8810227721" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "d6d3f0ce521c284e2116bd6b3c2fbfe58b8c6fc1" or // modules/system/system.install
        hash.sha1(0, filesize) == "d0a00f0f43cbf5ca8b82653f64c1c4c8a3c171d0" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.12 */
        hash.sha1(0, filesize) == "7728aaad89f4b2b7048e45aca552d6e87b490246" or // includes/common.inc
        hash.sha1(0, filesize) == "5d1edcb62a1238f0c4e8da2bbc67c1de8f2cf607" or // modules/search/search.module
        hash.sha1(0, filesize) == "5e631f496b3c991347718bc8ba101719580a6b84" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "f2586fdc686127708278384f13cec4ff558b20f8" or // includes/menu.inc
        hash.sha1(0, filesize) == "5f9e230c175ff571f3527de3c65f81b8059bcfda" or // modules/system/system.mail.inc
        hash.sha1(0, filesize) == "ede11f68fe46a87afcb14460ef43ed5ec7c0aa5a" or // modules/system/system.module
        hash.sha1(0, filesize) == "79be2c89fccb108f07d26229d52f04a091015115" or // modules/system/system.install
        hash.sha1(0, filesize) == "ecf9d642cc858780fec4219f3536740bf1e3b083" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.14 */
        hash.sha1(0, filesize) == "a2bcd5ff18895a51baadc93845c46db845a462e5" or // includes/common.inc
        hash.sha1(0, filesize) == "b9f3ca1efb85056ab2974aa327608a314ca480b4" or // modules/search/search.module
        hash.sha1(0, filesize) == "0d7a6f151407e1dd3ebe1a9661be5b8bc6708040" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "e09b42243aebaac906ee6aa45517c56290352034" or // includes/menu.inc
        hash.sha1(0, filesize) == "516263b5669ec5355a65744ba09aeb43166398d8" or // modules/system/system.module
        hash.sha1(0, filesize) == "debc10a301f5cd888b7a7f15d66d293d1ddad4aa" or // modules/system/system.install
        hash.sha1(0, filesize) == "2bfea940df3434a95184f6399e7191c7735fc014" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.15 */
        hash.sha1(0, filesize) == "4fc58f12950b1a9db5d347c52eb0e0183e1d104e" or // includes/common.inc
        hash.sha1(0, filesize) == "b9f63efe4e1cedbca4d92cfa9c5964edf938da6a" or // modules/system/system.install
        hash.sha1(0, filesize) == "a6376fa55cf42335c0c6cc611583031467841fa6" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.17 */
        hash.sha1(0, filesize) == "b82f9fd1b9dd92c8d0362edae86bfad55994110c" or // includes/common.inc
        hash.sha1(0, filesize) == "056234dc43df263c0b03d5be97e24385e304fe14" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "94339fd2074f7e71cdc1726ca7457e08a5dd1fda" or // includes/menu.inc
        hash.sha1(0, filesize) == "dfc5a49b2904e023e91370604383b19b3730d719" or // modules/system/system.module
        hash.sha1(0, filesize) == "2818972b8f7dcafa197d8af4a413a9d629990d6c" or // modules/system/system.install
        hash.sha1(0, filesize) == "586492ff24412fec62d2269ba8321703f526cdaa" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.22 */
        hash.sha1(0, filesize) == "82fa7c1d59b0c9b7f3311df4e7ac8ca21d783742" or // includes/common.inc
        hash.sha1(0, filesize) == "5ff70af738f8f439b7a27744548a35a0539834a3" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "343c688da90dfe7f4488cfc59e84777b45d378a4" or // includes/menu.inc
        hash.sha1(0, filesize) == "243026bcb2a774926b7863576cf347e1a92f5ad4" or // modules/system/system.module
        hash.sha1(0, filesize) == "178aee60052d0e24f0e42dfd24c11f3ed431d64c" or // modules/system/system.install
        hash.sha1(0, filesize) == "15ed7c799684a4af1d19f06d4e2f96892c4740f9" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.23 */
        hash.sha1(0, filesize) == "5f7076b3ac9616ee1db0904bbdcc7c5977b81729" or // includes/common.inc
        hash.sha1(0, filesize) == "07f0c594b975862d25a75272b703a86ad0c0769e" or // modules/simpletest/simpletest.install
        hash.sha1(0, filesize) == "bd6d316f39a406f6f83e6e9265e7772c7ce2ae99" or // modules/search/search.module
        hash.sha1(0, filesize) == "d3f207283cfa4afeff3193ebf446d75302f71976" or // includes/menu.inc
        hash.sha1(0, filesize) == "548126402fdd5b0777b23bbdc1059fbcd0537c7a" or // modules/system/system.install

        /* Drupal 7.24 */
        hash.sha1(0, filesize) == "a2dbe0e5fcb885cb5529d79961d7031385650178" or // includes/common.inc
        hash.sha1(0, filesize) == "eb1e40f64cd2a4bddd4683201daa668c239c83e6" or // modules/system/system.install

        /* Drupal 7.25 */
        hash.sha1(0, filesize) == "e9139bea663d2b8f1b05f19284e03d34d07d8374" or // includes/common.inc
        hash.sha1(0, filesize) == "1a6fe004b899c2c69f460ff9379fc84cb7f7d84b" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "1a6eb0f44f4711dfd81fb330ea0ce84fb8fed5be" or // includes/menu.inc
        hash.sha1(0, filesize) == "ed1536da93041018bb8c8ad4caec99e4fb8d3434" or // modules/system/system.mail.inc
        hash.sha1(0, filesize) == "3305b10eca2d8cb1fdd5e03c05760ed2d564132b" or // modules/system/system.module
        hash.sha1(0, filesize) == "05086f5de9e939826f938bfd0317f3a995da8cc1" or // modules/system/system.install
        hash.sha1(0, filesize) == "d408c5b00a59645c1d6e9df3d80f2e3e32c1f6da" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.27 */
        hash.sha1(0, filesize) == "f14b12e51e2ce67b3c7e27ec1eb354c4f6e31950" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.28 */
        hash.sha1(0, filesize) == "77bbb3d3fe0ed0676953dfdae9ed0f517e081045" or // includes/common.inc
        hash.sha1(0, filesize) == "1d471d104ca5cf95ecab7c8050750877376abe3e" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "b4ed63404630c966c32b64c7b440cceddd792ff3" or // includes/menu.inc
        hash.sha1(0, filesize) == "3ca239b4bf83a21d860b99a0f00ff179febeeff6" or // modules/system/system.module
        hash.sha1(0, filesize) == "d80b043a8488ffcc221f2d614f4afe87758e96e7" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.30 */
        hash.sha1(0, filesize) == "7c6098dbe80be0e39c3634ef7707fcf0a361c0cf" or // includes/common.inc
        hash.sha1(0, filesize) == "1da6e8f2f1f24791f3d7e0e78d4ec5e7ca5214c8" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "1a5c25ea2b6f1ec8b9c7be84bf8a903bbe3b3119" or // modules/system/system.module
        hash.sha1(0, filesize) == "7b27105bd91e5e91486edef47fa6b7384714d89c" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.33 */
        hash.sha1(0, filesize) == "06346a81c7cd991dcae3413f4c914a44f3d1b943" or // includes/common.inc
        hash.sha1(0, filesize) == "dea49a391a8b0586270114c5d383e325c060a845" or // modules/system/system.admin.inc
        hash.sha1(0, filesize) == "21f282000b12614fe7c37ab5704038769f9ce521" or // includes/menu.inc
        hash.sha1(0, filesize) == "5e06ca00f3d0863d99e45d32cf14cf7b7de52522" or // modules/system/system.module

        /* Drupal 7.35 */
        hash.sha1(0, filesize) == "58e7db3113ec76fa75132447ce42655d46cdfb20" or // includes/common.inc

        /* Drupal 7.36 */
        hash.sha1(0, filesize) == "28ffd68a69f59114c321efe5b5a52451d4605eed" or // includes/common.inc
        hash.sha1(0, filesize) == "af0cc3daa2b6db0292129167023c661da4ad548d" or // modules/simpletest/tests/image.test
        hash.sha1(0, filesize) == "6982f0ce106fc787b0e0d7a480dd31def06ff64b" or // includes/menu.inc
        hash.sha1(0, filesize) == "496cccbbe852c98df59d5fa334d248008cec7a74" or // modules/system/system.module
        hash.sha1(0, filesize) == "5443c0b6219aff501b98e1a37b9dcec984b127e3" or // modules/system/system.install
        hash.sha1(0, filesize) == "39242389c1e22918c8dc4791c8280daa68341875" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.37 */
        hash.sha1(0, filesize) == "1a2b54659f044c436b83c68fe07062126a97403f" or // includes/common.inc
        hash.sha1(0, filesize) == "2806280491d42e25b703143f79138bf125973c4a" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.38 */
        hash.sha1(0, filesize) == "c57cfddf1a93ed0f631c228174c4e8ab515631de" or // includes/common.inc

        /* Drupal 7.39 */
        hash.sha1(0, filesize) == "6e77e30f15bd24836da3562fd92a10d4c0eb7978" or // includes/menu.inc
        hash.sha1(0, filesize) == "675e4d181ff1cc2fff1ddddfedbcb185acbfe023" or // modules/system/system.module
        hash.sha1(0, filesize) == "61b385832918e8fe247d8291fadfcae8c772a900" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.40 */
        hash.sha1(0, filesize) == "a8d979417c2bc5c44d2342f6fbb7a70fd3376a44" or // includes/common.inc
        hash.sha1(0, filesize) == "e96a1524d6558b7a463918014c5539a85db158b1" or // includes/menu.inc
        hash.sha1(0, filesize) == "a98d950bfec2bc0ea5a505469fa0d5b1aac2e8cc" or // modules/system/system.module
        hash.sha1(0, filesize) == "94ea653b8bb5ceb702322ad332d992c7ca9eb861" or // modules/system/system.install
        hash.sha1(0, filesize) == "a9a36141c9fbd8b80ffe0eb08489e451f003f8e0" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.42 */
        hash.sha1(0, filesize) == "44c062de04eea5fef0899aa14e5a169eea611fa1" or // modules/system/system.module
        hash.sha1(0, filesize) == "e43fb514e9d5e54a7b51e65590877471439f8623" or // modules/system/system.tar.inc
        hash.sha1(0, filesize) == "0450cb4ee9e15268be8142794a73eca560e2ec01" or // modules/simpletest/drupal_web_test_case.php

        /* Drupal 7.43 */
        hash.sha1(0, filesize) == "2d241144cec9948454826e34c4bc1191aab5f048" or // includes/common.inc
        hash.sha1(0, filesize) == "aa93b4079e74dcb3122e7a1d7d85a818cf0ea072" or // modules/system/system.admin.inc

        /* Drupal 8.0.0 */
        hash.sha1(0, filesize) == "393474833397003658a3e05883afea9715d3e1d8" or // vendor/symfony/http-kernel/UriSigner.php
        hash.sha1(0, filesize) == "a3b7be20d89f5d8e37024c118cbbc8492688ec03" or // vendor/symfony/dependency-injection/Dumper/PhpDumper.php
        hash.sha1(0, filesize) == "1d37474f942a5b9d826826b9b2fc86b2a1a663bc" or // core/tests/Drupal/KernelTests/KernelTestBase.php
        hash.sha1(0, filesize) == "c5fbeb320de38df0320062abc78702920cc23160" or // core/modules/migrate_drupal/tests/fixtures/drupal7.php
        hash.sha1(0, filesize) == "f68ee1429e6803b99ad658fff4f69e8a05875b7f" or // vendor/symfony/console/Application.php
        hash.sha1(0, filesize) == "679d20f5d77e6b262c0154194fccba8090f2a25b" or // core/modules/migrate_drupal/tests/fixtures/drupal6.php
        hash.sha1(0, filesize) == "d3e83816cb2342ee785f0e5efd658a2996db0d55" or // vendor/easyrdf/easyrdf/lib/EasyRdf/Parser/RdfXml.php
        hash.sha1(0, filesize) == "0cc2fe92af333fe2bbf1c6838cbad22352d21b79" or // core/modules/simpletest/simpletest.install
        hash.sha1(0, filesize) == "16a9e2c6e2e450c7c1628afd28432bc8bb6f5936" or // core/lib/Drupal/Core/Archiver/ArchiveTar.php
        hash.sha1(0, filesize) == "ffe14e1f80dfb81c496c1084ee5199d348d17fb3" or // core/modules/color/color.module
        hash.sha1(0, filesize) == "02659d44c18e839bcd0d2f5b209949e4560b17ad" or // core/modules/file/file.module
        hash.sha1(0, filesize) == "725a80e1da25907af517807f62e25fc76fd7cf65" or // vendor/symfony/process/Process.php
        hash.sha1(0, filesize) == "f3b4ef25a055eb9364cd86e3517b64c5a3e5e0e1" or // core/modules/views/src/Plugin/views/area/Result.php
        hash.sha1(0, filesize) == "73b94cff56707cecf81493590a8ef318ef31faee" or // vendor/symfony/process/ExecutableFinder.php

        /* Drupal 8.0.2 */
        hash.sha1(0, filesize) == "34ff6fde753da2426c0d35447e400b16caff2a50" or // core/tests/Drupal/KernelTests/KernelTestBase.php
        hash.sha1(0, filesize) == "d3636f0eb5a63625587a05ac6ccade45fb97a55e" or // core/modules/migrate_drupal/tests/fixtures/drupal7.php
        hash.sha1(0, filesize) == "c4e272cab48f2dac89f19d5de64b2944463731f8" or // core/modules/migrate_drupal/tests/fixtures/drupal6.php
        hash.sha1(0, filesize) == "1b19aadd0add4f3e1b9ceae73868f032320121f5" or // core/modules/color/color.module
        hash.sha1(0, filesize) == "d0978a9f8a10156b5fab1f98ca5235f5bfab22db" or // core/modules/file/file.module

        /* Drupal 8.0.3 */
        hash.sha1(0, filesize) == "76ab6856a186ea2252f51389d3c4bc50b8bdb985" or // core/modules/migrate_drupal/tests/fixtures/drupal7.php
        hash.sha1(0, filesize) == "3b331fe4085e5e8c36fe82b3c06660a55c28e866" or // core/modules/migrate_drupal/tests/fixtures/drupal6.php
        hash.sha1(0, filesize) == "d7b1c7c605a0e83586000e0842f7d24600170bcd" or // core/modules/color/color.module
        hash.sha1(0, filesize) == "73b78575e2ade191d154bf674b42d32895d9d274" or // core/modules/file/file.module

        /* Drupal 8.0.5 */
        hash.sha1(0, filesize) == "5097b35d5485edfba103e45c7f75c9855d819d00" or // core/modules/migrate_drupal/tests/fixtures/drupal7.php
        hash.sha1(0, filesize) == "88c7085a63df08242b3f147b6b44948372af83b8" or // core/modules/migrate_drupal/tests/fixtures/drupal6.php
        hash.sha1(0, filesize) == "56bf01eca3bf4eb22be25267bfcf6a5739c1faea" or // core/modules/file/file.module

        /* Drupal 8.0.6 */
        hash.sha1(0, filesize) == "9488e1d8204f771476468cd3d18c20ed41f1b61e" or // core/tests/Drupal/KernelTests/KernelTestBase.php
        hash.sha1(0, filesize) == "a964b62e7cb4729dac1723d46a95e96aab66bd79"    // core/modules/migrate_drupal/tests/fixtures/drupal6.php
}
