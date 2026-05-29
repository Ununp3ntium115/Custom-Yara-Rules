import "hash"

rule GLASSWORM_KNOWN_HASHES_ATTACHED_LIST
{
    meta:
        description = "Matches any file whose SHA-256 appears in the attached GlassWorm hash list"
        source = "User-provided Glassworm-Files.csv"
        hash_count = "53"

    condition:
        hash.sha256(0, filesize) == "0076ac146330511a82f5ce00a8667b06e6548deb514e8658a67afbc0b181c171" or
        hash.sha256(0, filesize) == "014a6219fa87a0cb258437bdd815a74054aa8840c823d0358bec41d0e3b9348a" or
        hash.sha256(0, filesize) == "01df115c5cbf2366510ab84edd45c243ec57b61faf4d358c9e108b8c18920a33" or
        hash.sha256(0, filesize) == "02121d9c57a5ccc1a47c6847dd4ce8620b9def51b4bf7f29903055393391706d" or
        hash.sha256(0, filesize) == "029b84a488259de4e886faff7981daa58ec5f676d141f42eacd3e9db72c6e49a" or
        hash.sha256(0, filesize) == "03efc6c5d6d3854f20e2a3d7bdd55367238c2b3023ed33aad5f6f645940e4d0a" or
        hash.sha256(0, filesize) == "04811adadff1d4e7acbac0d9f96a76915c5f39cf5af92f33ad794c831b3aec38" or
        hash.sha256(0, filesize) == "04c8f2de54b18760e5ec42fd681501f871bbc11b22a69d924c4587d0c0196e05" or
        hash.sha256(0, filesize) == "04df6e500e6b9bf72b485a856e94b1207e07b059b20d59fc5245ace810411db2" or
        hash.sha256(0, filesize) == "0622506558032be8b4ae048850b475b335c22220cadc419f06403c54b65837f3" or
        hash.sha256(0, filesize) == "063effe8ceab2a05b8243b521f7e65235ac7ae15fedec346ee5d0dea43cb435d" or
        hash.sha256(0, filesize) == "06415479bb8d84aaa7f6b3ab1df9208e9d81c09c24bc020fa7cde31675acf021" or
        hash.sha256(0, filesize) == "06866f635337a9591f8566dcf86819cfc0a1ba40f15544d048c969bbe0d2c5a8" or
        hash.sha256(0, filesize) == "06f3c4f3fbf0e5453248580457a2d41bd7f387c2c16a917ac684e7de9972dee1" or
        hash.sha256(0, filesize) == "07f7947fe04d80b97e4d6d248622cf8797c8b3cd9b581f49d29ad3aea6b81991" or
        hash.sha256(0, filesize) == "0810f1e1b014228476c9a7f91d4202686d7509234ffa18cd43bf000336825eb3" or
        hash.sha256(0, filesize) == "0836883e1edd3c96c6fc6792419e86e621fa4002d543627074a99fba029134f0" or
        hash.sha256(0, filesize) == "083f72cc2ec1ac8fc746e05046d97ad32518d64206a4f9db3dc04ea5d5c72303" or
        hash.sha256(0, filesize) == "086e3ada93c6cd654b89445eba35458a8e6028a96626d3dc8fda5a848731607f" or
        hash.sha256(0, filesize) == "0940b6a7f5aed204277aa8c50694ea3e3d5a9e3c3be9e3ccf2a3edd0cf5f5777" or
        hash.sha256(0, filesize) == "0947079aa24751b61c5d169696076f07678f2846d1c49eae06382337a9b9c7e8" or
        hash.sha256(0, filesize) == "094d91f5d43f0b6f1ba70ab0efb252a6bd23399a4bb1a01bcdf013ee906a2bbd" or
        hash.sha256(0, filesize) == "09ad72ac1eedef1ee80aa857e300161bc701a2d06105403fb7f3992cbf37c8b9" or
        hash.sha256(0, filesize) == "09fb7bdeb400967a5a14709ffc3f757453f145e187619104d159d5ae55fc0e04" or
        hash.sha256(0, filesize) == "0a08adb41640d5dc0789effce7987e5d5b7929c35b193c1a6acb62e06826fe8b" or
        hash.sha256(0, filesize) == "0ccf879f8042839eab0b9bdef686ca6c71dc7d2e88875b2a626cea9cd01b7488" or
        hash.sha256(0, filesize) == "0d58ccba4ce2fab4fa62a0066318bb62cb4da16767b502e4f5dbe175c4ce194e" or
        hash.sha256(0, filesize) == "0e2ebfd289929981b9a4979af62e37fdcc60b993509553d5d960181bd50ce324" or
        hash.sha256(0, filesize) == "0fe3f3060f76851e40212ac78a2449d25b3357ef729ded79e9a2aa7b795c7e49" or
        hash.sha256(0, filesize) == "13d8743a593d157ac3c4eec2d379d06120127b3400c98be02ca596a887581334" or
        hash.sha256(0, filesize) == "17373e4ebd4660cc83d12d8a73c46701ad560740a4829064a8544feab9cf9e2a" or
        hash.sha256(0, filesize) == "17734ff29eec9c77dbda9aea37f8e85ec276d1599dc0162c569e637e17e86e42" or
        hash.sha256(0, filesize) == "1ca0b2d66ef35d4bc3496012bcd248a7d8456622993656b45086adc9b92968e4" or
        hash.sha256(0, filesize) == "1cb77c347a07670b56762a8e160c45a285c21af238a86cdf6113caed476666c3" or
        hash.sha256(0, filesize) == "1ed02734c776296ca21b524a9a13bdae96ff77cac6be789135c56ad35bbdb021" or
        hash.sha256(0, filesize) == "20ea9ea5c38024f985667863982eae930c0f92d2990a97e843c0b83a3ee94716" or
        hash.sha256(0, filesize) == "2470c06586bbc7794f77bc8a95d608d5552e5a532a04faa33d77d2e3657d058a" or
        hash.sha256(0, filesize) == "29b431808a394c9e0abc5aeafab108b03be7b9ecb728fd4894a45cbac6ca2f2c" or
        hash.sha256(0, filesize) == "2a4b9dfd49b5e37d178be022fcba5bff1cbfeb3647c8f4048d201c8e370a7ef2" or
        hash.sha256(0, filesize) == "2c97487d8557048f23e154128a606bc064723eb21e7cd24a04d760812920d954" or
        hash.sha256(0, filesize) == "50a68eded53d94c230fc57232c3e26028ae726929c9c8ae7905cde469e74296f" or
        hash.sha256(0, filesize) == "6dcd67d2704d9ebf659ea7a56db0b272747a2aab80d3cf57ef11a344c3059018" or
        hash.sha256(0, filesize) == "83173d5fcc462820f09d5cbb8bddeea15b17c2c4e4fec50df6d8a9c92378582c" or
        hash.sha256(0, filesize) == "8ff78d459a55378124a316b73f7ded9435582d805b8b4f984ae67983957c03eb" or
        hash.sha256(0, filesize) == "985837f6d29f2fca78db956b2a8db882e13a7190c9002e64b72928af1978b7e9" or
        hash.sha256(0, filesize) == "a031bc14dd0d6c64fa4c3877f9d3ad1c52562705b93e2c045d0cd9438303df26" or
        hash.sha256(0, filesize) == "ac5f976b3ed31509a11232db9bbae2ea2126762a0659061cf9522e7b66d230b8" or
        hash.sha256(0, filesize) == "b195a25a71de4eb55495de783c897dd897594cf5670f1aabaa6962255cb9343e" or
        hash.sha256(0, filesize) == "e0365007b8347a8fa2bd7166463c1bd924cdbf0fa882a835af843b86d4462927" or
        hash.sha256(0, filesize) == "e87a572245ed8628ec7fbcf0da2b91ad644f6b35e8788c8a529bcfa886629345" or
        hash.sha256(0, filesize) == "e9641bf12b4e28c659197fa6e56d438dab3b50c2f25e3144e5c6a1d396f67683" or
        hash.sha256(0, filesize) == "f3b22beb75e9c000869fdb683cef416ecdef4ac0cc78b9e04d886b5623905020" or
        hash.sha256(0, filesize) == "f59216286e80ffd684b909cce8cb2fb2b6d0819eb6417539726af8cd1a738b41"
}

rule GLASSWORM_ZIG_NODE_ADDON_STRINGS
{
    meta:
        description = "Detects string artifacts from the GlassWorm Zig IDE spreader described by Aikido"
        source = "Aikido Apr 8 2026 report"

    strings:
        $s1 = "vsx_installer_zig" ascii wide
        $s2 = "davidioasd" ascii wide
        $s3 = "./bin/win.node" ascii wide
        $s4 = "./bin/mac.node" ascii wide
        $s5 = "--install-extension" ascii wide
        $s6 = "autoimport-2.7.9.vsix" ascii wide
        $s7 = "ColossusQuailPray/oiegjqde/releases/download/12/autoimport-2.7.9.vsix" ascii wide
        $s8 = "specstudio/code-wakatime-activity-tracker" ascii wide
        $s9 = "floktokbok.autoimport" ascii wide

    condition:
        3 of ($s*)
}

rule GLASSWORM_IDE_SPREADER_PATHS
{
    meta:
        description = "Detects IDE path artifacts used by the GlassWorm native installer"
        source = "Aikido Apr 8 2026 report"

    strings:
        $w1 = "%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\bin\\code.cmd" ascii wide nocase
        $w2 = "%LOCALAPPDATA%\\Programs\\Microsoft VS Code Insiders\\bin\\code-insiders.cmd" ascii wide nocase
        $w3 = "%LOCALAPPDATA%\\Programs\\cursor\\resources\\app\\bin\\cursor.cmd" ascii wide nocase
        $w4 = "%LOCALAPPDATA%\\Programs\\windsurf\\resources\\app\\bin\\windsurf.cmd" ascii wide nocase
        $w5 = "%LOCALAPPDATA%\\Programs\\VSCodium\\resources\\app\\bin\\codium.cmd" ascii wide nocase
        $w6 = "%LOCALAPPDATA%\\Programs\\Positron\\resources\\app\\bin\\positron.cmd" ascii wide nocase
        $m1 = "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" ascii wide
        $m2 = "/Applications/Cursor.app/Contents/Resources/app/bin/cursor" ascii wide
        $m3 = "/Applications/Windsurf.app/Contents/Resources/app/bin/windsurf" ascii wide
        $m4 = "/Applications/VSCodium.app/Contents/Resources/app/bin/codium" ascii wide
        $m5 = "/Applications/Positron.app/Contents/Resources/app/bin/positron" ascii wide

    condition:
        4 of ($w*) or 3 of ($m*)
}

rule GLASSWORM_EMBEDDED_IP_IOCS
{
    meta:
        description = "Matches samples embedding IP literals from the attached GlassWorm IOC list"
        source = "User-provided IOCs-GlassWorm.csv and Glassworm-Files.csv"
        ip_count = "12"

    strings:
        $ip1 = "45.143.201.4" ascii
        $ip2 = "66.171.248.178" ascii
        $ip3 = "74.125.201.132" ascii
        $ip4 = "93.184.221.240" ascii
        $ip5 = "110.110.110.0" ascii
        $ip6 = "110.110.110.3" ascii
        $ip7 = "149.28.178.150" ascii
        $ip8 = "193.106.191.146" ascii
        $ip9 = "195.24.66.145" ascii
        $ip10 = "195.201.225.248" ascii
        $ip11 = "195.245.112.115" ascii
        $ip12 = "199.59.243.228" ascii

    condition:
        2 of ($ip*)
}

rule GLASSWORM_KNOWN_WIN_NODE_HASH
{
    meta:
        description = "Matches win.node hash published by Aikido on Apr 8 2026"
        source = "Aikido Apr 8 2026 report"

    condition:
        hash.sha256(0, filesize) == "2819ea44e22b9c47049e86894e544f3fd0de1d8afc7b545314bd3bc718bf2e02"
}

rule GLASSWORM_KNOWN_MAC_NODE_HASH
{
    meta:
        description = "Matches mac.node hash published by Aikido on Apr 8 2026"
        source = "Aikido Apr 8 2026 report"

    condition:
        hash.sha256(0, filesize) == "112d1b33dd9b0244525f51e59e6a79ac5ae452bf6e98c310e7b4fa7902e4db44"
}
