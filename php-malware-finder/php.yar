import "hash"
include "whitelist.yar"
include "common.yar"

/*
    Detect:
        - phpencode.org
        - http://www.pipsomania.com/best_php_obfuscator.do
        - http://atomiku.com/online-php-code-obfuscator/
        - http://www.webtoolsvn.com/en-decode/
        - http://obfuscator.uk/example/
        - http://w3webtools.com/encode-php-online/
        - http://www.joeswebtools.com/security/php-obfuscator/
        - https://github.com/epinna/weevely3
        - http://cipherdesign.co.uk/service/php-obfuscator
        - http://sysadmin.cyklodev.com/online-php-obfuscator/
        - http://mohssen.org/SpinObf.php
        - https://code.google.com/p/carbylamine/
        - https://github.com/tennc/webshell

        - https://github.com/wireghoul/htshells

    Thanks to:
        - https://stackoverflow.com/questions/3115559/exploitable-php-functions
*/

global private rule IsPhp
{
    strings:
        $php = /<\?[^x]/

    condition:
        $php and filesize < 5MB
}

private rule CloudFlareBypass
{
    strings:
        $ = "chk_jschl"
        $ = "jschl_vc"
        $ = "jschl_answer"

    condition:
        2 of them // Better be safe than sorry
}

rule ObfuscatedPhp
{
    strings:
        $eval = /(<\?php|[;{}])\s*@?(eval|preg_replace|system|assert|passthru|(pcntl_)?exec|win_shell_execute|call_user_func(_array)?)\s*\(/ nocase  // ;eval( <- this is dodgy
        $b374k = "'ev'.'al'"
        $align = /(\$\w+=[^;]*)*;\$\w+=@?\$\w+\(/  //b374k
        $weevely3 = /\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);/  // weevely3 launcher
        $c99_launcher = /;\$\w+\(\$\w+(,\s?\$\w+)+\);/  // http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html
        $variable_variable = /\${\$[0-9a-zA-z]+}/
        $too_many_chr = /(chr\([\d]+\)\.){5}/  // concatenation of more than two `chr()`
        $concat = /(\$[^\n\r]+\.){5}/  // concatenation of more than 5 words
        $var_as_func = /\$_(GET|POST|COOKIE|REQUEST)\s*\[[^\]]+\]\s*\(/
        $gif = /^GIF89/
condition:
        any of them and not IsWhitelisted
}

rule DodgyPhp
{
    strings:
        $basedir_bypass = /curl_init\s*\(\s*["']file:\/\//
        $basedir_bypass2 = "file:file:///" // https://www.intelligentexploit.com/view-details.html?id=8719
        $disable_magic_quotes = /set_magic_quotes_runtime\s*\(\s*0/
        $execution = /(eval|assert|passthru|exec|include|system|pcntl_exec|win_shell_execute|base64_decode|`|array_map|call_user_func(_array)?)\s*\(\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE))/ nocase
        $execution2 = /(array_filter|array_reduce|array_walk(_recursive)?|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|iterator_apply)\s*\(\s*[^,]+,\s*(base64_decode|php:\/\/input|str_rot13|gz(inflate|uncompress)|getenv|pack|\\?\$_(GET|REQUEST|POST|COOKIE))/ nocase  // functions that takes a callback as 2nd parameter

        $htaccess = "SetHandler application/x-httpd-php"
        $iis_com = /IIS:\/\/localhost\/w3svc/
        $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/  // Clever includes
        $ini_get = /ini_(get|set|restore)\s*\(\s*['"](safe_mode|open_basedir|disable_function|safe_mode_exec_dir|safe_mode_include_dir|register_globals|allow_url_include)/ nocase
        $pr = /(preg_replace(_callback)?|mb_ereg_replace|preg_filter)\s*\(\s*['"]\/[^\/]*\/e/  nocase // http://php.net/manual/en/function.preg-replace.php
        $safemode_bypass = /\x00\/\.\.\/|LD_PRELOAD/
        $shellshock = /\(\)\s*{\s*:\s*;\s*}\s*;/
        $udp_dos = /fsockopen\s*\(\s*['"]udp:\/\//
        $various = "<!--#exec cmd="  //http://www.w3.org/Jigsaw/Doc/User/SSI.html#exec

    condition:
        (any of them or CloudFlareBypass) and not IsWhitelisted
}

rule DangerousPhp
{
    strings:
        $system = "system" fullword nocase  // localroot bruteforcers have a lot of this

        $ = "array_filter" fullword nocase
        $ = "assert" fullword nocase
        $ = "backticks" fullword nocase
        $ = "call_user_func" fullword nocase
        $ = "eval" fullword nocase
        $ = "exec" fullword nocase
        $ = "fpassthru" fullword nocase
        $ = "fsockopen" fullword nocase
        $ = "function_exists" fullword nocase
        $ = "getmygid" fullword nocase
        $ = "shmop_open" fullword nocase
        $ = "mb_ereg_replace_callback" fullword nocase
        $ = "passthru" fullword nocase
        $ = /pcntl_(exec|fork)/ fullword nocase
        $ = "php_uname" fullword nocase
        $ = "phpinfo" fullword nocase
        $ = "posix_geteuid" fullword nocase
        $ = "posix_getgid" fullword nocase
        $ = "posix_getpgid" fullword nocase
        $ = "posix_getppid" fullword nocase
        $ = "posix_getpwnam" fullword nocase
        $ = "posix_getpwuid" fullword nocase
        $ = "posix_getsid" fullword nocase
        $ = "posix_getuid" fullword nocase
        $ = "posix_kill" fullword nocase
        $ = "posix_setegid" fullword nocase
        $ = "posix_seteuid" fullword nocase
        $ = "posix_setgid" fullword nocase
        $ = "posix_setpgid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setsid" fullword nocase
        $ = "posix_setuid" fullword nocase
        $ = "preg_replace_callback" fullword
        $ = "proc_open" fullword nocase
        $ = "popen" fullword nocase
        $ = "register_shutdown_function" fullword nocase
        $ = "register_tick_function" fullword nocase
        $ = "shell_exec" fullword nocase
        $ = "shm_open" fullword nocase
        $ = "show_source" fullword nocase
        $ = "socket_create(AF_INET, SOCK_STREAM, SOL_TCP)" nocase
        $ = "stream_socket_pair" nocase
        $ = "win32_create_service" fullword nocase
        $ = "win_shell_execute" fullword nocase
        $ = "xmlrpc_decode" fullword nocase nocase
        $ = /ob_start\s*\(\s*[^\)]/  //ob_start('assert'); echo $_REQUEST['pass']; ob_end_flush();

        $whitelist = /escapeshellcmd|escapeshellarg/ nocase

    condition:
        not $whitelist and (5 of them or #system > 250) and not IsWhitelisted
}

