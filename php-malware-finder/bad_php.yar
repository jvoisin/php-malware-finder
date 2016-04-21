rule Sqli
{
    strings:
        $mysql = /mysqli?_.*[[:space:]]*\(.*\$.*\)/
        $pg = /pg_.*[[:space:]]*\(.*\$.*\)/
        $sqlite = /sqlite_.*[[:space:]]*\(.*\$.*\)/
    condition:
        any of them
}

rule Xss
{
    strings:
        $xss1 = /(echo|print(_r)?)([[:space:]]|\()+.*\$(_ENV|_GET|_POST|_COOKIE|_REQUEST|_SERVER|HTTP|http).*/
    condition:
        any of them
}

rule CodeExec
{
    strings:
        $eval = /eval\s*\(\s*.\$.*\s*\)/
        $file = /(readfile|fopen|file(_get_contents)?)\s*\(.\$.*\)/
        $include = /(include|require)(_once)?\s*\(.*\$.*\)/
        $system = /(system|shell_exec)([[:space:]]*\(|[[:space:]]+).*\)?/
    condition:
        any of them
}


rule Misc
{
    strings:
        $header_splitting = /header\s*\(.*\$_(GET|POST|REQUEST|COOKIE).*\)/
        $serialize = /unserialize\s*\(.*\)|unserialize_callback_func/
        $chmod = /chmod\s*(.*777/
    condition:
        any of them
}

rule Infoleak
{
    strings:
        $php = /php(info|credits|version|_logo_guid|_uname)\s*\(.*\)/
        $zend = /zend(_logo_guid|_version)\s*\(.*\)/
        $extensions = /get_loaded_extensions\s*\(.*\)/
    condition:
        any of them
}
