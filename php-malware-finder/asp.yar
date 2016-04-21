import "hash"
include "whitelist.yar"
include "common.yar"

global private rule IsAsp
{
    strings:
        $asp = /<%|@{}/
        $cs = /using .{4,25};/

    condition:
        ($asp or $cs) and filesize < 5MB
}

rule ObfuscatedAsp
{
    strings:
        $ = /LANGUAGE\s*=\s*VBScript.Encode/ nocase
        $ = /(".{1,5}"&){5,}/ // "e"&"v"&"a"&"l"
        $ = /(chr\s*\(\s*\d{1,3}\s*\)[+\)\s]*){5,}/ nocase // chr(114)+chr(101)+chr(113)+chr(117)+chr(101)
        $stunnix = /execute\("dIm [a-z]*"\):[a-z]* = unescape/ nocase // http://stunnix.com/

    condition:
        any of them and not IsWhitelisted 
}

rule ObfuscatedEncodingAsp
{
    strings:
        $unicode = /\\u[a-f0-9]/ nocase
        $html_encode = /&#([0-9]{3}|x[a-f0-9]{2});/ nocase

    condition:
        (#unicode >= 10 or #html_encode >= 10) and not IsWhitelisted 
}

rule DangerousAsp
{
    strings:
        $ = /createobject\s*\(\s*"(WScript\.Shell|WScript\.Network|Shell\.Application|Scripting\.FileSystemObject|ScriptControl)/ nocase
        $ = /eval\s*\({0,1}\s*request/ nocase

    condition:
        2 of them and not IsWhitelisted
}

