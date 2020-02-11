[![Build Status](https://travis-ci.org/jvoisin/php-malware-finder.svg?branch=master)](https://travis-ci.org/jvoisin/php-malware-finder)

# PHP Malware Finder

 ```
  _______  __   __  _______
 |  ___  ||  |_|  ||       |
 | |   | ||       ||    ___|
 | |___| ||       ||   |___   Webshell finder,
 |    ___||       ||    ___|   kiddies hunter,
 |   |    | ||_|| ||   |		website cleaner.
 |___|    |_|   |_||___|

Detect potentially malicious PHP files.
```

## What does it detect?

PHP-malware-finder does its very best to detect obfuscated/dodgy code as well as
files using PHP functions often used in malwares/webshells.

The following list of encoders/obfuscators/webshells are also detected:

* [Best PHP Obfuscator]( http://www.pipsomania.com/best_php_obfuscator.do )
* [Carbylamine]( https://code.google.com/p/carbylamine/ )
* [Cipher Design]( http://cipherdesign.co.uk/service/php-obfuscator )
* [Cyklodev]( http://sysadmin.cyklodev.com/online-php-obfuscator/ )
* [Joes Web Tools Obfuscator]( http://www.joeswebtools.com/security/php-obfuscator/ )
* [P.A.S]( http://profexer.name/pas/download.php )
* [PHP Jiami]( http://www.phpjiami.com/ )
* [Php Obfuscator Encode]( http://w3webtools.com/encode-php-online/ )
* [SpinObf]( http://mohssen.org/SpinObf.php )
* [Weevely3]( https://github.com/epinna/weevely3 )
* [atomiku]( http://atomiku.com/online-php-code-obfuscator/ )
* [cobra obfuscator]( http://obfuscator.uk/example/ )
* [phpencode]( http://phpencode.org )
* [tennc]( http://tennc.github.io/webshell/ )
* [web-malware-collection]( https://github.com/nikicat/web-malware-collection )
* [webtoolsvn]( http://www.webtoolsvn.com/en-decode/ )
* [novahot]( https://github.com/chrisallenlane/novahot )
* [nano]( https://github.com/UltimateHackers/nano )


Of course it's **trivial** to bypass PMF,
but its goal is to catch kiddies and idiots,
not people with a working brain.
If you report a stupid tailored bypass for PMF, you likely belong to one (or
both) category, and should re-read the previous statement.

## How does it work?

Detection is performed by crawling the filesystem and testing files against a
[set](https://github.com/jvoisin/php-malware-finder/blob/master/php-malware-finder/php.yar)
of [YARA](http://virustotal.github.io/yara/) rules. Yes, it's that simple!

Instead of using an *hash-based* approach,
PMF tries as much as possible to use semantic patterns, to detect things like
"a `$_GET` variable is decoded two times, unzipped,
and then passed to some dangerous function like `system`".

## Installation
- [Install Yara](https://yara.readthedocs.io/en/stable/gettingstarted.html#compiling-and-installing-yara).  
This is also possible via some Linux package managers:  
  - Debian: `sudo apt-get install yara`  
  - Red Hat: `yum install yara` (requires the [EPEL repository](https://fedoraproject.org/wiki/EPEL))

You can also compile it from source:

```
git clone git@github.com:VirusTotal/yara.git
cd yara/
YACC=bison ./configure
make
```

- Download php-malware-finder `git clone https://github.com/jvoisin/php-malware-finder.git`

## How to use it?

```
$ ./phpmalwarefinder -h
Usage phpmalwarefinder [-cfhtvl] <file|folder> ...
    -c  Optional path to a rule file
    -f  Fast mode
    -h  Show this help message
    -t  Specify the number of threads to use (8 by default)
    -v  Verbose mode
```

Or if you prefer to use `yara`:

```
$ yara -r ./php.yar /var/www
```

Please keep in mind that you should use at least YARA 3.4 because we're using
[hashes]( https://yara.readthedocs.org/en/latest/modules/hash.html ) for the
whitelist system, and greedy regexps. Please note that if you plan to build
yara from sources, libssl-dev must be installed on your system in order to
have support for hashes.

Oh, and by the way, you can run the *comprehensive* testsuite with `make tests`.

## Whitelisting

Check the [whitelist.yar](https://github.com/jvoisin/php-malware-finder/blob/master/php-malware-finder/whitelist.yar) file.
If you're lazy, you can generate whitelists for entire folders with the
[generate_whitelist.py](https://github.com/jvoisin/php-malware-finder/blob/master/php-malware-finder/utils/generate_whitelist.py) script.

## Why should I use it instead of something else?

Because:
- It doesn't use [a single rule per sample](
  https://github.com/Neo23x0/signature-base/blob/e264d66a8ea3be93db8482ab3d639a2ed3e9c949/yara/thor-webshells.yar
  ), since it only cares about finding malicious patterns, not specific webshells
- It has a [complete testsuite](https://travis-ci.org/jvoisin/php-malware-finder), to avoid regressions
- Its whitelist system doesn't rely on filenames
- It doesn't rely on (slow) [entropy computation]( https://en.wikipedia.org/wiki/Entropy_(information_theory) )
- It uses a ghetto-style static analysis, instead of relying on file hashes
- Thanks to the aforementioned pseudo-static analysis, it works (especially) well on obfuscated files

## Licensing

PHP-malware-finder is
[licensed](https://github.com/jvoisin/php-malware-finder/blob/master/php-malware-finder/LICENSE)
under the GNU Lesser General Public License v3.

The _amazing_ YARA project is licensed under the Apache v2.0 license.

Patches, whitelists or samples are of course more than welcome.
