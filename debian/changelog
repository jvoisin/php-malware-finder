nbs-phpmalwarefinder (0.3.4-1~deb) oldstable; urgency=medium

  * new upstream version :
    - update the whitelists
    - new rules to prevent bypasses
    - readme improvement

 -- jre <jre@nbs-system.com>  Mon, 07 Nov 2016 14:26:22 +0100

nbs-phpmalwarefinder (0.3.3-1~deb) oldstable; urgency=medium

  * new upstream version :
    - add a strrev-based detection
    - update the whitelists
    - add a new fancy logo
  * improve the release process

 -- jvo <jvo@nbs-system.com>  Mon, 24 Oct 2016 10:02:32 +0200

nbs-phpmalwarefinder (0.3.2-1~deb) oldstable; urgency=medium

  * new upstream version : 
    - whitelists are now split into files, each for one CMS
    - a custom whitelist is available for users to add their own
    - a mass whitelist helper has been added
  * Added the custom whitelist to conffiles to prevent package upgrade from
    overwriting users modification.

 -- jre <jre@nbs-system.com>  Fri, 29 Jul 2016 09:47:56 +0200

nbs-phpmalwarefinder (0.3.1-1~deb) oldstable; urgency=medium

  * new upstream version : 
    - rules for visbot detection
    - now detecting base64 encoded string USER_AGENT
    - debian squeeze support dropped
    - some false positives fixes

 -- jre <jre@nbs-system.com>  Thu, 19 May 2016 15:22:47 +0200

nbs-phpmalwarefinder (0.3.0-1~deb) oldstable; urgency=medium

  * rules files refactoring : 
    - php-malware-finder now comes with asp malware detection
    - rules have been split in different files to avoid false positives

  * The -l option allows language specific checks, for now only ASP and PHP
    are supported.
  * The -u option now allows to update rules without having to upgrade the
    package.

 -- jre <jre@nbs-system.com>  Thu, 14 Apr 2016 16:04:14 +0200

nbs-phpmalwarefinder (0.2.2-1~deb) oldstable; urgency=medium

  * new rules : bad_php.yara to find bad coding practices
  * malwares.yara now comes with posix_* functions detection, new hard-coded
    strings as well as php:// filter
  * The TooShort rule has been improved to reduce FP

 -- jre <jre@nbs-system.com>  Mon, 15 Feb 2016 15:48:06 +0100

nbs-phpmalwarefinder (0.2.1-1~deb) oldstable; urgency=medium

  * docroot-checker.sh added, helpful for both first and periodic security
    scan.

 -- jre <jre@nbs-system.com>  Mon, 01 Feb 2016 11:08:08 +0100

nbs-phpmalwarefinder (0.2.0-2~deb) oldstable; urgency=medium

  * New detection rules added

 -- sbl <sbl@nbs-system.com>  Thu, 28 Jan 2016 14:58:45 +0200

nbs-phpmalwarefinder (0.2.0-1~deb) oldstable; urgency=medium

  * Now supports whitelist using yara hash function
  * New detection rules added (tested against
    https://github.com/tennc/webshell malware collection)

 -- jre <jre@nbs-system.com>  Fri, 09 Oct 2015 14:58:45 +0200

nbs-phpmalwarefinder (0.1.1-1~deb) oldstable; urgency=medium

  * new dependecy on util-linux since the script is using ionice
  * postinst script added to create diff folder

 -- jre <jre@nbs-system.com>  Tue, 28 Apr 2015 15:07:12 +0200

nbs-phpmalwarefinder (0.1.1-1~deb) oldstable; urgency=medium

  * new signature to detect malware in footer and header

 -- jre <jre@nbs-system.com>  Tue, 14 Apr 2015 14:40:05 +0000

nbs-phpmalwarefinder (0.1) UNRELEASED; urgency=medium

  * Initial release.

 -- jvoisin <jvo@nbs-system.com>  Tue, 24 Mar 2015 11:10:36 +0100
