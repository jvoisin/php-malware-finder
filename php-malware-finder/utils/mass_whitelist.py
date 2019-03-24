#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import tarfile
from copy import copy
from datetime import datetime
from collections import OrderedDict
from hashlib import sha1
from urllib2 import urlopen, HTTPError
from StringIO import StringIO

import yara

USAGE = """
USAGE: %(prog)s <NAME> <URL_PATTERN> [<MAJOR> [<MINOR> [<PATCH>]]]

Options:
    NAME : name of the CMS/whatever being whitelisted
    URL_PATTERN : download URL with __version__ as a version placeholder
    MAJOR : minimum and maximum major version to crawl (eg: 1-8, 8)
    MINOR : minimum and maximum minor version to crawl
    PATCH : minimum and maximum patch version to crawl

Examples:
    %(prog)s drupal https://ftp.drupal.org/files/projects/drupal-__version__.tar.gz 9 50
    %(prog)s drupal https://ftp.drupal.org/files/projects/drupal-__version__.tar.gz 4-9 1-50

    %(prog)s wordpress https://wordpress.org/wordpress-__version__.tar.gz 4 15

    %(prog)s symphony https://github.com/symfony/symfony/archive/v__version__.tar.gz 3 9

    %(prog)s phpmyadmin https://files.phpmyadmin.net/phpMyAdmin/__version__/phpMyAdmin-__version__-all-languages.tar.gz 4 9
""" % {'prog': sys.argv[0]}


class Opts:
    DEFAULT_MIN = 0
    DEFAULT_MAX = 99
    YARA_RULES = yara.compile(sys.path[0]+'/../php.yar', includes=True, error_on_warning=True)

    @classmethod
    def to_str(cls):
        values = []
        for attr in cls.__dict__:
            if attr.isupper():
                values.append('%s=%s' % (attr, getattr(cls, attr)))
        return '<Opts(%s)>' % ' '.join(values)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def extract_version_arg(index):
    min_ver, max_ver = (Opts.DEFAULT_MIN, Opts.DEFAULT_MAX)
    if len(sys.argv) >= (index + 1):
        if '-' in sys.argv[index]:
            min_ver, max_ver = map(int, sys.argv[index].split('-'))
        else:
            max_ver = int(sys.argv[index])
    return min_ver, max_ver


def generate_whitelist(version):
    rules = {}

    # download archive
    dl_failed = False
    download_url = Opts.URL_PATTERN.replace('__version__', version)
    download_url_str = Opts.URL_PATTERN.replace('__version__', '\x1b[1;33m%s\x1b[0m' % version)
    eprint("[+] Downloading %s... " % download_url_str, end='')
    sys.stdout.flush()
    try:
        resp = urlopen(download_url)
        resp_code = resp.code
    except HTTPError as err:
        dl_failed = True
        resp_code = err.code
    if dl_failed or (resp_code != 200):
        eprint("\x1b[1;31mFAILED (%d)\x1b[0m" % resp_code)
        return None
    data = StringIO(resp.read())
    data.seek(0)
    eprint("\x1b[1;32mOK\x1b[0m")

    # extract archive and check against YARA signatures (in-memory)
    eprint("[-] Generating whitelist... ", end='')
    sys.stdout.flush()
    tar = tarfile.open(mode='r:gz', fileobj=data)
    for entry in tar.getnames():
        entry_fd = tar.extractfile(entry)
        if entry_fd is None:
            continue
        entry_data = entry_fd.read()
        matches = Opts.YARA_RULES.match(data=entry_data, fast=True)
        if matches:
            rules['/'.join(entry.split('/')[1:])] = sha1(entry_data).hexdigest()
    eprint("\x1b[1;32mDONE\x1b[0m")

    return rules


# init vars
whitelists = OrderedDict()

# check args
if (len(sys.argv) < 3) or (len(sys.argv) > 6):
    eprint(USAGE)
    sys.exit(1)

# parse args
Opts.CMS_NAME = sys.argv[1]
Opts.URL_PATTERN = sys.argv[2]
Opts.MIN_MAJOR, Opts.MAX_MAJOR = extract_version_arg(3)
Opts.MIN_MINOR, Opts.MAX_MINOR = extract_version_arg(4)
Opts.MIN_PATCH, Opts.MAX_PATCH = extract_version_arg(5)

# loop over possible versions
for vmajor in range(Opts.MIN_MAJOR, Opts.MAX_MAJOR + 1):
    # download without vminor and vpatch (but ignore if it doesn't exist)
    version = "%d" % vmajor
    rules = generate_whitelist(version)
    if (rules is not None) and rules:
        whitelists[version] = rules

    has_mversion = False
    first_mloop = True
    for vminor in range(Opts.MIN_MINOR, Opts.MAX_MINOR + 1):
        # download without vpatch (but ignore if it doesn't exist)
        version = "%d.%d" % (vmajor, vminor)
        rules = generate_whitelist(version)
        if rules is not None:
            has_mversion = True
            if rules:
                whitelists[version] = rules
        #if (rules is None) and (has_mversion or not first_mloop):
        #    break
        first_mloop = False

        has_pversion = False
        first_ploop = True
        for vpatch in range(Opts.MIN_PATCH, Opts.MAX_PATCH + 1):
            version = "%d.%d.%d" % (vmajor, vminor, vpatch)
            rules = generate_whitelist(version)
            if rules is not None:
                has_pversion = True
                if rules:
                    whitelists[version] = rules
            # break loop if download failed and:
            # - a version has already been found during this loop
            # - this is the 2nd iteration (if a version wasn't found,
            #   it means download failed twice)
            if (rules is None) and (has_pversion or not first_ploop):
                break
            first_ploop = False

# remove duplicate entries:
eprint("[+] Deduplicating detections... ", end='')
known_files = []
for version, rules in copy(whitelists.items()):
    used_rules = 0
    for filename, digest in rules.items():
        rtuple = (filename, digest)
        if rtuple in known_files:
            del whitelists[version][filename]
        else:
            known_files.append(rtuple)
            used_rules += 1
    if used_rules == 0:
        del whitelists[version]
eprint("\x1b[1;32mDONE\x1b[0m")

eprint("[+] Generating final whitelist... ", end='')
# build final rule
prefix = 8 * ' '
conditions = []
len_wl = len(whitelists.keys()) - 1
for index, (version, rules) in enumerate(whitelists.items()):
    cond_str = '%s/* %s %s */\n' % (prefix, Opts.CMS_NAME.title(), version)
    len_rules = len(rules.keys()) - 1
    for inner_index, (filename, digest) in enumerate(rules.items()):
        if (index == len_wl) and (inner_index == len_rules):  # last loop iteration
            cond_str += '%shash.sha1(0, filesize) == "%s"    // %s\n' % (prefix, digest, filename)
        else:
            cond_str += '%shash.sha1(0, filesize) == "%s" or // %s\n' % (prefix, digest, filename)
    conditions.append(cond_str)
eprint("\x1b[1;32mDONE\x1b[0m")

final_rule = """
import "hash"

private rule %(name)s
{
    meta:
        generated = "%(gendate)s"

    condition:
%(conditions)s
}
""" % {
    'name': Opts.CMS_NAME.title(),
    'gendate': datetime.now().isoformat(),
    'conditions': '\n'.join(conditions)
}
print(final_rule)
