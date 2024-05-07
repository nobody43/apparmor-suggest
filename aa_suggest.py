#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-License-Identifier: GPL-3.0-only
# Version: 0.8.10

# line, l - single log line in form of dictionary
# normalize - prepare line values for a possible merge; make keys consistent
# adapt - replace line values with sutable for usage in the rule
# merge - make single line from many lines; unequivocally by default, or ambiguously by params
# unequivocally - non-aggressive deduplication; no rule covarage is lost, but paths could be replaced by tunables
# ambiguously - aggressive deduplication; some rule coverage could be broader than needed
# keep/drop - include or exclude the line from deduplication, affects merging (preprocessing); active filtering
# show/hide - include or exclude the line from display, does NOT affect merging (postprocessing)

# MAIN FLOW:
# gather logs ->
# normalization ->
# adaption (& colorization preparation) ->
# merging ->
# sorting ->
# alignment ->
# colorization ->
# display

import sys
import argparse
import re
import shlex
import pathlib
import string
import random
import copy
import os

def adaptFilePath(l, key, ruleStyle):
    '''Applied early to fully handle duplicates.
       For file paths, not necessary file lines.
       Watch out for bugs: launchpad #1856738
       Do only one capture per regex helper, otherwise diffs will be a mess (will match recursively)
    '''
    # Always surround these helpers with other charactes or new/endlines
    # Capturing group must not be optional '?', but always provide at least empty '|' match
    # Mix of regex and pcre styles!; 'C' for capture
    random6  = '(?![0-9]{6}|[a-z]{6}|[A-Z]{6}|[A-Z][a-z]{5}|[A-Z][a-z]{4}[0-9])(?:[0-9a-zA-Z]{6})' # aBcXy9, AbcXyz, abcxy9; NOT 123789, abcxyz, ABCXYZ, Abcxyz, Abcxy1
    random8  = '(?![0-9]{8}|[a-z]{8}|[A-Z]{8}|[A-Z][a-z]{7}|[A-Z][a-z]{6}[0-9])(?:[0-9a-zA-Z]{8})' # aBcDwXy9, AbcdWxyz, abcdwxy9; NOT: 12346789, abcdwxyz, ABCDWXYZ, Abcdwxyz, Abcdwxy1
    random10 = '(?![0-9]{10}|[a-z]{10}|[A-Z]{10}|[A-Z][a-z]{9}|[A-Z][a-z]{8}[0-9])(?:[0-9a-zA-Z]{10})' # aBcDeVwXy9, AbcdeVwxyz, abcdevwxy9; NOT: 1234567890, abcdevwxyz, ABCDEVWXYZ, Abcdevwxyz, Abcdevwxy1
    users        = r'(?:[0-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9}|@{uid})'
    usersC       = r'(?:[0-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9})'
    hex2         = r'(?:[0-9a-fA-F]{2}|\[0-9a-f\]\[0-9a-f\]|@{h}@{h})'
    hex2C        = r'(?:[0-9a-fA-F]{2})'
    hex16        = r'(?:[0-9a-fA-F]{16}|\[0-9a-f\]\*\[0-9a-f\]|@{hex16})'
    hex16C       = r'(?:[0-9a-fA-F]{16})'
    hex32        = r'(?:[0-9a-fA-F]{32}|\[0-9a-f\]\*\[0-9a-f\]|@{hex32})'
    hex32C       = r'(?:[0-9a-fA-F]{32})'
    hex38        = r'(?:[0-9a-fA-F]{38}|\[0-9a-f\]\*\[0-9a-f\]|@{hex})'
    hex38C       = r'(?:[0-9a-fA-F]{38})'
    ints         = r'(?:\d+|\[0-9\]\*|@{int})'
    intsC        = r'(?:\d+|\[0-9\]\*|@{int})'
    uuid         = r'(?:[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}|\[0-9a-f\]\*\[0-9a-f\]|@{uuid})'
    uuidC        = r'(?:[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})'
    etc_ro       = r'(?:/usr/etc|@{etc_ro})'
    run          = r'(?:/var/run|/run|@{run})'
    runC         = r'(?:/var/run|/run)'
    runJ         = r'(?:/var|/run|@{run})'
    proc         = r'(?:/proc|@{PROC})'
    procC        = r'(?:/proc)'
    sys          = r'(?:/sys|@{sys})'
    sysC         = r'(?:/sys)'
    pids         = r'(?:[2-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9}|@{pid})'  # 3-4999999999
    pidsC        = r'(?:[2-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9})'         # 3-4999999999; capture
    tids         = r'(?:[1-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9}|@{tid})'  # 1-4999999999
    tidsC        = r'(?:[1-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9})'         # 1-4999999999; capture
    multiarch    = r'(?:[^/]+-linux-(?:gnu|musl)(?:[^/]+)?|@{multiarch})'
    multiarchC   = r'(?:[^/]+-linux-(?:gnu|musl)(?:[^/]+)?)'
    user_cache   = r'(?:@?/home/[^/]+/\.cache|@{user_cache_dirs})'
    user_cacheC  = r'(?:@?/home/[^/]+/\.cache)'
    user_config  = r'(?:@?/home/[^/]+/\.config|@{user_config_dirs})'
    user_configC = r'(?:@?/home/[^/]+/\.config)'
    user_share   = r'(?:@?/home/[^/]+/\.local/share|@{user_share_dirs})'
    user_shareC  = r'(?:@?/home/[^/]+/\.local/share)'
    homes        = r'(?:@?/home/[^/]+|@{HOME})'
    homesC       = r'(?:@?/home/[^/]+)'
    pciId        = r'(?:[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d|\?\?\?\?:\?\?:\?\?\.\?|@{pci_id})'
    pciIdC       = r'(?:[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d)'
    o3           = r'(?:3|{\,3})?'                # optional '3'
    oWayland     = r'(?:-wayland|{\,-wayland})?'  # optional '-wayland'
    oUsr         = r'(?:usr/|{\,usr/})?'          # optional '/usr'
    oUsrC        = r'(?:usr/)?'                   # optional '/usr'; capture
    Any          = r'(?!@{.+|{.+|\[0-9.+|\*)[^/]+'
    literalBackslash = '\\\\'

    # Special cases <3
    pciBus = r'(?:(?:pci)?[0-9a-f]{4}:[0-9a-f]{2}|(?:pci)?\?\?\?\?:\?\?|@{pci_bus})'
    if ruleStyle == 'AppArmor.d':
        Bin     = r'(?:/(?:usr/)?(?:s)?bin|@{bin})'
        BinC    = r'(?:/(?:usr/)?(?:s)?bin)'
        pciBusC = r'(?:pci[0-9a-f]{4}:[0-9a-f]{2})'
    else:
        Bin     = r'(?:/(?:usr/)?(?:s)?bin|/{\,usr/}bin)'
        BinC    = r'(?:/(?:usr/)?bin)'
        pciBusC = r'(?:[0-9a-f]{4}:[0-9a-f]{2})'

    # Substitute capturing group with t[1] or t[2]; order matters when mentioned
    regexpToMacro = [  # non-tunables
 # regex                                                                            # default style         # apparmor.d style      # prefix, optional
(rf'^{user_share}/gvfs-metadata/(|{Any})$',                                           None,                  '{,*}',                 'deny'),
(rf'^/var/lib/apt/lists/({Any})\.yml\.gz$',                                          '*',                     None),
#(f'^{user_share}/yelp/storage/({Any})/',                                            '*',                     None,                  'owner'),
#(f'^{user_share}/yelp/storage/[^/]+/({Any})/',                                      '*',                     None,                  'owner'),
 # Capturing *any* goes above
(rf'^{Bin}/(|e|f)grep$',                                                             '{,e,f}',                None),
(rf'^{Bin}/(|g|m)awk$',                                                              '{,g,m}',                None),
(rf'^{Bin}/gettext(|\.sh)$',                                                         '{,.sh}',                None),
(rf'^{Bin}/python3\.(\d+)(?:-[a-z]+)?$',                                             '[0-9]{,[0-9]}',        '@{int}'),
(rf'^{Bin}/ruby\d+\.(\d+)$',                                                         '[0-9]',                '@{int}'),
(rf'^{Bin}/which(|\.debianutils)$',                                                  '{,.debianutils}',       None),
(rf'^{Bin}/ldconfig(|\.real)$',                                                      '{,.real}',              None),
(rf'^/{oUsr}(?:local/)?lib/python3\.(\d+)/',                                         '[0-9]{,[0-9]}',        '@{int}'),
(rf'^/usr/share/gdm({o3})/',                                                         '{,3}',                  None),
(rf'^/usr/share/gtk-([2-4])\.\d+/',                                                  '[2-4]',                 None),
(rf'^/usr/share/icu/(\d+)\.',                                                        '[0-9]*',               '@{int}'),
(rf'^/usr/share/icu/{ints}\.(\d+)/',                                                 '[0-9]*',               '@{int}'),
(rf'^/usr/share/qt(|5|6)(?:ct)?/',                                                   '{,5,6}',                None),
(rf'^/{oUsr}lib/kde(|3|4)/',                                                         '{,3,4}',                None),
(rf'^/etc/apparmor\.d/libvirt/libvirt-({uuidC})$',                                   '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^/etc/gdm({o3})/',                                                               '{,3}',                  None),
(rf'^/etc/gtk-([2-4])\.0/',                                                          '[2-4]',                 None),
(rf'^/etc/python3\.(\d+)/',                                                          '[0-9]{,[0-9]}',        '@{int}'),
(rf'^/var/backups/apt\.extended_states\.(\d+)$',                                     '[0-9]*',    	     '@{int}',               'owner'),
(rf'^/var/cache/fontconfig/({hex32C})-',                                             '[0-9a-f]*[0-9a-f]',    '@{hex32}',             'owner'),
(rf'^/var/cache/fontconfig/{hex32}-le64\.cache-\d+\.TMP-({random6})$',               '??????',               '@{rand6}',             'owner'),
(rf'^/var/cache/fontconfig/({uuidC})-',                                              '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(rf'^{runJ}/log/journal/({hex32C})/',                                          	     '[0-9a-f]*[0-9a-f]',    '@{hex32}'),
(rf'^{runJ}/log/journal/{hex32}/system@({hex16C})-',                                 '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/system@{hex16}-({hex16C})\.',                  	     '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/system@({hex32C})-',                           	     '[0-9a-f]*[0-9a-f]',    '@{hex32}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/system@{hex32}-({hex16C})-',                         '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/system@{hex32}-{hex16}-({hex16C})\.',          	     '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/user-{users}@({hex32C})-',                     	     '[0-9a-f]*[0-9a-f]',    '@{hex32}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/user-{users}@{hex32}-({hex16C})-',       	     '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/user-{users}@{hex32}-{hex16}-({hex16C})\.',    	     '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/user-{users}@({hex16C})-',            	             '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^{runJ}/log/journal/{hex32}/user-{users}@{hex16}-({hex16C})\.',            	     '[0-9a-f]*[0-9a-f]',    '@{hex16}'), # '@' is a string
(rf'^/var/log/lightdm/seat(\d+)-',                                    		     '[0-9]*',               '@{int}',               'owner'),
(rf'^/var/log/popularity-contest\.(\d+)(?:\.)?$',                                    '[0-9]*',               '@{int}',               'owner'),
(rf'^/var/log/Xorg\.(\d+)\.',                                                        '[0-9]*',               '@{int}',               'owner'),
(rf'^/var/lib/btrfs/scrub\.progress\.({uuidC})$',                                    '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^/var/lib/btrfs/scrub\.status\.({uuidC})(?:_tmp)?$',                             '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^/var/lib/cni/results/cni-loopback-({uuidC})-lo$',                               '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^/var/lib/ca-certificates/openssl/({random8})\.',                                '????????',             '@{rand8}'),
(rf'^/var/lib/update-notifier/tmp\.({random10})$',                                   '??????????',           '@{rand10}'),
(rf'^@?/var/lib/gdm({o3})/',                                                         '{,3}',                  None),
(rf'^@?/var/lib/gdm{o3}/\.cache/ibus/dbus-({random8})$',                             '????????',             '@{rand8}'),
(rf'^/var/lib/gdm{o3}/\.cache/gstreamer-(\d+)$',                                     '[0-9]*',               '@{int}'),
(rf'^/var/lib/gdm{o3}/\.cache/mesa_shader_cache/({hex2C})/',                         '[0-9a-f][0-9a-f]',     '@{h}@{h}'),
(rf'^/var/lib/gdm{o3}/\.cache/mesa_shader_cache/{hex2}/({hex38C})(?:\.tmp)?$',       '[0-9a-f]*[0-9a-f]',    '@{hex}'),   # temp pair? TODO
(rf'^/var/lib/gdm{o3}/\.config/ibus/bus/({hex32C})-',                                '[0-9a-f]*[0-9a-f]',    '@{hex32}'),
#(f'^/var/lib/gdm{o3}/\.config/ibus/bus/{hex32}-unix({oWayland})-{ints}$',           '{,-wayland}',           None),
(rf'^/var/lib/gdm{o3}/\.config/ibus/bus/{hex32}-unix{oWayland}-(\d+)$',              '[0-9]*',               '@{int}'),
(rf'^/var/lib/gdm{o3}/\.local/share/xorg/Xorg\.(\d+)\.',                             '[0-9]*',               '@{int}'),
(rf'^/var/lib/kubelet/pods/({uuidC})/',                                              '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^/var/lib/libvirt/swtpm/({uuidC})/',                                             '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^{homes}/xauth_({random6})$',                                                    '??????',               '@{rand6}',             'owner'),
(rf'^({user_cacheC})/',                                                               None,                  '@{user_cache_dirs}',   'owner'),
(rf'^({user_configC})/',                                                              None,                  '@{user_config_dirs}',  'owner'),
(rf'^{user_cache}/calibre/ev2/[a-z]/[a-z]{2}-({random8})/',                          '????????', 	      None,                  'owner'), # unconventional '_' random tail
(rf'^{user_cache}/fontconfig/({hex32C})-',                                           '[0-9a-f]*[0-9a-f]',    '@{hex32}',             'owner'),
(rf'^{user_cache}/fontconfig/{hex32}-le64\.cache-\d+\.TMP-({random6})$',             '??????',               '@{rand6}',             'owner'),
(rf'^{user_cache}/fontconfig/({uuidC})-',                                            '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(rf'^{user_cache}/gnome-software/icons/({hex38C})-',                                 '[0-9a-f]*[0-9a-f]',    '@{hex}',               'owner'),
(rf'^{user_cache}/gstreamer-(\d+)/',                                                 '[0-9]*',               '@{int}',               'owner'),
(rf'^{user_cache}/event-sound-cache\.tdb\.({hex32C})\.',                             '[0-9a-f]*[0-9a-f]',    '@{hex32}',             'owner'),
(rf'^{user_cache}/mesa_shader_cache/({hex2C})/',                                     '[0-9a-f][0-9a-f]',     '@{h}@{h}',             'owner'),
(rf'^{user_cache}/mesa_shader_cache/{hex2}/({hex38C})(?:\.tmp)?$',                   '[0-9a-f]*[0-9a-f]',    '@{hex}',               'owner'), # temp pair? TODO
(rf'^{user_cache}/thumbnails/[^/]+/({hex32C})\.',                                    '*',                    '@{hex32}',             'owner'),
(rf'^{user_cache}/thumbnails/fail/gnome-thumbnail-factory/({hex32C})\.',             '*',                    '@{hex32}',             'owner'),
(rf'^@?{user_cache}/ibus/dbus-({random8})$',                                         '????????',             '@{rand8}',             'owner'),
(rf'^{user_config}/#(\d+)$',                                                         '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^{user_config}/ibus/bus/({hex32C})-',                                            '[0-9a-f]*[0-9a-f]',    '@{hex32}',             'owner'),
#r(f'^{user_config}/ibus/bus/{hex32}-unix({oWayland})-{ints}$',                       '{,-wayland}',           None,                  'owner'),
(rf'^{user_config}/ibus/bus/{hex32}-unix{oWayland}-(\d+)$',                          '[0-9]*',               '@{int}',               'owner'),
(rf'^{user_config}/vlc/vlcrc\.(\d+)$',                                               '[0-9]*',               '@{int}',               'owner'),
(rf'^{user_config}/vlc/vlc-qt-interface\.conf(|\.{random6})$',                       '{,.??????}',           '{,.@{rand6}}',         'owner'), # unconventional random tail
(rf'^{user_config}/qBittorrent/\.({random6})/',                                      '??????',               '@{rand6}',             'owner'),
(rf'^{user_config}/qBittorrent/qBittorrent-data\.conf(|\.{random6})$',               '{,.??????}',           '{,.@{rand6}}',         'owner'), # unconventional random tail
(rf'^{user_config}/QtProject\.conf(|\.{random6})$',                                  '{,.??????}',           '{,.@{rand6}}',         'owner'), # unconventional random tail
(rf'^{user_config}/qt(|5|6)(?:ct)?/',                                                '{,5,6}',                None,                  'owner'),
(rf'^{user_share}/gvfs-metadata/root-({random8})\.',                                 '????????',             '@{rand8}',             'owner'),
(rf'^{user_share}/kcookiejar/cookies\.({random6})$',                                 '??????',               '@{rand6}',             'owner'),
(rf'^@({hex16})/',                                                                   '????????????????',      None),
(rf'^@?/tmp/\.X11-unix/X(\d+)$',                                                     '[0-9]*',               '@{int}',               'owner'),
(rf'^@?/tmp/\.ICE-unix/(\d+)$',                                                      '[0-9]*',               '@{int}'),
(rf'^@?/tmp/dbus-({random8})$',                                                      '????????',             '@{rand8}' ,            'owner'),
(rf'^@?/tmp/dbus-({random10})$',                                                     '??????????',           '@{rand10}' ,           'owner'),
(rf'^@?/tmp/xauth_({random6})(?:-c|-l)?$',                                           '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/\.dotnet/shm/session(\d+)/',                                               '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^/tmp/\.coreclr\.({random6})/',                                                  '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/\.gnome_desktop_thumbnail\.({random6})$',                                  '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/\.mount_nextcl({random6})/',                                               '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/\.org\.chromium\.Chromium\.({random6})$',                                  '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/\.xfsm-ICE-({random6})$',                                                  '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/\.t?X(\d+)-',                                                              '[0-9]*',               '@{int}',               'owner'),
(rf'^/tmp/adb\.(\d+)\.',		                                             '[0-9]*',               '@{int}',               'owner'),
(rf'^/tmp/akregator\.({random6})\.', 	                                             '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/akregator\.{random6}\.({random6})$',                                       '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/apt-changelog-({random6})/',                                               '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/apt-changelog-{random6}/\.apt-acquire-privs-test\.({random6})$',           '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/apt\.data\.({random6})$',                                                  '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/apt-dpkg-install-({random6})/',                                            '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/apt-key-gpghome\.({random10})/',                                           '??????????',           '@{rand10}',            'owner'),
(rf'^/tmp/apt-key-gpghome\.{random10}/\.#lk0x({hex16C})\.',                          '[0-9a-f]*[0-9a-f]',    '@{hex}',               'owner'),
(rf'^/tmp/apt-key-gpghome\.{random10}/\.#lk0x{hex16}\.debian-stable\.(\d+)x?$',      '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^/tmp/aurules\.({random8})$',                                                    '????????',             '@{rand8}',             'owner'),
(rf'^/tmp/calibre_\d+\.\d+\.\d+_tmp_({random8})/',                                   '????????',             '@{rand8}',             'owner'),
(rf'^/tmp/clr-debug-pipe-(\d+)-',                                                    '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^/tmp/clr-debug-pipe-{ints}-(\d+)-',                                             '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^/tmp/config-err-({random6})$',                                                  '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/dotnet-diagnostic-(\d+)-',                                                 '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^/tmp/dotnet-diagnostic-{ints}-(\d+)-',                                          '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^/tmp/dpkg\.({random6})/',                                                       '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/fz[0-9]temp-(\d+)/',                                                       '[0-9]*',               '@{int}',               'owner'),
(rf'^/tmp/gdkpixbuf-xpm-tmp\.({random6})$',                                          '??????',               '@{rand6}' ,            'owner'),
(rf'^/tmp/kcminit\.({random6})$',                                                    '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/librnnoise-(\d+)\.',                                                       '[0-9]*',               '@{int}',               'owner'),
(rf'^/tmp/mozilla-temp-(\d+)$',                                                      '[0-9]*',    	     '@{int}',               'owner'),
(rf'^/tmp/Mozilla({uuidC})-',                                                        '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(rf'^/tmp/Mozilla{literalBackslash}{{({uuidC}){literalBackslash}}}-',                '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(rf'^/tmp/pty(\d+)/',                                                		     '[0-9]*',    	     '@{int}',               'owner'),
(rf'^/tmp/QNapi\.(\d+)$',                                                            '[0-9]*',    	     '@{int}',               'owner'),
(rf'^/tmp/qtsingleapp-quiter-(\d+)-',                                                '[0-9]*',    	     '@{int}',               'owner'),
(rf'^/tmp/qtsingleapp-quiter-{ints}-(\d+)(?:-)?$',                                   '[0-9]*',    	     '@{int}',               'owner'),
(rf'^/tmp/read-file(\d+)/',                                                          '[0-9]*',               '@{int}',               'owner'),
(rf'^/tmp/(?:syscheck,sanity)-squashfs-(\d+)$',                                      '[0-9]*',               '@{int}'),
(rf'^/tmp/server-(\d+)\.',                                                           '[0-9]*',               '@{int}'),
(rf'^/tmp/sort({random6})$',                                                         '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/systemd-private-({hex32C})-',                                              '[0-9a-f]*[0-9a-f]',    '@{hex32}',             'owner'),
(rf'^/tmp/systemd-private-{hex32}-[^/]+\.service-({random6})/',                      '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/sddm-:(\d+)-',           					             '[0-9]*',               '@{int}',               'owner'),
(rf'^/tmp/sddm-:\d+-{random6}$',                      				     '??????',               '@{rand6}',             'owner'),
(rf'^/tmp/talpid-openvpn-({uuidC})$',                                                '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(rf'^/tmp/Temp-({uuidC})/',                                                          '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(rf'^/tmp/tmp\.({random10})/',                                                       '??????????',           '@{rand10}',            'owner'),
(rf'^/tmp/tmp({random8})/',                                                          '????????',             '@{rand8}',             'owner'),
(rf'^/tmp/user/{users}/tmp\.({random10})$',                                          '??????????',           '@{rand10}',            'owner'),
(rf'^/tmp/({uuidC})$',                                                               '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(rf'^/tmp/wireshark_extcap_ciscodump_(\d+)_',                                        '[0-9]*',               '@{int}',               'owner'),
(rf'^/tmp/zabbix_server_({random6})$',                                               '??????',               '@{rand6}',             'owner'),
(rf'^{run}/cockpit/({random8})$',                                                    '????????',             '@{rand8}'),
(rf'^{run}/gdm({o3})/',                                                              '{,3}',                  None),
(rf'^{run}/netns/cni-({uuidC})$',                                                    '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^{run}/NetworkManager/nm-openvpn-({uuidC})$',                                    '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^{run}/systemd/seats/seat(\d+)$',                                                '[0-9]*',               '@{int}'),
(rf'^{run}/systemd/netif/links/(\d+)$',                                              '[0-9]*',               '@{int}'),
(rf'^{run}/systemd/(?:sessions|inhibit)/(.+)\.ref$',                                 '*',                     None),
(rf'^{run}/snapper-tools-({random6})/',                                              '??????',               '@{rand6}',             'owner'),
(rf'^{run}/user/{users}/\.dbus-proxy/[a-z]+-bus-proxy-({random6})$',                 '??????',               '@{rand6}',             'owner'),
(rf'^{run}/user/{users}/at-spi/bus_(\d+)$',                                          '[0-9]*',               '@{int}',               'owner'),
(rf'^{run}/user/{users}/akregatorbWqrit\.(\d+)\.',                                   '[0-9]*',               '@{int}',               'owner'),
(rf'^{run}/user/{users}/discover({random6})\.',                                      '??????',               '@{rand6}'),
(rf'^{run}/user/{users}/kmozillahelper({random6})\.',                                '??????',               '@{rand6}',             'owner'),
(rf'^{run}/user/{users}/kmozillahelper{random6}\.(\d+)\.',                           '[0-9]*[0-9]',          '@{int}',               'owner'),
(rf'^{run}/user/{users}/wayland-(\d+)(?:\.lock)?$',                                  '[0-9]*',               '@{int}',               'owner'),
(rf'^{run}/user/{users}/webkitgtk/[a-z]+-proxy-({random6})$',                        '??????',               '@{rand6}',             'owner'),
(rf'^{run}/user/{users}/xauth_({random6})$',                                         '??????',               '@{rand6}',             'owner'),
(rf'^{run}/user/{users}/pipewire-(\d+)$',                                            '[0-9]*',               '@{int}',               'owner'),
(rf'^{run}/user/{users}/snap\.snapd-desktop-integration/wayland-cursor-shared-({random6})$', '??????',       '@{rand6}',             'owner'),
(rf'^{sys}/block/zram(\d+)/',                                                        '[0-9]*',               '@{int}'),
(rf'^{sys}/bus/pci/slots/(\d+)/',                                                    '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/{pciBus}/({pciIdC})/',                                            '????:??:??.?',         '@{pci_id}'),
(rf'^{sys}/devices/{pciBus}/{pciId}/({pciIdC})/',                                    '????:??:??.?',         '@{pci_id}'),
(rf'^{sys}/devices/{pciBus}/{pciId}/[^/]+/host(\d+)/',                               '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/{pciBus}/{pciId}/(?:{pciId}/)?drm/card(\d+)/',                    '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/{pciBus}/{pciId}/(?:{pciId}/)?drm/card{ints}/metrics/({uuidC})/', '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^{sys}/devices/pci({pciBusC})/',                                                 '????:??',               None),
(rf'^{sys}/devices/({pciBusC})/',                                                     None,                  '@{pci_bus}'),
(rf'^{sys}/devices/i2c-(\d+)/',                                                      '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/platform/serial\d+/tty/ttyS?(\d+)/',                              '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/system/cpu/cpu(\d+)/',                                            '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/system/cpu/cpufreq/policy(\d+)/',                                 '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/system/memory/memory(\d+)/',                                      '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/system/node/node(\d+)/',                                          '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/virtual/tty/tty(\d+)/',                                           '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/virtual/hwmon/hwmon(\d+)/',                                       '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/virtual/block/dm-(\d+)/',                                         '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/virtual/vc/[a-z]+(\d+)/',                                         '[0-9]*',               '@{int}'),
(rf'^{sys}/devices/virtual/block/dm-(\d+)/',                                         '[0-9]*',               '@{int}'),
(rf'^{sys}/fs/cgroup/user\.slice/user-{users}\.slice/user@@{users}\.service/app\.slice/app-gnome-org\.gnome\.Epiphany-(\d+)\.', '[0-9]*', '@{int}'),
(rf'^{sys}/fs/btrfs/({uuidC})/',                                                     '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^{sys}/firmware/efi/efivars/[^/]+-({uuidC})$',                                   '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(rf'^{sys}/kernel/iommu_groups/(\d+)/',                                              '[0-9]*',               '@{int}'),
(rf'^{proc}/{pids}/fdinfo/(\d+)$',                                                   '[0-9]*',               '@{int}',               'owner'),
(rf'^{proc}/sys/net/ipv(4|6)/',                                                      '{4,6}',                 None),
(rf'^{proc}/irq/(\d+)/',                                                             '[0-9]*',               '@{int}'),
(rf'^/dev/cpu/(\d+)/',                                                               '[0-9]*',               '@{int}'),
(rf'^/dev/dri/card(\d+)$',                                                           '[0-9]*',               '@{int}'),
(rf'^/dev/dm-(\d+)$',                                                                '[0-9]*',               '@{int}'),
(rf'^/dev/input/event(\d+)$',                                                        '[0-9]*',               '@{int}'),
(rf'^/dev/loop(\d+)$',                                                               '[0-9]*',               '@{int}'),
(rf'^/dev/media(\d+)$',                                                              '[0-9]*',               '@{int}'),
(rf'^/dev/parport(\d+)$',                                                            '[0-9]*',               '@{int}'),
(rf'^/dev/pts/(\d+)$',                                                               '[0-9]*',               '@{int}',               'owner'),
(rf'^/dev/shm/sem\.({random6})$',                                                    '??????',               '@{rand6}',             'owner'),
(rf'^/dev/shm/sem\.mp-(\w+)$',                                                       '????????',              None,                  'owner'),
(rf'^/dev/shm/dunst-({random6})$',                                                   '??????',               '@{rand6}',             'owner'),
(rf'^/dev/tty(\d+)$',                                                                '[0-9]*',               '@{int}',               'owner'),
(rf'^/dev/ttyS(\d+)$',                                                               '[0-9]*',               '@{int}',               'owner'),
(rf'^/dev/vfio/(\d+)$',                                                              '[0-9]*',               '@{int}'),
(rf'^/dev/video(\d+)$',                                                              '[0-9]*',               '@{int}'),
(rf'/#(\d+)$',                                                                       '[0-9]*[0-9]',          '@{int}'),
(rf'/\.goutputstream-({random6})$',                                                  '??????',               '@{rand6}'),
(rf'/\.uuid\.TMP-({random6})$',                                                      '??????',               '@{rand6}'),
(rf'/\.mutter-Xwaylandauth\.({random6})$',                                           '??????',               '@{rand6}'),
(rf'/file({random6})$',                                                              '??????',               '@{rand6}'),
(rf'/gnome-control-center-user-icon-({random6})$',                                   '??????',               '@{rand6}'),
(rf'/blkid\.tab-({random6})$',                                                       '??????',               '@{rand6}'),
(rf'/nvidia-xdriver-({random8})$',                                                   '????????',             '@{rand8}'),
(rf'/socket-({random8})$',                                                           '????????',             '@{rand8}'),
(rf'/pulse/({hex32C})-runtime(?:\.tmp)?$',                                           '[0-9a-f]*[0-9a-f]',    '@{hex32}'),  # temp pair? TODO
(rf'/({random6})\.(?:tmp|TMP)$',                                                     '??????',               '@{rand6}',             'owner'),
(rf'/({random8})\.(?:tmp|TMP)$',                                                     '????????',             '@{rand8}',             'owner'),
(rf'/({random10})\.(?:tmp|TMP)$',                                                    '??????????',           '@{rand10}',            'owner'),
(rf'^(/home/{Any})/',                                                                '@{HOME}',               None,                  'owner'), # before the last; tunable isn't matching unix lines
(rf'^@/home/({Any})/',                                                               '*',                     None,                  'owner'), # last; fallback for unix lines
(rf'^(/{oUsr}lib(?:exec|32|64)?)/',                                                   None,                  '@{lib}'),  # last <3
(rf'^({BinC})/',                                                                      None,                  '@{bin}'),  # last <3
(rf'^/({oUsr}s)bin/',                                                                '{,usr/}{,s}',           None),     # last <3 (to match unhandled)
(rf'^/({oUsr}local/)bin',                                                            '{,usr/}{,local/}',      None),     # last <3
(rf'^/({oUsrC})bin/',                                                                '{,usr/}',               None),     # last <3
(rf'^/({oUsrC})lib/',                                                                '{,usr/}',               None),     # last <3
    ]
    tunables = [  # default tunables only
(rf'^/{oUsr}lib/({multiarchC})/',                                                    '@{multiarch}',          None),
(rf'^({etc_ro})/',                                                                   '@{etc_ro}',             None),
(rf'^/dev/shm/lttng-ust-wait-{ints}-({usersC})$',                                    '@{uid}',                None,                  'owner'),
(rf'^{runJ}/log/journal/{hex32}/user-({usersC})(?:@|\.)',                            '@{uid}',                None),
(rf'^/var/log/Xorg\.pid-({pidsC})\.',                                                '@{pid}',                None,                  'owner'),
(rf'^{homes}/(Desktop)/',                                                            '@{XDG_DESKTOP_DIR}',    None,                  'owner'),
(rf'^{homes}/(Downloads)/',                                                          '@{XDG_DOWNLOAD_DIR}',   None,                  'owner'),
(rf'^{homes}/(Templates)/',                                                          '@{XDG_TEMPLATES_DIR}',  None,                  'owner'),
(rf'^{homes}/(Public)/',                                                             '@{XDG_PUBLICSHARE_DIR}',None,                  'owner'),
(rf'^{homes}/(Documents)/',                                                          '@{XDG_DOCUMENTS_DIR}',  None,                  'owner'),
(rf'^{homes}/(Music)/',                                                              '@{XDG_MUSIC_DIR}',      None,                  'owner'),
(rf'^{homes}/(Pictures)/',                                                           '@{XDG_PICTURES_DIR}',   None,                  'owner'),
(rf'^{homes}/(Videos)/',                                                             '@{XDG_VIDEOS_DIR}',     None,                  'owner'),
(rf'^({user_shareC})/',                                                              '@{user_share_dirs}',    None,                  'owner'),
(rf'^({runC})/',                                                                     '@{run}',                None),
(rf'^{run}/user/({usersC})/',                                                        '@{uid}',                None,                  'owner'),
(rf'^{run}/systemd/users/({usersC})$',                                               '@{uid}',                None),
(rf'^({sysC})/',                                                                     '@{sys}',                None),
(rf'^{sys}/fs/cgroup/user\.slice/user-({usersC})\.',                                 '@{uid}',                None),
(rf'^{sys}/fs/cgroup/user\.slice/user-{users}\.slice/user@({usersC})\.',             '@{uid}',                None),  # '@' is a string
(rf'^({procC})/',                                                                    '@{PROC}',               None),
(rf'^{proc}/({pidsC})/',                                                             '@{pid}',                None,                  'owner'),
(rf'^{proc}/{pids}/task/({tidsC})/',                                                 '@{tid}',                None,                  'owner'),
(rf'^/tmp/tracker-extract-3-files.({usersC})/',                                      '@{uid}',                None,                  'owner'),
(rf'^/tmp/user/({usersC})/',                                                         '@{uid}',                None,                  'owner'),
(rf'^/tmp/user/{users}/Temp-({uuidC})/',                                             '@{uuid}',               None,                  'owner'),
    ]
    lineType = findLineType(l)
    if lineType != 'UNIX':
        tunables.extend(regexpToMacro)  # tunables come first
        regexpToMacro = tunables

    path = l.get(key)
    hexToString_Out = hexToString(path)
    if hexToString_Out != path:  # changed
        path = hexToString_Out
        l[key] = path

    # Backslash special characters after decoding and before PCRE replacement
    pcreChars = (']', '[', '*', '}', '{', '?', '^', '"', "'")  # literal backslashes aren't handled
    for i in pcreChars:
        occurences = range(l.get(key).count(i))
        for j in occurences:
            regexp = f'(?<!{literalBackslash})()\\{i}'  # do not match already escaped
            subGroup = substituteGroup(l.get(key), '\\', regexp)
            if subGroup[0]:
                resultPath = subGroup[0]
                subSpan = subGroup[1]
                l[key] = resultPath
                updatePostcolorizationDiffs(l, subSpan, '', key)

    # Attempt to substitute matches in path one by one
    for t in regexpToMacro:
        regexp = t[0]
        d      = t[1]  # default
        a      = t[2]  # apparmor.d
        if not d and not a:
            raise ValueError('No rule style choices. Check your regexes.')

        # Assign chosen style, fallback to default if absent
        # Always choose default for unix line
        # Lastly, skip if default is absent
        if   (ruleStyle == 'default' or \
              lineType  == 'UNIX')   and \
          not d:

            continue

        elif lineType == 'UNIX':
            macro = d

        elif ruleStyle == 'AppArmor.d' and a:
            macro = a

        else:
            macro = d

        path = l.get(key)  # fetch again in case it had changed
        subGroup = substituteGroup(path, macro, regexp)
        if subGroup[0]:
            resultPath = subGroup[0]
            subSpan = subGroup[1]
            oldDiff = subGroup[2]
            l[key] = resultPath
            updatePostcolorizationDiffs(l, subSpan, oldDiff, key)
            if len(t) >= 4:
                l[f'{key}_prefix'] = t[3]

    return l

def adaptDbusPaths(lines, ruleStyle):

    # First capture but not (second) match; 'C' for capture
    Any    = r'(?!@{.+|{.+|\[0-9.+|\*)[^/]+'
    usersC = r'(?:[0-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9})'
    hex32C = r'(?:[0-9a-fA-F]{32})'
    uuidC  = r'(?:[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})'
    regexpToMacro = (
 # regex                                              # default  # apparmor.d
(rf'^/org/freedesktop/ColorManager/devices/({Any})$',  '*',       None),
(rf'^/org/freedesktop/login1/session/({Any})$',        '*',       None),
(rf'^/org/freedesktop/systemd1/unit/({Any})$',         '*',       None),
(rf'^/org/freedesktop/UDisks2/drives/({Any})$',        '*',       None),
(rf'^/org/freedesktop/UDisks2/block_devices/({Any})$', '*',       None),
(rf'^/org/freedesktop/UPower/devices/({Any})$',        '*',       None),
 # Capturing *any* goes above
(rf'/User({usersC})(?:/|$)',                           '@{uid}',  None),
(rf'/({uuidC})(?:/|$)',                                '*',       '@{uuid}'),
(rf'/org/bluez/obex/({uuidC})$',                       '*',       '@{uuid}'),
(rf'/icc_({hex32C})$',                                 '*',       '@{hex32}'),
(rf'/(\d+)$',                                          '[0-9]*',  '@{int}'),
(rf'/(\d+)/',                                          '[0-9]*',  '@{int}'),  # separate to mitigate overlaping
(rf'/_(\d+)$',                                         '[0-9]*',  '@{int}'),
(rf'/Client(\d+)(?:/|$)',                              '[0-9]*',  '@{int}'),
(rf'/ServiceBrowser(\d+)(?:/|$)',                      '[0-9]*',  '@{int}'),
(rf'/seat(\d+)$',                                      '[0-9]*',  '@{int}'),
(rf'/Source_(\d+)(?:/|$)',                             '[0-9]*',  '@{int}'),
(rf'/prompt/u(\d+)$',                                  '[0-9]*',  '@{int}'),
(rf'/Prompt/p(\d+)$',                                  '[0-9]*',  '@{int}'),
(rf'/loop(\d+)$',                                      '[0-9]*',  '@{int}'),  # unreachable?
    )

    for profile in lines:
        for l in lines[profile]:
            if not findLineType(l).startswith('DBUS'):
                raise ValueError('Using this function to handle non-DBus log lines could lead to silent errors.')

            if not l.get('path'):  # skip bind, eavesdrop, etc
                continue

            for r,d,a in regexpToMacro:
                if ruleStyle == 'AppArmor.d' and a:
                    macro = a
                else:
                    macro = d

                path = l.get('path')
                subGroup = substituteGroup(path, macro, r)
                if subGroup[0]:
                    subPath = subGroup[0]
                    subSpan = subGroup[1]
                    oldDiff = subGroup[2]
                    l['path'] = subPath
                    updatePostcolorizationDiffs(l, subSpan, oldDiff, 'path')

    return lines

def findTempTailPair(filename, ruleStyle):
    '''Intended only for temp pairs'''
    # Fallback to default if style have 'None'
    tempRegexesToMacro = (
        # regex                 # default style      # apparmor.d style
        (r'\.tmp$',             '{,.tmp}',           None),
        (r'~$',                 '{,~}',              None),
        (r'\.[A-Z0-9]{6}$',     '{,.??????}',        '{,.@{rand6}}'),
        (r'\.tmp[A-Z0-9]{6}$',  '{,.tmp??????}',     '{,.tmp@{rand6}}'),
        (r'\.tmp[0-9]{4}$',     '{,.tmp????}',       '{,.tmp@{int}}'),
    )
    # TODO
    # /usr/share/applications/mimeinfo.cache
    # /usr/share/applications/.mimeinfo.cache.JLI8D2

    for r,d,a in tempRegexesToMacro:
        suffixRe = re.search(r, filename)
        if suffixRe:
            tempTail = suffixRe.group(0)
            if ruleStyle == 'AppArmor.d' and a:
                macro = a
            else:
                macro = d

            break
    else:
        tempTail = None
        macro    = None

    return (tempTail, macro)

def highlightWords(string_, isHighlightVolatile=True):
    '''Sensitive words should not have false-positives, volatile words are expected to have false-positives
       Volatile is for those paths which could not be unequivocally normalized
       Repeating, non-positional patterns must be greedy
       Capturing group is the highlight'''

    ignorePath = '/usr/share'

    sensitivePatterns = (  # with Red; re.I
        r'/\.ssh/(id[^.]+)(?!.*\.pub)(?:/|$)',
        r'/(ssh_host_[^/]+_key(?:[^.]|))(?!.*\.pub)',
        r'(?<!pubring\.orig\.)(?<!pubring\.)(?<!mouse)(?<!turn|whis|flun|dove|alar|rick|apt-|gtk-)(?<!hot|hoc|don|mon|tur|coc|joc|lac|buc|soc|haw|pun|tac|flu|dar|sna|smo|cri|coo|pin|din|dic)(?<!ca|mi)(key)(?!button|stroke|board|punch|less|code|pal|pad|gen|\.pub|word\.cpython|-manager-qt_ykman\.png|-personalization-gui\.png|-personalization-gui_yubikey-personalization-gui\.png)', # only key; NOT: turkey, keyboard, keygen, etc
        r'(?<!/ISRG_)(?<!grass|snake|birth|colic|coral|arrow|blood|orris|bread|squaw|fever|itter|inger)(?<!worm|alum|rose|club|pink|beet|poke|musk|fake)(?<!tap|che|red|she)(?<!sc|ch)(root)(?!stalk|worm|stock|less|s)', # only root; NOT: grassroots, rootless, chroot, etc
        r'(?<!non)(secret)(?!agogue|ion|ary|ari)', # only secret, secrets; NOT: nonsecret, secretary, etc
        r'(?<!non|set)(priv)(?!ate\.CoreLib|atdocent|atdozent|iledge|ates|ation|ateer|atise|arize|atist|ation|er|et|es|ed|ie|al|y|e)', # only priv, private; NOT: nonprivate, privatise, etc
        r'(?<!com|sur|out)(pass)(?!word-symbolic\.svg|epied|erine|enger|along|ible|erby|able|less|band|ivi|ive|age|ade|ion|ed|el|er|wd)', # only pass, password; NOT: compass, passage, etc
        r'(?<!over|fore)(?<!be)(shadow)(?!coord|graph|iest|like|less|map|ing|ily|ers|box|ier|er|ed|y|s)', # only shadow; NOT: foreshadow, shadows, etc
        r'(?<!na|sa|ac)(cred)(?!ulous|ulity|uliti|enza|ence|ibl|ibi|al|it|o)', # only cred, creds, credentials; NOT: sacred, credence, etc
        r'(?:/|^)(0)(?:/|$)', # standalone zero: 0, /0, /0/; NOT: a0, 0a, 01, 10, 101, etc
        r'^(?:/proc|@{PROC})/(1)/',
        r'^(?:/proc|@{PROC})(?:/\d+|/@{pids?})?/(cmdline)$',
        r'(cookies)\.sqlite(?:-wal)?$',
        r'(cookiejar)',
        )
    random6  = r'(?![0-9]{6}|[a-z]{6}|[A-Z]{6}|[A-Z][a-z]{5}|[A-Z][a-z]{4}[0-9]|base\d\d|\d{5}x|sha\d{3}|[a-z]{5}\d|UPower)[0-9a-zA-Z]{6}' # aBcXy9, AbcXyz, ABCXY9; NOT 123789, abcxyz, ABCXYZ, Abcxyz, Abcxy1, base35, 12345x, abcxy9
    random8  = r'(?<!arphic-)(?![0-9]{8}|[a-z]{8}|[A-Z]{8}|[A-Z][a-z]{7}|[A-Z][a-z]{6}[0-9]|[a-z]{7}\d|GeoClue\d)[0-9a-zA-Z]{8}' # aBcDwXy9, AbcdWxyz, ABCDWXY9; NOT: 12346789, abcdwxyz, ABCDWXYZ, Abcdwxyz, Abcdwxy1, abcdwxy9
    random10 = r'(?![0-9]{10}|[a-z]{10}|[A-Z]{10}|[A-Z][a-z]{9}|[A-Z][a-z]{8}[0-9]|PackageKit|PolicyKit\d)[0-9a-zA-Z]{10}' # aBcDeVwXy9, AbcdeVwxyz, abcdevwxy9, ABCDEVWXY9; NOT: 1234567890, abcdevwxyz, ABCDEVWXYZ, Abcdevwxyz, Abcdevwxy1, PackageKit
    volatilePatterns = (  # with Yellow
        r'/#(\d+)$',  # trailing number with leading hash sign
        r'[-./@](1000)(?:/|$)',  # first user id
       rf'[-.]({random6})(?:/|$)',
       rf'[-.]({random8})(?:/|$)',
       rf'[-.]({random10})(?:/|$)',
       rf'/(?:var/)?tmp/({random6})(?:/|$)',
       rf'/(?:var/)?tmp/({random8})(?:/|$)',
       rf'/(?:var/)?tmp/({random10})(?:/|$)',
        r'[-.](?![0-9]{8}|[a-z]{8})([0-9a-z]{8})\.log$',
        r'[-.](?![0-9]{8}|[A-Z]{8})([0-9A-Z]{8})\.log$',
        r'(?=[^0-9a-fA-F]0x([0-9a-fA-F]{16})(?:[^0-9a-fA-F]|$))', # hex address
        r'(?=[^0-9a-fA-F]([0-9a-fA-F]{32})(?:[^0-9a-fA-F]|$))',   # standalone MD5
        r'(?=[^0-9a-fA-F]([0-9a-fA-F]{38})(?:[^0-9a-fA-F]|$))',   # ??
        r'(?=[^0-9a-fA-F]([0-9a-fA-F]{56})(?:[^0-9a-fA-F]|$))',   # standalone SHA224
        r'(?=[^0-9a-fA-F]([0-9a-fA-F]{64})(?:[^0-9a-fA-F]|$))',   # standalone SHA256
        r'(?=[^0-9a-fA-F]([0-9a-fA-F]{96})(?:[^0-9a-fA-F]|$))',   # standalone SHA384
        r'(?=[^0-9a-fA-F]([0-9a-fA-F]{128})(?:[^0-9a-fA-F]|$))',  # standalone SHA512
        r'(?=[^0-9a-fA-F]([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})(?:[^0-9a-fA-F]|$))', # standalone UUID
        r'^@?/home/([^/]+)/', # previously unmatched homes
    )

    if not string_.startswith(ignorePath):
        for r in sensitivePatterns:
            allSpans = []
            sensitiveRe = re.finditer(r, string_, re.I)
            for m in sensitiveRe:
                allSpans.append(m.span(1))
    
            # Begin from the end to mitigate colorization shifting
            allSpans.sort(reverse=True)
    
            for s in allSpans:
                string_ = colorizeBySpan(string_, 'Red', s)
    
        if isHighlightVolatile:
            for r in volatilePatterns:
                allSpans = []
                volatileRe = re.finditer(r, string_)
                for m in volatileRe:
                    allSpans.append(m.span(1))
     
                allSpans.sort(reverse=True)
     
                for s in allSpans:
                    string_ = colorizeBySpan(string_, 'Yellow', s)

    return string_

def findExecType(path):

    always_ix = {  # not for programs with network access or large scope
        'awk',                     'nice',                 
        'base64',                  'nproc',
        'basename',                'od',
        'bunzip2',                 'readlink',
        'bzip2',                   'realpath',
        'cat',                     'rm',
        'chmod',                   'rmdir',
        'chown',                   'sed',
        'cp',                      'seq',
        'cpio',                    'shasum',
        'cut',                     'sha1sum',
        'date',                    'sha224sum',
        'diff',                    'sha256sum',
        'dir',                     'sha384sum',
        'dirname',                 'sha512sum',
        'echo',                    'shred',
        'egrep',                   'sleep',
        'env',                     'sort',
        'expr',                    'strings',
        'false',                   'sync',
        'fgrep',                   'tac',
        'file',                    'tail',
        'find',                    'tar',
        'fold',                    'tempfile',
        'gawk',                    'test',
        'getfacl',                 'timeout',
        'getopt',                  'touch',
        'gettext',                 'tr',
        'grep',                    'true',
        'gzip',                    'uname',
        'head',                    'uniq',
        'id',                      'unzip',
        'ionice',                  'wc',
        'ln',                      'which',
        'locale',                  'which.debianutils',
        'ls',                      'xargs',
        'lz4cat',                  'xz',
        'lzop',                    'xzcat',
        'mawk',                    'zgrep',
        'md5sum',                  'zip',
        'mktemp',                  'zstd',
        'mv',                      'setfacl',
        'unexpand',                'tsort',
        'truncate',                'yes',
        'sum',                     'install',
        'fold',                    'factor',
        'fmt',                     'split',
        'b2sum',                   'base32',
    }
    always_Px = {
        'ps',
        'spice-vdagent',
    }

    if   path in always_ix:
        result = 'i'
    elif path in always_Px:
        result = 'P'
    else:
        result = None

    return result

def adaptProfileAutoTransitions(l):

    # Move automatic transition to the parent
    if '▶' in l.get('profile'):             # only for 'profile'
        split = l.get('profile').split('▶')
        transitionExecType = findExecType(split[-1])
        if transitionExecType == 'i' and \
           split[-1] == l.get('comm'):      # if present in 'always_ix' and equals to 'comm'

            del split[-1]  # delete last automatic transition id
            l['profile'] = '▶'.join(split)  # identify as parent
            l['comm']    = colorize(l.get('comm'), 'Blue')  # colorize imidiately

            binExecType = findExecType(getBaseBin(l.get('name')))
            if binExecType == 'i':
                l['requested_mask'] += 'i'  # mark as possible 'ix' candidate

    return l

def isBaseAbstractionTransition(l, profile_):
    '''Only for file lines. Must be done after normalization and before adaption. Temporary solution?'''
    multiarch   = r'(?:[^/]+-linux-(?:gnu|musl)(?:[^/]+)?|@{multiarch})'
    proc        = r'(?:/proc|@{PROC})'
    etc_ro      = r'(?:/usr/etc|/etc|@{etc_ro})'
    run         = r'(?:/var/run|/run|@{run})'
    sys         = r'(?:/sys|@{sys})'

    baseAbsRules = {  # re.match
       rf'^/dev/log$': {'w'},
       rf'^/dev/u?random$': {'r'},
       rf'^{run}/uuidd/request$': {'r'},
       rf'^{etc_ro}/locale/.+': {'r'},
       rf'^{etc_ro}/locale\.alias$': {'r'},
       rf'^{etc_ro}/localtime$': {'r'},
       rf'^/etc/writable/localtime$': {'r'},
       rf'^/usr/share/locale-bundle/.+': {'r'},
       rf'^/usr/share/locale-langpack/.+': {'r'},
       rf'^/usr/share/locale/.+': {'r'},
       rf'^/usr/share/.+/locale/.+': {'r'},
       rf'^/usr/share/zoneinfo/.*': {'r'},
       rf'^/usr/share/X11/locale/.+': {'r'},
       rf'^{run}/systemd/journal/dev-log$': {'w'},
       rf'^{run}/systemd/journal/socket$': {'w'},
       rf'^{run}/systemd/journal/stdout$': {'r', 'w'},
       rf'^/(|usr/)lib(|32|64)/locale/.+': {'m', 'r'},
       rf'^/(|usr/)lib(|32|64)/gconv/[^/]+\.so$': {'m', 'r'},
       rf'^/(|usr/)lib(|32|64)/gconv/gconv-modules(|[^/]+)$': {'m', 'r'},
       rf'^/(|usr/)lib/{multiarch}/gconv/[^/]+\.so$': {'m', 'r'},
       rf'^/(|usr/)lib/{multiarch}/gconv/gconv-modules(|[^/]+)$': {'m', 'r'},
       rf'^{etc_ro}/bindresvport\.blacklist$': {'r'},
       rf'^{etc_ro}/ld\.so\.cache$': {'m', 'r'},
       rf'^{etc_ro}/ld\.so\.conf$': {'r'},
       rf'^{etc_ro}/ld\.so\.conf\.d/(|[^/]+\.conf)$': {'r'},
       rf'^{etc_ro}/ld\.so\.preload$': {'r'},
       rf'^/(|usr/)lib(|32|64)/ld(|32|64)-[^/]+\.so$': {'m', 'r'},
       rf'^/(|usr/)lib/{multiarch}/ld(|32|64)-[^/]+\.so$': {'m', 'r'},
       rf'^/(|usr/)lib/tls/i686/(cmov|nosegneg)/ld-[^/]+\.so$': {'m', 'r'},
       rf'^/(|usr/)lib/i386-linux-gnu/i686/(cmov|nosegneg)/ld-[^/]+\.so$': {'m', 'r'},
       rf'^/opt/[^/]+-linux-uclibc/lib/ld-uClibc(|[^/]+)so(|[^/]+)$': {'m', 'r'},
       rf'^/(|usr/)lib(|32|64)/.+': {'r'},
       rf'^/(|usr/)lib(|32|64)/.+\.so(|[^/]+)$': {'m', 'r'},
       rf'^/(|usr/)lib/{multiarch}/.+': {'r'},
       rf'^/(|usr/)lib/{multiarch}/.+\.so(|[^/]+)$': {'m', 'r'},
       rf'^/(|usr/)lib/tls/i686/(cmov|nosegneg)/[^/]+\.so(|[^/]+)$': {'m', 'r'},
       rf'^/(|usr/)lib/i386-linux-gnu/i686/(cmov|nosegneg)/[^/]+\.so(|[^/]+)$': {'m', 'r'},
       rf'^/(|usr/)lib(|32|64)/\.lib[^/]+\.so[^/]+\.hmac$': {'r'},
       rf'^/(|usr/)lib/{multiarch}/\.lib[^/]+\.so[^/]+\.hmac$': {'r'},
       rf'^/dev/null$': {'r', 'w',},
       rf'^/dev/zero$': {'r', 'w',},
       rf'^/dev/full$': {'r', 'w',},
       rf'^{proc}/sys/kernel/version$': {'r'},
       rf'^{proc}/sys/kernel/ngroups_max$': {'r'},
       rf'^{proc}/meminfo$': {'r'},
       rf'^{proc}/stat$': {'r'},
       rf'^{proc}/cpuinfo$': {'r'},
       rf'^{sys}/devices/system/cpu/(|online)$': {'r'},
       rf'^{proc}/\d+/(maps|auxv|status)$': {'r'},
       rf'^{proc}/crypto/[^/]+$': {'r'},
       rf'^/usr/share/common-licenses/.+': {'r'},
       rf'^{proc}/filesystems$': {'r'},
       rf'^{proc}/sys/vm/overcommit_memory$': {'r'},
       rf'^{proc}/sys/kernel/cap_last_cap$': {'r'},
       # crypto include (oldest)
       rf'^{etc_ro}/gcrypt/random\.conf$': {'r'},
       rf'^{proc}/sys/crypto/[^/]+$': {'r'},
       rf'^/(etc/|usr/share/)crypto-policies/[^/]+/[^/]+\.txt$': {'r'},
    }

    result = False
    if '▶' in profile_ or isTransitionComm(l.get('comm')):  # transition features
        path      = l.get('path')
        pathMasks = l.get('mask')
        for regex,mask in baseAbsRules.items():
            if 'a' in pathMasks and \
               'w' in mask:     # 'w' consumes 'a'

                mask.add('a')

            if re.match(regex, path)   and \
               pathMasks.issubset(mask):
 
                result = True
                break

    return result

def findBootId(positionalId):

    raise NotImplementedError('Handling previous boot IDs is not yet implemented.')

    return None

def grabJournal(args):

    if not args.keep_status_audit:
        statusTypes = '(?:AVC |USER_AVC )?apparmor="?(ALLOWED|DENIED)'
    else:
        statusTypes = '(?:AVC |USER_AVC )?apparmor="?(ALLOWED|DENIED|AUDIT)'

    disableEpochConvertion = {'__REALTIME_TIMESTAMP': int}
    j = journal.Reader(converters=disableEpochConvertion)
    if args.boot_id:
        hexBootId = findBootId(args.boot_id)
        j.this_boot(hexBootId)
    else:
        j.this_boot()

    j.this_machine()
    j.add_match('SYSLOG_IDENTIFIER=kernel',
                'SYSLOG_IDENTIFIER=audit',
                'SYSLOG_IDENTIFIER=dbus-daemon')  # try to limit spoofing surface

    rawLines = []
    for entry in j:
        if re.search(statusTypes, entry['MESSAGE']):
            rawLines.append(entry)

    return rawLines

def isDbusJournalLine(entry):
    '''"_SELINUX_CONTEXT" is arbitrary, don't use for higher trusts'''
    if   entry.get('SYSLOG_IDENTIFIER') == 'dbus-daemon':
        result = True
    elif entry.get('_SELINUX_CONTEXT')  == 'dbus-daemon':
        result = True
    elif entry.get('_SELINUX_CONTEXT')  == 'dbus-daemon (complain)':
        result = True
    elif entry.get('_SELINUX_CONTEXT')  == 'dbus-daemon (complain)\n':
        result = True
    else:
        result = False

    return result

def findLogLines(rawLines, args):

    toDropDbusKeyValues_inLines = {
        'hostname': '?',
        'addr':     '?',
        'terminal': '?',
        'exe':      '/usr/bin/dbus-daemon',
    }

    lineDicts = []
    latestTimestamp = 0
    trusts_byLine = {}
    timestamps_byLine = {}
    for entry in rawLines:
        normalizedLine = normalizeJournalLine(entry['MESSAGE'], args)
        processedLine = normalizedLine[0]
        trust         = normalizedLine[1]  # dirty or None, expected to be overwritten further
        lineType = findLineType(processedLine)
        if lineType.startswith('DBUS'):  # drop non-informative DBus data
            [processedLine.pop(k) for k,v in toDropDbusKeyValues_inLines.items() if processedLine.get(k) == v]

        if not lineType.startswith('DBUS') and isDbusJournalLine(entry):  # came from DBus, but not a DBus line
            trust = 1

        elif   entry.get('_AUDIT_TYPE_NAME') == 'USER_AVC':
            if not lineType.startswith('DBUS'):
                trust = 3
            else:
                trust = 8

        elif   entry.get('_AUDIT_TYPE_NAME') == 'AVC':
            if   isDbusJournalLine(entry) and entry.get('AUDIT_FIELD_BUS') != 'system':
                trust = 3
            elif entry.get('AUDIT_FIELD_BUS')  == 'system':
                trust = 9
            else:
                trust = 10  # not necessarily top trust

        elif   isDbusJournalLine(entry):  # not matched previously gets lower trust
            trust = 7

        elif   lineType.startswith('DBUS'):  # what line itself tells
            trust = 6

        else: # Finished without falling under other conditions
            trust = 4

        lineId = makeHashable(processedLine)
        lineTrust = trusts_byLine.get(lineId)
        # Only mark to merge if current trust is no less that 4
        if   trust <= 3:
            processedLine['trust'] = trust        # assign imidiately to prevent merging
            lineId = makeHashable(processedLine)  # regenerate the ID
            trusts_byLine[lineId] = trust

        elif lineTrust:  # duplicate line
            # Only mark to merge if current trust is higher than trust for previously gathered line
            if lineTrust <= trust:
                trusts_byLine[lineId] = trust
            # Skip reassigning trust for duplicate line if nothing is matched
        else:  # new line
            trusts_byLine[lineId] = trust

        timestamps_byLine[lineId] = entry['__REALTIME_TIMESTAMP']

        if processedLine in lineDicts:
            lineDicts.remove(processedLine)  # always use most recent line

        lineDicts.append(processedLine)

    for l in lineDicts:
        lineId = makeHashable(l)
        l['timestamp'] = timestamps_byLine.get(lineId)
        if trusts_byLine.get(lineId):
            l['trust'] = trusts_byLine[lineId]
        else:  # guard
            l['trust'] = 2

        if l.get('timestamp') > latestTimestamp:
            latestTimestamp = l.get('timestamp')

    return (lineDicts, latestTimestamp)

def normalizeJournalLine(rawLine, args):

    toSkipKeys = {'audit:', 'AVC', 'capability', 'denied_mask', 'ouid', 'sauid', 'fsuid', 'pid', 'peer_pid', 'type', 'class'}
    if not args.keep_status:
        toSkipKeys.add('apparmor')

    lineList = shlex.split(rawLine)

    # Unwrap nested message
    trust = None
    for i in lineList:
        if re.match('msg=(?:AVC |USER_AVC )?apparmor="?(ALLOWED|DENIED|AUDIT)', i):  # greedy match, type filtering is handled by grabJournal()
            cleaned = i.removeprefix('msg=').strip()
            trust = 5
            lineList = shlex.split(cleaned)
            break

    lineDict = {}
    for l in lineList:
        d = l.split('=')
        key = d[0]
        try:
            val = d[1]
        except:
            val = None  # not a logline pair

        if   key in toSkipKeys:
            continue

        elif key == 'name' and \
             re.match(r':\d+\.\d+', val):

            if args.style == 'AppArmor.d':
                pcreStyle = '.@{int}'
            else:
                pcreStyle = '.[0-9]*'

            adaptedName = re.sub(r'\.\d+$', pcreStyle, val)
            lineDict.update({key: adaptedName})

        elif val:
            lineDict.update({key: val})

    return (lineDict, trust)

def normalizeProfileName(l):
    '''Dealing early with regular operation format (string)'''
    if l.get('operation').startswith('dbus'):
        l['profile'] = l.pop('label')

        if 'peer_label' in l.keys():
            l['peer'] = l.pop('peer_label')

    # Remove 'target' if it's the same as 'name' (path)
    delimiter = '//null-'
    if l.get('target'):
        if delimiter in l.get('target'):
            split = l.get('target').split(delimiter)
            realTarget = split[-1]
            if l.get('name') == realTarget:
                l.pop('target')

    # Make automatic transition more readable
    toChangeKeys = ['profile', 'peer', 'target']
    for k in toChangeKeys:
        if l.get(k):
            if delimiter in l.get(k):
                profileNames = []
                split = l.pop(k).split(delimiter)
                for p in split:
                    baseName = getBaseBin(p)
                    if baseName:
                        path = baseName
                    else:
                        path = p

                    profileNames.append(path)
 
                l[k] = '▶'.join(profileNames)

    return l

def getBaseBin(path):

    grn  = r'\x1b\[0;32m' # (escaped) regular green
    rst  = r'\x1b\[0m'    # (escaped) reset
    regexp = re.match(rf'^(?:/(?:usr/|{grn}{{\,usr/}}{rst}|{grn}{{usr/\,}}{rst})?bin|{grn}@{{bin}}{rst})/([^/]+)$', path)  # 'sbin' isn't covered
    if regexp:
        result = regexp.group(1)
    else:
        result = None

    return result

def composeSuffix(l, keysToHide):
    '''Handles line leftovers'''
    if 'ALL' in keysToHide:
        l = {}
    elif keysToHide:
        if '*_diffs' in keysToHide:
            toDropKeys = ('path_diffs', 'srcpath_diffs', 'target_diffs', 'addr_diffs', 'peer_addr_diffs')
            keysToHide.extend(toDropKeys)
        [l.pop(k) for k in keysToHide if l.get(k)]

    toDropStalePrefixesKeys = ('path_prefix', 'srcpath_prefix', 'target_prefix', 'addr_prefix', 'peer_addr_prefix')
    [l.pop(k) for k in toDropStalePrefixesKeys if l.get(k)]  # drop prefixes which unrelevant anymore

    keys = sorted(l.keys())
    if 'addr_diffs' in keys:
        keys.remove('addr_diffs')
        keys.append('addr_diffs')
    l = {i: l[i] for i in keys}

    s = ''
    for k,v in l.items():
        if isinstance(v, set):
            if 'file_inherit' in v:
                v.remove('file_inherit')
                v.add(colorize('file_inherit', 'Bright Yellow'))
            v = ','.join(sorted(v))

        try:
            if ' ' in v:
                v = f"'{v}'"
        except:
            pass

        # Diffs
        if k.endswith('_diffs'):
            plainDiffs = []
            for subL in v:
                plainDiffs.append(subL[1])
            v = ','.join(plainDiffs)

        s += f'{k}={v} '

    if s:
        s = s.replace(',', colorize(',', 'Bright Blue'))
        s = s.strip()
    else:
        s = None

    return s

def colorize(string_, color, style='0'):
    '''https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
    No nested colorization'''
    colorTable = {
        'Black':          '30', 'Bright Black':   '90',
        'Red':            '31', 'Bright Red':     '91',
        'Green':          '32', 'Bright Green':   '92',
        'Yellow':         '33', 'Bright Yellow':  '93',
        'Blue':           '34', 'Bright Blue':    '94',
        'Magenta':        '35', 'Bright Magenta': '95',
        'Cyan':           '36', 'Bright Cyan':    '96',
        'White':          '37', 'Bright White':   '97',
    }

    if not color in colorTable:
        raise ValueError('Incorrect color specified: ' + color)

    string_ = f'\033[{style};{colorTable[color]}m{string_}\033[0m'

    return string_

def colorizeBySpan(string_, color, span_):

    prefix = string_[:span_[0]]
    macro  = string_[span_[0]:span_[1]]
    suffix = string_[span_[1]:]

    colorizedPart = colorize(macro, color)
    string_ = prefix + colorizedPart + suffix

    return string_

def highlightSpecialChars(string_):
    '''Better to apply after alignment'''
    charsToColors = {
        '=': 'Bright Blue',
        '(': 'Cyan',
        ')': 'Cyan',
        '"': 'Cyan',
        "'": 'Cyan',
    }

    for char,color in charsToColors.items():
        if char in string_:
            string_ = string_.replace(char, colorize(char, color))

    return string_

def hexToString(path_):
    '''For whitespaces and localized paths'''
    # unix addr
    if path_.startswith('@'):
        path_ = path_.removeprefix('@')
        isLeadingAt = True
    else:
        isLeadingAt = False

    for c in path_:
        if c not in string.hexdigits:
            break
    else:
        try:
            path_ = bytes.fromhex(path_).decode('utf-8')
            while path_.endswith('\x00'):  # trim trailing zeroes
                path_ = path_.removesuffix('\x00')
        except:
            pass  # not utf-8

    if isLeadingAt:
        path_ = '@' + path_

    return path_


def substituteGroup(subWhat, subWith, regexp_):
    '''Substitute the capturing group'''
    whatRe = re.search(regexp_, subWhat)
    if whatRe:
        if   len(whatRe.groups()) == 0 or whatRe.group(1) is None:
            raise ValueError('No matching capturing group. Check your regexes.')
        elif len(whatRe.groups()) >= 2:
            raise NotImplementedError('More than one capturing group is not supported. Check your regexes.')
        elif subWith == 'owner':
            raise ValueError('Looks like an error. Check missing commas in your regex tuples.')
#        elif whatRe.group(1).startswith('@{') or \
#             whatRe.group(1).startswith('{')  or \
#             whatRe.group(1).startswith('['):
#            print('Second attempt to capture an already substituted match. This is unnecessary and will lead to malformed diffs. Check your regexes.', file=sys.stderr)
#            print(whatRe,          file=sys.stderr)
#            print(whatRe.group(1), file=sys.stderr)

        oldDiff = whatRe.group(1)
        span = whatRe.span(1)
        pathPrefix = subWhat[:span[0]]
        pathSuffix = subWhat[span[1]:]
        adjustedEndIndex = span[0] + len(subWith)
        span = (span[0], adjustedEndIndex)
        resultPath = pathPrefix + subWith + pathSuffix

    else:
        resultPath = None
        span       = None
        oldDiff    = None

    return (resultPath, span, oldDiff)

def updatePostcolorizationDiffs(l, currentSpan, currentDiff, key):
    '''After each replacement in path, spans determined for colorization can and will shift, breaking the colorization.
       Such cases are being adjusted here.
    '''
    diffs = l.get(f'{key}_diffs')
    if diffs:
        # Determine the shift padding
        oldLen = len(currentDiff)
        newLen = currentSpan[1] - currentSpan[0]
        padding = newLen - oldLen

        # Add new diff to already present ones and sort by span
        currentItem = [currentSpan, currentDiff]
        diffs.append(currentItem)
        sortedDiffs = sorted(diffs, key=lambda t: t[0])

        # Slice sorted list of diffs by current item
        currentIndex = sortedDiffs.index(currentItem)
        leftDiffs  = sortedDiffs[:currentIndex]    # preserve correct items
        rightDiffs = sortedDiffs[currentIndex+1:]  # do not match the current item

        # Only elements to the right need to be shifted
        for s,d in rightDiffs:
            newSpan = (s[0] + padding, s[1] + padding)
            leftDiffs.append([newSpan, d])

        leftDiffs.append(currentItem)  # preserve current item
        resultDiffs = sorted(leftDiffs, key=lambda t: t[0])  # sort again for tests sake
        l[f'{key}_diffs'] = resultDiffs

    # No problems on first replacement
    else:
        l[f'{key}_diffs'] = [[currentSpan, currentDiff]]

    return l

def findLineType(l):
    '''Handles regular and custom operations (sets), but only for file, DBus and network rules'''
    fileOperations = {
        'exec',        'open',
        'getattr',     'mknod',
        'rename_src',  'rename_dest',
        'symlink',     'unlink',
        'mkdir',       'rmdir',
        'chown',       'chmod',
        'file_mmap',   'file_lock',
        'truncate',    'link',
        'connect',     'file_perm',
        'sendmsg',     'recvmsg',
        'file_receive',
        'file_inherit',
    }
    networkOperations = {
        'listen',      'connect',
        'bind',        'create',
        'sendmsg',     'recvmsg',
        'getsockname',
        'getsockopt',  'setsockopt',
        'file_inherit',
    }

    operation = l.get('operation')
    if isinstance(operation, set):
        for e in operation:
            operation = e  # other items will be the same type
            break

    if not operation:
        result = 'NONE'

    elif   operation in fileOperations and \
       not l.get('sock_type'):

        result = 'FILE'

    elif operation.startswith('dbus'):
        result = 'DBUS'

    elif operation in networkOperations and \
       l.get('sock_type')               and \
       l.get('family') != 'unix':

        result = 'NETWORK'

    elif l.get('family') == 'unix':  # depends on earlier 'NETWORK' condition
        result = 'UNIX'

    elif operation == 'capable':
        result = 'CAPABILITY'

    elif operation == 'signal':
        result = 'SIGNAL'

    elif operation == 'ptrace':
        result = 'PTRACE'

    elif operation.endswith('mount'):  # mount, umount, remount
        result = 'MOUNT'

    elif operation == 'pivotroot':
        result = 'PIVOT'

    else:
        result = 'UNKNOWN'

    return result

def composeFileMask(maskSet, transitionMask, isConvertToUsable):
    '''Convert mask set to string, sorting by pattern and highlight special cases.'''
    maskPrecedence = 'mriPUCpuxwadclk'
    toColorize = {}

    if 'P' in maskSet:
        toColorize['P'] = ('White', '1')  # bold

    if 'N' in maskSet:
        maskSet.remove('N')
        maskSet.add('P')
        toColorize['P'] = ('Bright Black', '7')  # background

    # Determine additional mask from automatic transition
    if transitionMask:
        maskDiff = maskSet.intersection(transitionMask)
        for i in maskDiff:
            toColorize[i] = ('Blue', '0')  # regular
            if 'i' in maskSet and \
               'x' in maskSet:

                toColorize['i'] = ('White', '1')  # bold

    # Add accompanied masks
    accompaniedMasks = {
        'x': 'r',  # 'x' should be always accompanied by 'r'
    }
    for k,v in accompaniedMasks.items():
        if len(k) != 1 or len(v) != 1:
            raise NotImplementedError('Accompanied key:value masks are expected to be single characters')

        if k in maskSet:
            if v not in maskSet:  # colorize only if not present
                toColorize[v] = ('White', '1')  # bold
                maskSet.add(v)

    # Convert not yet implemented to usable
    notImplemented = {'d', 'c'}
    if isConvertToUsable:
        for i in notImplemented:
            if i in maskSet:
                maskSet.add('w')
                maskSet.remove(i)
                toColorize['w'] = ('Green', '0')  # regular

    # Ommit mutually exclusive
    if 'w' in maskSet and \
       'a' in maskSet:

        maskSet.remove('a')
 
    # Sort
    maskList = []
    for s in maskPrecedence:
        if s in maskSet:
            maskList.append(s)
            maskSet.remove(s)

    # Determine what to colorize as dangerous combinations; takes precedence as final (rewrite)
    dangerousCombinations = (
        ('x', 'wadclk'),
        ('m', 'wadclk'),
    )
    for s1,s2 in dangerousCombinations:
        if len(s1) >= 2:  # sanity
            raise ValueError('Leading mask for comparison could only be a single character.')

        for subS in s2:
            if   s1 in maskList and \
               subS in maskList:
                toColorize[s1]   = ('Red', '7')  # background
                toColorize[subS] = ('Red', '7')  # background

    # Final colorization
    for k,v in toColorize.items():
        color      = v[0]
        colorStyle = v[1]
        highlight = colorize(k, color, colorStyle)
        for n,i in enumerate(maskList):
            if k == i:
                maskList[n] = highlight
                break

    # Combine into string and preserve unknown masks
    maskString = ''.join(maskList)
    if maskSet:
        suffix = ''.join(sorted(maskSet))
        maskString += suffix

    return maskString

def composeMembers(lines):
    '''Sort and encase DBus members. Expected after processing and before line sorting'''
    for profile in lines:
        for l in lines[profile]:
            if l.get('member'):
                if len(l.get('member')) >= 2:
                    membersList = sorted(l.pop('member'))
                    members = ','.join(membersList)
                    l['member'] = '{%s}' % members
                elif l.get('member'):
                    l['member'] = '_BUG_'.join(l.pop('member'))

    return lines

def groupLinesByProfile(lines):
    '''Group all profile-related log lines as list-value under each profile as key'''
    profiles = []
    for l in lines:
        p = l.get('profile')
        if p not in profiles:
            profiles.append(p)
    profiles.sort()

    dictOfListsOfLines_byProfile = {}
    for p in profiles:
        profileLines = []
        for l in lines:
            if p == l.get('profile'):
                l.pop('profile')  # key became profile at this point
                profileLines.append(l)

        if profileLines:
            dictOfListsOfLines_byProfile[p] = profileLines

    return dictOfListsOfLines_byProfile

def makeHashable(l):
    '''With limited case coverage'''
    if l.get('timestamp'):
        raise ValueError('Hashing a line with a timestamp will always result in unique hash')

    L = dict(l)
    for k,v in L.items():
        if   isinstance(v, set):
            L[k] = sorted(v)

        elif isinstance(v, dict):
            L[k] = sorted(v.items())

    result = str(sorted(L.items()))

    return result

def mergeDictsBySingleKey(lines, key):
    '''Merge dictionaries if specified key is the only difference, preserving both keys'''
    newDictOfListsOfLines_byProfile = {}
    for profile in lines:
        differences_byId = {}
        suffixes_byId = {}
        newLogLines_forProfile = []
        for l in lines[profile]:
            if not l.get(key):
                newLogLines_forProfile.append(l)  # save non-mergable
                continue

            if 'file_inherit' in l.get('operation'):
                newLogLines_forProfile.append(l)
                continue

            diff = l.pop(key)
            if not isinstance(diff, set):
                raise NotImplementedError('Could merge diff sets only')

            timestamp = l.pop('timestamp')
            lineId    = makeHashable(l)
            if not lineId in differences_byId:
                differences_byId[lineId] = diff
            else:
                differences_byId[lineId].update(diff)

            suffix = l  # leftovers
            suffix['timestamp'] = timestamp  # use only the latest timestamp for duplicates
            suffixes_byId[lineId] = suffix

        for lineId,merged in differences_byId.items():
            logLine = suffixes_byId.get(lineId)
            logLine[key] = merged
            newLogLines_forProfile.append(logLine)

        newDictOfListsOfLines_byProfile[profile] = newLogLines_forProfile

    return newDictOfListsOfLines_byProfile

def mergeDictsByKeyPair(lines, firstKey, secondKey):

    newDictOfListsOfLines_byProfile = {}
    for profile in lines:
        newLogLines_forProfile = []
        pair_byId = {}
        suffixes_byId = {}
        for l in lines[profile]:
            if not l.get(firstKey) or \
               not l.get(secondKey):
                newLogLines_forProfile.append(l)  # save non-mergable
                continue

            if 'file_inherit' in l.get('operation'):
                newLogLines_forProfile.append(l)
                continue

            firstVal  = l.pop(firstKey)
            secondVal = l.pop(secondKey)
            if not isinstance(firstVal,  set) or \
               not isinstance(secondVal, set):
                raise NotImplementedError('Could merge diff sets only')

            timestamp = l.pop('timestamp')
            lineId = makeHashable(l)
            if not lineId in pair_byId:
                pair_byId[lineId] = [firstVal, secondVal]

            else:
                sublist = pair_byId.get(lineId)
                mergedFirstVals  = sublist[0]
                mergedSecondVals = sublist[1]
                mergedFirstVals.update(firstVal)
                mergedSecondVals.update(secondVal)
                pair_byId[lineId] = [mergedFirstVals, mergedSecondVals]

            suffix = l  # leftovers
            suffix['timestamp'] = timestamp  # use only the latest timestamp for duplicates
            suffixes_byId[lineId] = suffix

        # Collect back the lines for each profile
        for lineId,sublist in pair_byId.items():
            logLine = suffixes_byId.get(lineId)
            mergedFirstVals  = sublist[0]
            mergedSecondVals = sublist[1]
            logLine[firstKey]  = mergedFirstVals
            logLine[secondKey] = mergedSecondVals
            newLogLines_forProfile.append(logLine)

        newDictOfListsOfLines_byProfile[profile] = newLogLines_forProfile

    return newDictOfListsOfLines_byProfile

def mergeCommMasks(lines):
    '''Copy of mergeDictsByKeyPair() for merging comms and thier masks'''
    newDictOfListsOfLines_byProfile = {}
    for profile in lines:
        newLogLines_forProfile = []
        pair_byId = {}
        suffixes_byId = {}
        commMasks_byId = {}
        for l in lines[profile]:
            maskKey = 'mask'
            operKey = 'operation'
            commKey = 'comm'
            if not l.get(maskKey) or \
               not l.get(operKey) or \
               not l.get(commKey):
                newLogLines_forProfile.append(l)  # save non-mergable
                continue

            if 'file_inherit' in l.get('operation'):
                newLogLines_forProfile.append(l)
                continue

            firstVal  = l.pop(maskKey)
            secondVal = l.pop(operKey)
            thirdVal  = l.pop(commKey)
            if not isinstance(firstVal,  set) or \
               not isinstance(secondVal, set) or \
               not isinstance(thirdVal,  set):
                raise NotImplementedError('Could merge diff sets only')

            timestamp = l.pop('timestamp')
            lineId = makeHashable(l)
            if isTransitionComm(thirdVal):
                commMasks_byId[lineId] = firstVal

            if not lineId in pair_byId:
                pair_byId[lineId] = [firstVal, secondVal, thirdVal]

            else:
                sublist = pair_byId.get(lineId)
                mergedFirstVals  = sublist[0]
                mergedSecondVals = sublist[1]
                mergedThirdVals  = sublist[2]
                mergedFirstVals.update(firstVal)
                mergedSecondVals.update(secondVal)
                mergedThirdVals.update(thirdVal)
                pair_byId[lineId] = [mergedFirstVals, mergedSecondVals, mergedThirdVals]

            suffix = l  # leftovers
            suffix['timestamp'] = timestamp  # use only the latest timestamp for duplicates
            suffixes_byId[lineId] = suffix

        # Handle skipped
        for l in newLogLines_forProfile:
            if l.get('comm'):
                if isTransitionComm(l.get('comm')) and len(l.get('comm')) == 1:
                    l['transition_mask'] = l.get('mask')

        # Collect back the lines for each profile
        for lineId,sublist in pair_byId.items():
            logLine = suffixes_byId.get(lineId)
            mergedFirstVals  = sublist[0]
            mergedSecondVals = sublist[1]
            mergedThirdVals  = sublist[2]
            logLine[maskKey] = mergedFirstVals
            logLine[operKey] = mergedSecondVals
            logLine[commKey] = mergedThirdVals
            if commMasks_byId.get(lineId):
                logLine['transition_mask'] = commMasks_byId.get(lineId)

            newLogLines_forProfile.append(logLine)

        newDictOfListsOfLines_byProfile[profile] = newLogLines_forProfile

    return newDictOfListsOfLines_byProfile

def mergeLinkMasks(lines):
    '''For merging link's source/target and their masks and operations'''
    for profile in lines:
        # Find all link lines
        allLinkedLines = []
        for t in lines[profile]:
            if t.get('target') and 'link' in t.get('operation'):
                allLinkedLines.append(t)

        # Compare link lines with all lines
        toCleanup = []
        for t in allLinkedLines:
            for l in lines[profile]:
                if 'file_inherit' in l.get('operation'):
                    continue

                if l.get('path') == t.get('path') and l != t:  # 'path' is the same, but not itself
                    # Ommit diff keys from target (copy) line to compare further
                    t_copy = copy.deepcopy(t)
                    t_copy.pop('timestamp')
                    t_copy.pop('target')
                    t_copy.pop('mask')
                    t_copy.pop('operation')
                    if t_copy.get('target_diffs'):
                        t_copy.pop('target_diffs')
                    if t_copy.get('target_prefix'):
                        t_copy.pop('target_prefix')

                    # If subset, combine neighbour line with target line
                    if t_copy.items() <= l.items():
                        l['target'] = t.get('target')
                        l['mask'].update(t.get('mask'))
                        l['operation'].update(t.get('operation'))
                        if t.get('target_diffs'):
                            l['target_diffs']  = t.get('target_diffs')
                        if t.get('target_prefix'):
                            l['target_prefix'] = t.get('target_prefix')

                        toCleanup.append(t)
                        break  # success, break to the next 't' link

        # Cleanup merged sources
        for l in lines[profile]:
            for t in toCleanup:
                if l == t:
                    lines[profile].remove(l)

    return lines

def mergeExactDuplicates(lines):

    newDictOfListsOfLines_byProfile = {}
    for profile in lines:
        uniqueLines_byId = {}
        timestamps_byId = {}
        newLogLines_forProfile = []
        for l in lines[profile]:
            timestamp = l.pop('timestamp')
            lineId    = makeHashable(l)
            uniqueLines_byId[lineId] = l
            timestamps_byId[lineId] = timestamp  # use only the latest timestamp for duplicates

        for lineId,merged in uniqueLines_byId.items():
            logLine = uniqueLines_byId.get(lineId)
            logLine['timestamp'] = timestamps_byId.get(lineId)
            newLogLines_forProfile.append(logLine)

        newDictOfListsOfLines_byProfile[profile] = newLogLines_forProfile

    return newDictOfListsOfLines_byProfile

def adaptTempPaths(lines, ruleStyle):
    '''Make similar path-pairs look the same for further merging. Could normalize masks. Rewrite is welcome
       Contrary to specific file path adaption, this function is designed for any path pairs'''
    for profile in lines:
        # Determine which read paths have write duplicates and normalize
        for l in lines[profile]:
            if findLineType(l) != 'FILE':
                raise ValueError('Using this function to handle non-file log lines will lead to silent errors.')

            if l.get('mask') == {'r'}:
                path = l.get('path')
                for j in lines[profile]:
                    neighborPath = j.get('path')
                    neighborMasks = j.get('mask')
                    if (neighborPath == path) and \
                       ('c' in neighborMasks or \
                        'w' in neighborMasks):

                        l['mask'].update(neighborMasks) # merge pair masks if they share write access
                        break

        # Determine all present tails
        diffs_byTimestamp = {}
        for l in lines[profile]:
            fullPath = pathlib.PurePath(l.get('path'))
            findTempTailPair_Out = findTempTailPair(fullPath.name, ruleStyle)
            tempTail = findTempTailPair_Out[0]
            macro    = findTempTailPair_Out[1]
            if tempTail:
                baseFilename = fullPath.name.removesuffix(tempTail)
                basePath = pathlib.PurePath.joinpath(fullPath.parent, baseFilename)
                l['full_path']  = str(fullPath)
                l['base_path']  = str(basePath)
                l['macro_path'] = str(basePath) + macro

                # Prepare tail diff for postcolorization
                if 'c' in l.get('mask') or \
                   'w' in l.get('mask'):  # Apply only to writable path

                    spanStart = len(str(basePath))
                    spanEnd   = len(str(basePath) + macro)
                    macroSpan = (spanStart, spanEnd)
                    diffs_byTimestamp[l.get('timestamp')] = {'macro_span':     macroSpan,
                                                             'temp_tail':      tempTail,
                                                             'confirmed_pair': False}
        # Set identical path (macro) for all temp tails and their bases
        for l in lines[profile]:
            if l.get('path') == l.get('full_path'):  # is tail
                l.pop('full_path')
                basePath  = l.pop('base_path')
                macroPath = l.pop('macro_path')
                for j in lines[profile]:  # to find similar base pair
                    neighborPath = j.get('path')
                    if (neighborPath == basePath or \
                        neighborPath == macroPath):  # if current tail-line have base pair, or pair is already replaced

                        baseMasks     = l.get('mask')
                        neighborMasks = j.get('mask')
                        if ('c' in baseMasks      or \
                            'w' in baseMasks)     and \
                           ('c' in neighborMasks  or \
                            'w' in neighborMasks):  # only apply to writable pairs

                            # Prepare base pair for postcolorization
                            diffs_byTimestamp[l.get('timestamp')]['confirmed_pair'] = True
                            if basePath == j.get('path'):
                                macroSpan_ = diffs_byTimestamp[l.get('timestamp')]['macro_span']
                                diffs_byTimestamp[j.get('timestamp')] = {'macro_span':    macroSpan_,
                                                                         'temp_tail':     '',
                                                                         'confirmed_pair': True}  # base pair diff is always empty
                            l['path'] = macroPath
                            j['path'] = macroPath

        # Assign diffs for postcolorization
        for l in lines[profile]:
            if l.get('timestamp') in diffs_byTimestamp:
                diffsSubDict = diffs_byTimestamp[l.get('timestamp')]
                if diffsSubDict['confirmed_pair']:
                    updatePostcolorizationDiffs(l, diffsSubDict.get('macro_span'), diffsSubDict.get('temp_tail'), 'path')

    return lines

def isRequestedProfile(currentProfile, requestedProfiles):
    '''For profiles and profile peers (labels)'''
    result = False
    if not requestedProfiles:  # all
        result = True

    elif not currentProfile:   # no 'profile_peer' key
        result = False

    elif currentProfile in requestedProfiles:
        result = True

    # Deeper dive into requested profiles
    elif requestedProfiles:
        for r in requestedProfiles:
            # Handle single wildcard
            if '*' in r:
                if r.count('*') >= 2:
                    raise NotImplementedError("Only single wildcard '*' is supported")

                part = r.partition('*')
                if currentProfile.startswith(part[0]) and \
                   currentProfile.endswith(part[2]):

                    result = True
                    break

            # Handle transition profile
            if '▶' in currentProfile:
                if currentProfile.startswith(r + '▶'):
                    result = True
                    break
 
            # Handle child profile
            if re.search('[^/]//[^/]', currentProfile):
                if currentProfile.startswith(r + '//'):
                    result = True
                    break

    return result

def isRequestedOperation(currentOperations, requestedOperations):

    result = False
    for o in currentOperations:
        if o in requestedOperations:
            result = True
            break

        for r in requestedOperations:
            if '*' in r:
                raise NotImplementedError("Wildcard '*' is not supported for operations")

    return result

def normalizeAndGroup(lines, args):
    '''Split lines by type and convert specific values to sets for further merging'''
    toAdaptPathKeys = ('path', 'srcpath', 'target', 'interface', 'addr', 'peer_addr')  # must be done after normalization and before stacking

    fileDict = {}
    dbusDict = {}
    networkDict = {}
    unixDict = {}
    capDict = {}
    signalDict = {}
    ptraceDict = {}
    mountDict = {}
    pivotDict = {}
    unknownDict = {}
    for profile in lines:
        if not isRequestedProfile(profile, args.profile):
            continue

        fileL = []
        dbusL = []
        networkL = []
        unixL = []
        capL = []
        signalL = []
        ptraceL = []
        mountL = []
        pivotL = []
        unknownL = []
        for l in lines[profile]:
            if not isRequestedProfile(l.get('peer'), args.peer):
                continue

            if args.drop_comm:
                if l.get('comm'):
                    l.pop('comm')
            elif l.get('comm'):
                l['comm'] = {hexToString(l.pop('comm'))}

            l['operation'] = {l.pop('operation')}

            # Stacks or sinkholes based on params
            if findLineType(l) == 'FILE':
                if 'file' in args.type:
                    l['path'] = l.pop('name')
                    l['mask'] = set(list(l.pop('requested_mask')))

                    if not args.keep_base_abs_transitions:
                        if isBaseAbstractionTransition(l, profile):
                            continue

                    [adaptFilePath(l, k, args.style) for k in toAdaptPathKeys if l.get(k)]
                    fileL.append(l)

            elif findLineType(l).startswith('DBUS'):
                if 'dbus' in args.type:
                    if l.get('member'):
                        l['member'] = {l.pop('member')}
 
                    dbusL.append(l)

            elif findLineType(l) == 'NETWORK':
                if 'network' in args.type:
                    l.pop('protocol')
                    l['mask'] = set(l.pop('requested_mask').split())
                    networkL.append(l)

            elif findLineType(l) == 'UNIX':
                if 'unix' in args.type:
                    if l.get('protocol') == '0':
                        l.pop('protocol')
 
                    l['mask'] = set(l.pop('requested_mask').split())
                    [adaptFilePath(l, k, args.style) for k in toAdaptPathKeys if l.get(k)]
                    unixL.append(l)

            elif findLineType(l) == 'CAPABILITY':
                if 'cap' in args.type:
                    capL.append(l)

            elif findLineType(l) == 'SIGNAL':
                if 'signal' in args.type:
                    l['signal'] = {l.pop('signal')}
                    signalL.append(l)

            elif findLineType(l) == 'PTRACE':
                if 'ptrace' in args.type:
                    l['mask'] = set(l.pop('requested_mask').split())
                    ptraceL.append(l)

            elif findLineType(l) == 'MOUNT':
                if 'mount' in args.type:
                    if l.get('name'):
                        l['path'] = l.pop('name')
                    if l.get('srcname'):
                        l['srcpath'] = l.pop('srcname')

                    [adaptFilePath(l, k, args.style) for k in toAdaptPathKeys if l.get(k)]
                    mountL.append(l)

            elif findLineType(l) == 'PIVOT':
                if 'pivot' in args.type:
                    if l.get('name'):
                        l['path'] = l.pop('name')
                    if l.get('srcname'):
                        l['srcpath'] = l.pop('srcname')

                    [adaptFilePath(l, k, args.style) for k in toAdaptPathKeys if l.get(k)]
                    pivotL.append(l)

            else:
                unknownL.append(l)

        if fileL:    fileDict[profile]    = fileL
        if dbusL:    dbusDict[profile]    = dbusL
        if networkL: networkDict[profile] = networkL
        if unixL:    unixDict[profile]    = unixL
        if capL:     capDict[profile]     = capL
        if signalL:  signalDict[profile]  = signalL
        if ptraceL:  ptraceDict[profile]  = ptraceL
        if mountL:   mountDict[profile]   = mountL
        if pivotL:   pivotDict[profile]   = pivotL
        if unknownL: unknownDict[profile] = unknownL

    return fileDict,   dbusDict,  networkDict, \
           unixDict,   capDict,   signalDict,  \
           ptraceDict, mountDict, pivotDict,  unknownDict
 
def isTransitionComm(comm_):
    '''If any element is a transition comm (highlighted prior)'''
    blu = '\x1b[0;34m'
    result = False
    for i in comm_:
        if i.startswith(blu):
            result = True
            break

    return result

def mergeNestedDictionaries(dictOne, dictTwo):

   allKeys      = set(dictOne.keys())
   allKeys.update(set(dictTwo.keys()))

   newDict = {}
   for k in allKeys:
       if k in dictOne and \
          k in dictTwo:

           intermList = dictOne[k]
           intermList.extend(dictTwo[k])
           newDict[k] = intermList

       elif k in dictOne:
           newDict[k] = dictOne[k]
       elif k in dictTwo:
           newDict[k] = dictTwo[k]

   return newDict

def composeRule(l, args):
    '''Compose final rule and insert it into dictionary line.'''
    if findLineType(l) == 'FILE':
        if l.get('flags'):
            flagsStr = ', '.join(sorted(l.pop('flags')))
            rule = f'flags=({flagsStr})'

        else:
            transitionMask = None
            if   l.get('transition_mask'):
                transitionMask = l.pop('transition_mask')
            elif l.get('comm'):  # guard
                if isTransitionComm(l.get('comm')) and len(l.get('comm')) == 1:
                    transitionMask = l.get('mask')
 
            execType = findExecType(getBaseBin(l.get('path')))
            if execType:
                splitProfile = l.get('profile')
                splitPath    = l.get('path')
                if   execType == 'i':
                    l['mask'].add(execType)
                elif splitProfile[-1] != splitPath[-1] and \
                     execType == 'P':  # affect only transition, not calling itself
                    l['mask'].add(execType)

            if ' ' in l.get('path'):
                path = f'"{l.pop("path")}"'
            else:
                path = l.pop('path')
 
            if l.get('path_prefix'):
                prefix = f"{l.pop('path_prefix')} "
            else:
                prefix = ''
 
            mask = composeFileMask(l.pop('mask'), transitionMask, args.convert_file_masks)
            if l.get('target'):
                rule = f"{prefix}{path} {mask} -> {l.pop('target')},"
            else:
                rule = f'{prefix}{path} {mask},'

    elif findLineType(l).startswith('DBUS'):
        mask = f"({l.pop('mask')})"
        l.pop('operation')
        if l.get('path'):
            pP = adjustPadding(l.get('path'), 38)
        if l.get('interface'):
            iP = adjustPadding(l.get('interface'), 36)
        if l.get('member'):
            mP = adjustPadding(l.get('member'), 18)

        if   'bind' in mask:
            rule = f"dbus {mask} bus={l.pop('bus')} name={l.pop('name')},"

        elif 'eavesdrop' in mask:
            rule = f"dbus {mask} bus={l.pop('bus')},"

        elif not 'peer' in l.keys():
            comment = colorize('# no peer label', 'Bright Cyan')
            rule = f"dbus {mask:9} bus={l.pop('bus'):13} path={l.pop('path'):{pP}} interface={l.pop('interface'):{iP}} member={l.pop('member'):{mP}} peer=(name={l.pop('name')}),  {comment}"

        else:
            rule = f"dbus {mask:9} bus={l.pop('bus'):13} path={l.pop('path'):{pP}} interface={l.pop('interface'):{iP}} member={l.pop('member'):{mP}} peer=(name={l.pop('name')}, label={l.pop('peer')}),"

    elif findLineType(l) == 'NETWORK':
        rule = f"network {l.pop('family')} {l.pop('sock_type')},"

    elif findLineType(l) == 'UNIX':
        masks = ', '.join(sorted(l.pop('mask'), reverse=True))
        masks = '(%s)' % masks
        addr = '"%s"' % l.pop('addr')
        if 'peer' in l.keys():
            rule = f'{l.pop("family")} {masks:24} type={l.pop("sock_type"):6} addr={addr:25} peer=(addr="{l.pop("peer_addr")}", label={l.pop("peer")}),'

        else:
            rule = f'{l.pop("family")} {masks:24} type={l.pop("sock_type"):6} addr={addr},'

    elif findLineType(l) == 'CAPABILITY':
        rule = f"capability {l.pop('capname')},"
        l.pop('operation')

    elif findLineType(l) == 'SIGNAL':
        rule = 'signal ({}) set=({}) peer={},'.format(l.pop('requested_mask'), ', '.join(l.pop('signal')), l.pop('peer'))
        l.pop('operation')

    elif findLineType(l) == 'PTRACE':
        masks = ', '.join(sorted(l.pop('mask')))
        masks = '(%s)' % masks
        rule = f"ptrace {masks} peer={l.pop('peer')},"
        l.pop('operation')

    elif 'mount' in l.get('operation'):
        path = l.pop('path')
        l.pop('operation')
        if l.get('flags') and \
           l.get('srcpath'):
            srcpath = l.pop('srcpath')
            rule = f'mount options=({l.pop("flags")}) {srcpath} -> {path},'

        elif l.get('flags'):
            rule = f'mount options=({l.pop("flags")}) -> {path},'

        else:
            rule = f'mount -> {path},'

    elif 'umount' in l.get('operation'):
        path = l.pop('path')
        l.pop('operation')
        rule = f'umount {path},'

    elif findLineType(l) == 'PIVOT':
        path = l.pop('path')
        l.pop('operation')
        if l.get('srcpath'):
            srcpath = l.pop('srcpath')
            rule = f'pivot_root {path} -> {srcpath},'

        else:
            rule = f'pivot_root {path},'

    else:
        rule = 'UNKNOWN_RULE'

    rule = highlightSpecialChars(rule)
    l['rule'] = rule

    return l  # leftovers

def sortLines(fileL,   dbusL,  networkL,
              unixL,   capL,   signalL,
              ptraceL, mountL, pivotL,  unknownL, args):

    allDicts = mergeNestedDictionaries(fileL,    dbusL)
    allDicts = mergeNestedDictionaries(allDicts, networkL)
    allDicts = mergeNestedDictionaries(allDicts, unixL)
    allDicts = mergeNestedDictionaries(allDicts, capL)
    allDicts = mergeNestedDictionaries(allDicts, signalL)
    allDicts = mergeNestedDictionaries(allDicts, ptraceL)
    allDicts = mergeNestedDictionaries(allDicts, mountL)
    allDicts = mergeNestedDictionaries(allDicts, pivotL)
    if 'unknown' in args.type:
        allDicts = mergeNestedDictionaries(allDicts, unknownL)

    # Convert dict of dicts to list of dicts
    allDicts_inlined = []
    for profile in allDicts:
        for l in allDicts[profile]:
            if args.operation:
                if not isRequestedOperation(l.get('operation'), args.operation):
                    continue

            l['profile'] = profile
            allDicts_inlined.append(l)

    # Sort by peer, member, interface, then path if exists, finally grouping by profile
    if args.sort == 'profile':
        sortedList = sorted(allDicts_inlined, key=lambda l: ('peer'      not in l, l.get('peer',      None)))
        sortedList = sorted(sortedList,       key=lambda l: ('member'    not in l, l.get('member',    None)))
        sortedList = sorted(sortedList,       key=lambda l: ('interface' not in l, l.get('interface', None)))
        sortedList = sorted(sortedList,       key=lambda l: ('path'      not in l, l.get('path',      None)))
        sortedList = sorted(sortedList,       key=lambda l: ('bus'       not in l, l.get('bus',       None)))
        sortedList = sorted(sortedList,       key=lambda l: ('addr'      not in l, l.get('addr',      None)))
        sortedList = sorted(sortedList,       key=lambda l:                        l.get('profile'))

    # Sort by order of appearance
    elif args.sort == 'timestamp':
        sortedList = sorted(allDicts_inlined, key=lambda l: l.get('timestamp'))

    # Sort by path if exists ignoring profile names
    elif args.sort == 'path':
        sortedList = sorted(allDicts_inlined, key=lambda l: ('path' not in l, l.get('path', None)))

    # Sort by profile's peer name (label) if exists ignoring profile names
    elif args.sort == 'peer':
        sortedList = sorted(allDicts_inlined, key=lambda l: ('peer' not in l, l.get('peer', None)))

    # Sort by DBus interface if exists ignoring profile names
    elif args.sort == 'interface':
        sortedList = sorted(allDicts_inlined, key=lambda l: ('interface' not in l, l.get('interface', None)))

    # Sort by DBus member if exists ignoring profile names
    elif args.sort == 'member':
        sortedList = sorted(allDicts_inlined, key=lambda l: ('member' not in l, l.get('member', None)))

    else:  # args guard
        raise NotImplementedError('This function is not adapted to such sorting request.')

    return sortedList

def colorizeLines(plainLines):
    '''& postprocess'''
    # Replace 'peer' after sorting, if it's the same as 'profile'
    for l in plainLines:
        if l.get('peer') == l.get('profile'):
            l['peer'] = colorize('@{profile_name}', 'Green')

    # Final colorization after alignment
    toColorizeKeys = ('path_diffs', 'target_diffs', 'addr_diffs', 'peer_addr_diffs')
    for l in plainLines:
        for k in toColorizeKeys:
            if l.get(k):
                diffs = l.get(k)
                sortedDiffs = sorted(diffs, key=lambda t: t[0], reverse=True) # colorize from the end
                for span,diff in sortedDiffs:
                    originalPathKey = k.removesuffix('_diffs')
                    if diff == '':  # colorize differently and remove from display
                        color = 'White'
                        diffs.remove([span, diff])
                    else:
                        color = 'Green'

                    l[originalPathKey] = colorizeBySpan(l.get(originalPathKey), color, span)

                l[k] = sorted(diffs, key=lambda t: t[0])  # prepare for display

    toHighlightWordsKeys = (
        'path', 'srcpath', 'target', 'interface', 'addr', 'peer_addr',
    )
    for l in plainLines:
        for k in toHighlightWordsKeys:
            if l.get(k):
                l[k] = highlightWords(l[k])

    for l in plainLines:
        profile = l.get('profile')
        if profile and l.get('comm'):
            if '▶' in profile:
                profile = profile.split('▶')[-1]  # select last profile for transition
            if {profile} == l.get('comm'):
                l.pop('comm')  # ommit comm for itself; but only when single

        flags = set()
        if l.get('info') == 'Failed name lookup - disconnected path':
            flags.add(colorize('attach_disconnected', 'Bright Yellow'))
        if l.get('info') == 'Failed name lookup - deleted entry':
            flags.add('mediate_deleted')
        if l.get('info') == 'profile transition not found':
            l['mask'].add('N')
        if flags:
            l['flags'] = flags

        if findLineType(l).startswith('DBUS'):
            if re.match(r':\d+\.(?:\[0-9\]\*|@\{int\})$', l.get('name')):
                if l['name'].endswith('@{int}'):  # known style characteristic
                    pcreStyle = '.@{int}'
                else:
                    pcreStyle = '.[0-9]*'
                colorized = colorize(pcreStyle, 'Green')
                l['name'] = l['name'].removesuffix(pcreStyle) + colorized

            members = l.get('member')
            if members:
                if members.startswith('{') and \
                   members.endswith('}'):  # multiple changed members

                    l['member'] = colorize(members, 'White')

        toColorizeKeys = ['profile', 'peer', 'target']
        for k in toColorizeKeys:
            if l.get(k):
                if '▶' in l.get(k):
                    l[k] = l.get(k).replace('▶', colorize('▶', 'Blue'))

        trustToColor = {
            10:  None,
            9:  'White',
            8:  'Cyan',
            7:  'Blue',
            6:  'Bright Blue',
            5:  'Yellow',
            4:  'Bright Yellow',
            3:  'Red',
            2:  'Bright Red',
            1:  'Magenta',
            0:  'Bright Magenta',
        }
        l['trust_color'] = trustToColor[l.pop('trust')]

    return plainLines

def adjustPadding(str_, targetPadding_):
    '''By decolorizing (a copy). Temp?'''

    strRe = re.findall(r'\\033\[\d;\d{2}m|\\033\[0m', str_)
    if strRe:
        result = targetPadding_ + len(''.join(strRe))
    else:
        result = targetPadding_

    return result

def isSupportedDistro():

    # Needs to be allowed in AA profile also
    supportedDistros = (
         # file                 # key in file        # value(s) in file
        ('/usr/lib/os-release', 'VERSION_CODENAME', {'bookworm',  #  Debian 12
                                                     'jammy',     # *Ubuntu 22.04
                                                    }),
    )
    isSupported = False
    for p,k,v in supportedDistros:
        path = pathlib.Path(p)
        if path.is_file():
            with open(path, 'r') as f:
                for l in f:
                    part = l.partition('=')
                    fileKey = part[0].strip()
                    fileVal = part[2].strip()
                    if fileKey == k and \
                       fileVal in v:

                        isSupported = True
                        break

            if isSupported:
                break

    return isSupported

def failIfNotConfined():
    '''Only covers confinement, not necessary enforcement'''
    randomTail = ''.join(random.choice(string.ascii_letters) for i in range(8))
    path = f'/dev/shm/aa_suggest.am_i_confined.{randomTail}'

    try:
        with open(path, 'w') as f:
            f.write("DELETEME\n")
    except Exception:  # expected behavior
        pass

    file = pathlib.Path(path)
    if file.is_file():
        file.unlink()
        raise EnvironmentError('''The process is not confined by AppArmor. Refusing to function. Expected action:\n
$ sudo install -m 644 -o root -g root apparmor-suggest/apparmor.d/aa_suggest /etc/apparmor.d/
$ sudo apparmor_parser --add /etc/apparmor.d/aa_suggest''')

    return None

def findPadding(plainLines):

    padding = {}

    return padding

def display(plainLines, padding_, previousTimestamp, args):

    [composeRule(l, args) for l in plainLines]
    previousProfile = None
    for l in plainLines:
        timestamp = l.pop('timestamp')

        if previousProfile != l.get('profile'):
            isNextProfile = True
        else:
            isNextProfile = False
        previousProfile = l.get('profile')

        if args.sort == 'profile':
            prefix = ''
            profile = l.pop('profile')
            if isNextProfile:
                print(f"\n   {profile}")

        else:
            pP = adjustPadding(l.get('profile'), 29)
            prefix = f"{l.pop('profile'):{pP}} "

        trustColor = l.pop('trust_color')
        if trustColor:
            bracketP = colorize('[', trustColor, 7)  # background
            bracketS = colorize(']', trustColor, 7)  # background
        else:
            bracketP = '['
            bracketS = ']'
        rule = f"{bracketP}{l.pop('rule')}{bracketS}"

        if rule.startswith('[unix '):  # :/
            P = adjustPadding(rule, 120)
        else:
            P = adjustPadding(rule, 50)

        if l:  # if have leftovers
            suffix = composeSuffix(l, args.hide_keys)
            toDisplay = f'{prefix}{rule:{P}} {suffix}'
        else:
            toDisplay = f'{prefix}{rule}'

        if   previousTimestamp == -10:       # poisoning
            prefixSign = colorize('!', 'Red', 1)

        elif previousTimestamp == -3:        # unknown
            prefixSign = colorize('*', 'Yellow', 1)

        elif previousTimestamp == -2:        # unknown
            prefixSign = colorize('*', 'Yellow')

        elif previousTimestamp == -1:        # first run
            prefixSign = colorize('*', 'White', 1)

        elif previousTimestamp < timestamp:  # diff between current run and previous run (newest)
            prefixSign = colorize('+', 'Green')

        else:
            prefixSign = ' '  # shown on previous run(s)

        print(f'{prefixSign}{toDisplay}')

    return None

def findPreviousTimestamp(pathStr):
    '''Read previously saved epoch timestamp from a file'''
    path = pathlib.Path(pathStr)
    dirPath = path.parent
    errors = {}
    try:
        if path.exists():
            if dirPath.stat().st_uid != 0 or oct(dirPath.stat().st_mode) != '0o40700':
                result = -10  # poisoning
                poisoning = colorize('poisoning', 'Magenta')
                errors[f"Potential timestamp {poisoning}! Explore '{dirPath}/' permissions."] = 21  # exit code
            else:
                result = int(path.read_text())
    
        elif path.is_file():
            result = int(path.read_text())
    
        elif not path.exists():
            result = -1  # first run
    
        else:
            result = -2  # unknown

    except PermissionError as e:
        result = -10  # poisoning
        poisoning = colorize('poisoning', 'Magenta')
        errors[f"Potential timestamp {poisoning}! Explore '{dirPath}/' permissions."] = 21  # exit code

    except:  # never fail
        result = -3  # unknown

    return (errors, result)

def rewriteLatestTimestamp(pathStr, timestamp):
    '''(Re)write latest epoch timestamp to a file'''
    path = pathlib.Path(pathStr)
    dirPath = path.parent

    errors = {}
    if dirPath.exists():
        if dirPath.stat().st_uid != 0 or oct(dirPath.stat().st_mode) != '0o40700':
            poisoning = colorize('poisoning', 'Magenta')
            errors[f"Potential timestamp {poisoning}! Explore '{dirPath}/' permissions."] = 20  # exit code

    else:
        dirPath.mkdir(mode=0o700)

    isSuccessfullWrite = False
    try:
        with open(pathStr, 'w') as f:
            f.write(f"{timestamp}\n")

        isSuccessfullWrite = True

    except PermissionError as e:
        poisoning = colorize('poisoning', 'Magenta')
        errors[f"Potential timestamp {poisoning}! Explore '{dirPath}/' permissions."] = 20  # exit code

    except:  # never fail
        pass

    return (errors, isSuccessfullWrite)

def displayLegend():

    itl = '\x1b[3m'
    rst = '\x1b[0m'
    rule = f'{itl}rule{rst}'
    aster_WhtB      = colorize('*', 'White', 1)
    plus_Grn        = colorize('+', 'Green')
    aster_YlwB      = colorize('*', 'Yellow', 1)
    exclm_RedB      = colorize('!', 'Red', 1)
    bracketL_CyaBg  = colorize('[', 'Cyan', 7)
    bracketR_CyaBg  = colorize(']', 'Cyan', 7)
    bracketL_bBluBg = colorize('[', 'Bright Blue', 7)
    bracketR_bBluBg = colorize(']', 'Bright Blue', 7)
    bracketL_BluBg  = colorize('[', 'Blue', 7)
    bracketR_BluBg  = colorize(']', 'Blue', 7)
    bracketL_YlwBg  = colorize('[', 'Yellow', 7)
    bracketR_YlwBg  = colorize(']', 'Yellow', 7)
    bracketL_bYlwBg = colorize('[', 'Bright Yellow', 7)
    bracketR_bYlwBg = colorize(']', 'Bright Yellow', 7)
    bracketL_RedBg  = colorize('[', 'Red', 7)
    bracketR_RedBg  = colorize(']', 'Red', 7)
    bracketL_MgnBg  = colorize('[', 'Magenta', 7)
    bracketR_MgnBg  = colorize(']', 'Magenta', 7)
    key_Red         = colorize('key', 'Red')
    tail_Ylw        = colorize('aBcXy9', 'Yellow')
    quote_Cya       = colorize('"', 'Cyan')
    parenL_Cya      = colorize('(', 'Cyan')
    parenR_Cya      = colorize(')', 'Cyan')
    equals_bBlu     = colorize('=', 'Bright Blue')
    comma_bBlu      = colorize(',', 'Bright Blue')
    delimiter_Blu   = colorize('▶', 'Blue')
    commW_Blu       = colorize('w', 'Blue')
    commN_Blu       = colorize('grep', 'Blue')
    commS_Blu       = colorize('sed', 'Blue')
    parentR_Blu     = colorize('r', 'Blue')
    read_Wht        = colorize('r', 'White', 1)
    iExec_Wht       = colorize('i', 'White', 1)
    suggest_Grn     = colorize('@{run}', 'Green')
    tail_Wht        = colorize('{,.??????}', 'White')
    write_Grn       = colorize('w', 'Green')
    wxViol_RedB     = colorize('wx', 'Red', 7)
    targetMis_bBlkB = colorize('P', 'Bright Black', 7)
    members_Wht     = colorize('{AddMatch,Hello}', 'White')
    attachD_bYlw    = colorize('attach_disconnected', 'Bright Yellow')
    comments        = colorize('# no peer label', 'Bright Cyan')
    fileI_bYlw      = colorize('file_inherit', 'Bright Yellow')
    warnings        = colorize('warning', 'Yellow')
    errors          = colorize('error', 'Red')
    poisoning       = colorize('poisoning', 'Magenta')

    legend = f"""
{aster_WhtB}[{rule}]                              First run
{aster_YlwB}[{rule}]                              Something went wrong during timestamp file access
{plus_Grn}[{rule}]                              Difference between current run and previous run (newest lines)
{exclm_RedB}[{rule}]                              Incorrect permissions for working directory (potential timestamp poisoning)
 
 [{suggest_Grn}] diffs=/run                 Suggestion with a diff (replacement)
 [/f.conf{tail_Wht}]                 Suggestion without a diff (addition)
 [/cert.{key_Red}]                         Sensitive path patterns - close attention advised
 [/f.conf.{tail_Ylw}]                    Volatile path patterns - not necessarily suitable in it's current form
 [/file r{write_Grn}]                          Access suggestion optimised from declared 'dc' to usable 'w'
 [/bin/cat {read_Wht}x]                       'x' is always accompanied by 'r'
 [/bin/sed r{iExec_Wht}x]                      'sed' always have 'i' execution type
 [/bin/f {targetMis_bBlkB}x]                         Profile transition not found
 [/bin/f r{wxViol_RedB}]                        W^X violation. Strongly discouraged. Takes precedence over every other mask
 [{parenL_Cya}s, r{parenR_Cya} {quote_Cya}/spa ced{quote_Cya}]                 Isolation characters
 [key{equals_bBlu}value] a{comma_bBlu}b                     Delimiters
 [member={members_Wht}]           DBus members grouped together without additions

 parent{delimiter_Blu}child [{rule}]                 Delimiter for automatically separated subprofiles
 parent [/file r{commW_Blu}] comm=parent,{commN_Blu}  'w' came from 'grep' child. Line changed identification as parent. 'base' abstraction lines are ommited
 parent [/file {parentR_Blu}{write_Grn}] comm=parent,{commS_Blu}   Parent's 'r' is consumed. Child's 'd' or 'c' is optimised and took presedence
                                                           
 [{rule}]                              Came from 'AVC'
 {bracketL_CyaBg}{rule}{bracketR_CyaBg}                              Came from 'USER_AVC'
 {bracketL_BluBg}{rule}{bracketR_BluBg}                              Confirmed DBus line
 {bracketL_bBluBg}{rule}{bracketR_bBluBg}                              Identifies itself as DBus line
 {bracketL_bYlwBg}{rule}{bracketR_bYlwBg}                              Nested line with unknown trust
 {bracketL_YlwBg}{rule}{bracketR_YlwBg}                              Unknown trust
 {bracketL_RedBg}{rule}{bracketR_RedBg}                              Came from 'USER_AVC', but not a DBus line. Or came from 'AVC', but not from 'system' bus (potential journal poisoning)
 {bracketL_MgnBg}{rule}{bracketR_MgnBg}                              Came from DBus, but not a DBus line (potential journal poisoning)

 [{rule},  {comments}]                               Comments
 [flags=({attachD_bYlw})] operation={fileI_bYlw}   Not necessarily required

 This is a {warnings}                                      Warnings
 This is an {errors}                                       Errors
 This is {poisoning}                                      Potential attacks on input data

Note: you might want to change your palette to more distinctive colors"""

    print(legend)

    return None

def handleArgs():

    allLineTypes  = ['file', 'dbus', 'unix', 'network', 'signal', 'ptrace', 'cap', 'mount', 'pivot', 'unknown']
    allSuffixKeys = ['comm', 'operation', 'mask', '*_diffs', 'error', 'info', 'class']

    parser = argparse.ArgumentParser(description='Suggest AppArmor rules')
    parser.add_argument('-v', '--version', action='version', version='aa_suggest.py 0.8.10')
    parser.add_argument('--legend', action='store_true',
                        default=False,
                        help='Display color legend')
    parser.add_argument('-b', '--boot-id', action='store', type=int,
                        choices=range(-14, 1),
                        default=0,
                        help='Specify (previous) boot id')
    parser.add_argument('-t', '--type', action='append',
                        choices=allLineTypes,
                        help='Handle only specified rule type')
    parser.add_argument('-p', '--profile', action='append',
                        default=[],
                        help='Handle only specified profile')
    parser.add_argument('-l', '--peer', action='append',
                        help='Handle only specified peer profile')
    parser.add_argument('-o', '--operation', action='append',
                        help='Show only lines containing specified operation. Does not affect merging')
    parser.add_argument('--hide-keys', action='append',
                        choices=allSuffixKeys + ['ALL'],
                        default=[],
                        help='Hide specified keys in suffix. Does not affect merging')
    parser.add_argument('--drop-comm', action='store_true',
                        default=False,
                        help='Drop comm key to affect further merging')
    parser.add_argument('--keep-base-abs-transitions', action='store_true',
                        default=False,
                        help="Do not drop automatic transition lines '▶' which rules are present in 'base' abstraction")
    parser.add_argument('--keep-status', action='store_true',
                        help="Do not drop 'apparmor' status key. Affects merging")
    parser.add_argument('--keep-status-audit', action='store_true',
                        help="Do not drop 'AUDIT' log lines. Implies '--keep-status'")
    parser.add_argument('-c', '--convert-file-masks', action='store_true',
                        help='Convert requested file masks to currently supported variants. Will be deprecated (changed)')
    parser.add_argument('-s', '--sort', action='store',
                        choices=['profile', 'peer', 'path', 'interface', 'member', 'timestamp'],
                        default='profile',
                        help="Sort by. 'profile' is the default")
    parser.add_argument('--style', action='store',
                        choices=['default', 'AppArmor.d'],
                        default='default',
                        help="Style preset. Stock or 'roddhjav/AppArmor.d'. Affects custom tunables")

    args = parser.parse_args()

    if args.legend:
        displayLegend()
        sys.exit(0)

    if not args.type:
        args.type = allLineTypes

    if 'ALL' in allSuffixKeys:
        args.hide_keys = allSuffixKeys

    if args.keep_status_audit:
        args.keep_status = True

    return args

if __name__ == '__main__':

    failIfNotConfined()

    try:
        from systemd import journal
    except ModuleNotFoundError:
        Debian = colorize('# Debian/Ubuntu/Mint', 'Bright Cyan')
        Arch   = colorize('# Arch',               'Bright Cyan')
        SUSE   = colorize('# openSUSE/SLE',       'Bright Cyan')
        raise ModuleNotFoundError(f"""'systemd' module not found! Install with:
$ sudo apt install python3-systemd  {Debian}
# pacman -Sy python-systemd         {Arch}
# zypper in python3-systemd         {SUSE}""")

    args = handleArgs()

    errors = {}
    timestampPath = '/dev/shm/apparmor_suggest/timestamp.latest'
    findPreviousTimestamp_Out = findPreviousTimestamp(timestampPath)
    errors.update(findPreviousTimestamp_Out[0])
    previousTimestamp = findPreviousTimestamp_Out[1]

    rawLines = grabJournal(args)
    findLogLines_Out = findLogLines(rawLines, args)
    logLines        = findLogLines_Out[0]
    latestTimestamp = findLogLines_Out[1]  # regardless of filtering
    rewriteLatestTimestamp_Out = rewriteLatestTimestamp(timestampPath, latestTimestamp)  # write as soon as possible
    errors.update(rewriteLatestTimestamp_Out[0])
    unsortedLines = []
    for l in logLines:
        normalizeProfileName(l)
        if findLineType(l) == 'FILE':
            adaptProfileAutoTransitions(l)

        unsortedLines.append(l)

    allLines = groupLinesByProfile(unsortedLines)

    groupedLines_Out = normalizeAndGroup(allLines, args)
    fileLines    = groupedLines_Out[0]
    dbusLines    = groupedLines_Out[1]
    networkLines = groupedLines_Out[2]
    unixLines    = groupedLines_Out[3]
    capLines     = groupedLines_Out[4]
    signalLines  = groupedLines_Out[5]
    ptraceLines  = groupedLines_Out[6]
    mountLines   = groupedLines_Out[7]
    pivotLines   = groupedLines_Out[8]
    unknownLines = groupedLines_Out[9]

    if 'file'    in args.type:
        fileLines = adaptTempPaths(fileLines, args.style)
        fileLines = mergeLinkMasks(fileLines)
        fileLines = mergeDictsByKeyPair(fileLines, 'mask', 'operation')
        fileLines = mergeCommMasks(fileLines)

    if 'dbus'    in args.type:
        dbusLines = adaptDbusPaths(dbusLines, args.style)
        dbusLines = mergeDictsBySingleKey(dbusLines, 'member')
        dbusLines = composeMembers(dbusLines)
        dbusLines = mergeExactDuplicates(dbusLines)

    if 'network' in args.type:
        networkLines = mergeDictsByKeyPair(networkLines, 'mask', 'operation')

    if 'unix'    in args.type:
        unixLines    = mergeDictsByKeyPair(unixLines, 'mask', 'operation')
        unixLines    = mergeCommMasks(unixLines)

    if 'cap'     in args.type:
        capLines     = mergeExactDuplicates(capLines)

    if 'signal'  in args.type:
        signalLines  = mergeDictsBySingleKey(signalLines, 'signal')

    if 'ptrace'  in args.type:
        ptraceLines  = mergeDictsBySingleKey(ptraceLines, 'mask')

    if 'mount'   in args.type:
        mountLines   = mergeExactDuplicates(mountLines)

    if 'pivot'   in args.type:
        pivotLines   = mergeExactDuplicates(pivotLines)

    if 'unknown' in args.type:
        unknownLines = mergeExactDuplicates(unknownLines)

    sortedLines = sortLines(fileLines,   dbusLines,  networkLines,
                            unixLines,   capLines,   signalLines,
                            ptraceLines, mountLines, pivotLines,  unknownLines, args)

    padding        = findPadding(sortedLines)
    colorizedLines = colorizeLines(sortedLines)

    display(colorizedLines, padding, previousTimestamp, args)

    if not isSupportedDistro():
        not_supported = colorize('not supported', 'Yellow')
        errors[f'This distro is {not_supported}. Watch out for inconsistencies.'] = 10  # exit code

    if os.getuid() != 0:
        as_root_user = colorize('as root user', 'Yellow')
        errors[f'Designed to be run {as_root_user}. Will not rely on timestamps. Watch out for inconsistencies.'] = 8

    if not rawLines:
        taken_over = colorize('taken over', 'Red')
        errors[f"Empty journal! Was {taken_over} by 'auditd'?"] = 100

    isFirst = True
    highestErrorCode = 0
    for e,c in errors.items():
        if isFirst:
            print('', file=sys.stderr)
            isFirst = False
        if highestErrorCode < c:
            highestErrorCode = c
        print(e, file=sys.stderr)

    if highestErrorCode != 0:
        sys.exit(highestErrorCode)
