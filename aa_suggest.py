#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-License-Identifier: GPL-3.0-only
# Version: 0.8

# line, l - single log line in form of dictionary
# normalize - prepare line values for a possible merge; make keys consistent
# adapt - replace line values with sutable for usage in the rule
# merge - make single line from many lines; explicitly by default, or ambiguously by params
# explicitly - non-aggressive deduplication; no rule covarage is lost, but paths could be replaced by tunables
# ambiguously - aggressive deduplication; some rule coverage could be broader than needed
# keep/drop - include or exclude the line from deduplication, affects merging (preprocessing)
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

def adaptFilePath(l, key, ruleStyle):
    '''Applied early to fully handle duplicates.
       For file paths, not necessary file lines.
       Watch out for bugs: launchpad #1856738
       Do only one capture per regex helper, otherwise diffs will be a mess (will match recursively)'''
    # Always surround these helpers with other charactes or new/endlines
    # Mix of different regex styles!; 'C' for capture
    random6     = '(?![0-9]{6}|[a-z]{6}|[A-Z]{6}|[A-Z][a-z]{5}|[A-Z][a-z]{4}[0-9])(?:[0-9a-zA-Z]{6}|@{rand6})' # aBcXy9, AbcXyz, abcxy9, @{rand6}; NOT 123789, abcxyz, ABCXYZ, Abcxyz, Abcxy1
    random8     = '(?![0-9]{8}|[a-z]{8}|[A-Z]{8}|[A-Z][a-z]{7}|[A-Z][a-z]{6}[0-9])(?:[0-9a-zA-Z]{8}|@{rand8})' # aBcDwXy9, AbcdWxyz, abcdwxy9, @{rand8}; NOT: 12346789, abcdwxyz, ABCDWXYZ, Abcdwxyz, Abcdwxy1
    random10    = '(?![0-9]{10}|[a-z]{10}|[A-Z]{10}|[A-Z][a-z]{9}|[A-Z][a-z]{8}[0-9])(?:[0-9a-zA-Z]{10}|@{rand10})' # aBcDeVwXy9, AbcdeVwxyz, abcdevwxy9, @{rand10}; NOT: 1234567890, abcdevwxyz, ABCDEVWXYZ, Abcdevwxyz, Abcdevwxy1
    users       = '(?:[0-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9}|@{uid})'
    md5         = '(?:[0-9a-fA-F]{32}|\[0-9a-f\]\*\[0-9a-f\]|@{md5})'
    hexes2      = '(?:[0-9a-fA-F]{2}|\[0-9a-f\]\[0-9a-f\]|@{h}@{h})'
    hexes16     = '(?:[0-9a-fA-F]{16}|\[0-9a-f\]\*\[0-9a-f\]|@{hex})'
    hexes38     = '(?:[0-9a-fA-F]{38}|\[0-9a-f\]\*\[0-9a-f\]|@{hex})'
    ints        = '(?:\d+|\[0-9\]\*|@{int})'
    uuid        = '(?:[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}|\[0-9a-f\]\*\[0-9a-f\]|@{uuid})'
    etc_ro      = '(?:/usr/etc|@{etc_ro})'
    run         = '(?:/var/run|/run|@{run})'
    proc        = '(?:/proc|@{PROC})'
    sys         = '(?:/sys|@{sys})'
    pids        = '(?:[2-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9}|@{pid})' # 3-4999999999
    tids        = '(?:[1-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9}|@{tid})' # 1-4999999999
    multiarch   = '(?:[^/]+-linux-gnu(?:|[^/]+)|@{multiarch})'
    user_cache  = '(?:@?/home/[^/]+/\.cache|@{user_cache_dirs})'
    user_config = '(?:@?/home/[^/]+/\.config|@{user_config_dirs})'
    homes       = '(?:@?/home/[^/]+|@{HOME})'
    pciAddr     = '(?:\d{4}:\d{2}:\d{2}\.\d|\?\?\?\?:\?\?:\?\?\.\?)'
    o3          = '(?:3|{\,3}|)' # optional '3'
    oWayland    = '(?:-wayland|{\,-wayland}|)' # optional '-wayland'
    usr         = '(?:usr/|{\,usr/}|)'
    Any         = '(?!@{.+|{.+|\[0-9.+|\*)[^/]+'
    user_share  = '(?:@?/home/[^/]+/\.local/share|@{user_share_dirs})'
    user_shareC = '(?:@?/home/[^/]+/\.local/share)'

    # Special cases <3
    if ruleStyle == 'roddhjav/apparmor.d':
        Bin  = '(?:/(?:usr/)?(?:s)?bin|@{bin})'
        BinC = '(?:/(?:usr/)?(?:s)?bin)'
        #pci = ''
    else:
        Bin  = '(?:/(?:usr/)?(?:s)?bin|/{\,usr/}bin)'
        BinC = '(?:/(?:usr/)?bin)'
        #pci = ''

    # Substitute capturing group with t[1] or t[2]; order matters when mentioned
    regexpToMacro = [  # non-tunables
 # regex                                                                            # default style         # apparmor.d style      # prefix, optional
(f'^{user_share}/gvfs-metadata/(|{Any})$',                                           None,                  '{,*}',                 'deny'),
(f'^/var/lib/apt/lists/({Any})\.yml\.gz$',                                          '*',                     None),
(f'^{user_share}/yelp/storage/({Any})/',                                            '*',                     None,                  'owner'),
(f'^{user_share}/yelp/storage/[^/]+/({Any})/',                                      '*',                     None,                  'owner'),
 # Capturing *any* goes above
(f'^{Bin}/(|e|f)grep$',                                                             '{,e,f}',                None),
(f'^{Bin}/(|g|m)awk$',                                                              '{,g,m}',                None),
(f'^{Bin}/gettext(|\.sh)$',                                                         '{,.sh}',                None),
(f'^{Bin}/python3\.(\d+)',                                                          '[0-9]{,[0-9]}',        '@{int}'),
(f'^{Bin}/which(|\.debianutils)$',                                                  '{,.debianutils}',       None),
(f'^{Bin}/ldconfig(|\.real)$',                                                      '{,.real}',              None),
(f'^/usr/share/gtk-([2-4])\.0/',                                                    '[2-4]',                 None),
(f'^/etc/apparmor\.d/libvirt/libvirt-({uuid})$',                                    '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^/etc/gdm({o3})/',                                                               '{,3}',                  None),
(f'^/etc/gtk-([2-4])\.0/',                                                          '[2-4]',                 None),
(f'^/var/log/journal/({md5})/',                                                     '[0-9a-f]*[0-9a-f]',    '@{md5}'),
(f'^/var/log/journal/{md5}/user-{users}@({md5})-',                                  '[0-9a-f]*[0-9a-f]',    '@{md5}'), # '@' is a string
(f'^/var/log/journal/{md5}/system@({md5})-',                                        '[0-9a-f]*[0-9a-f]',    '@{md5}'), # '@' is a string
(f'^/var/log/journal/{md5}/user-{users}@{md5}-({hexes16}-{hexes16})\.',             '*',                     None),    # '@' is a string
(f'^/var/log/journal/{md5}/system@{md5}-({hexes16}-{hexes16})\.',                   '*',                     None),    # '@' is a string
(f'^/var/lib/btrfs/scrub\.progress\.({uuid})$',                                     '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^/var/lib/btrfs/scrub\.status\.({uuid})(?:|_tmp)$',                              '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^/var/lib/cni/results/cni-loopback-({uuid})-lo$',                                '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^/var/lib/ca-certificates/openssl/({random8}).\d+$',                             '????????',             '@{rand8}'),
(f'^@?/var/lib/gdm({o3})/',                                                         '{,3}',                  None),
(f'^@?/var/lib/gdm{o3}/\.cache/ibus/dbus-({random8})$',                             '????????',             '@{rand8}'),
(f'^/var/lib/gdm{o3}/\.cache/gstreamer-(\d+)$',                                     '[0-9]*',               '@{int}'),
(f'^/var/lib/gdm{o3}/\.cache/mesa_shader_cache/({hexes2})/',                        '[0-9a-f][0-9a-f]',     '@{h}@{h}'),
(f'^/var/lib/gdm{o3}/\.cache/mesa_shader_cache/{hexes2}/({hexes38})(?:|\.tmp)$',    '[0-9a-f]*[0-9a-f]',    '@{hex}'),
(f'^/var/lib/gdm{o3}/\.config/ibus/bus/({md5})-',                                   '[0-9a-f]*[0-9a-f]',    '@{md5}'),
#(f'^/var/lib/gdm{o3}/\.config/ibus/bus/{md5}-unix({oWayland})-{ints}$',             '{,-wayland}',           None),
(f'^/var/lib/gdm{o3}/\.config/ibus/bus/{md5}-unix{oWayland}-({ints})$',             '[0-9]*',               '@{int}'),
(f'^/var/lib/kubelet/pods/({uuid})/',                                               '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^/var/lib/libvirt/swtpm/({uuid})/',                                              '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^{homes}/xauth_({random6})$',                                                    '??????',               '@{rand6}',             'owner'),
(f'^({user_cache})/',                                                                None,                  '@{user_cache_dirs}',   'owner'),
(f'^({user_config})/',                                                               None,                  '@{user_config_dirs}',  'owner'),
(f'^{user_cache}/fontconfig/({md5})-',                                              '[0-9a-f]*[0-9a-f]',    '@{md5}',               'owner'),
(f'^{user_cache}/fontconfig/{md5}-le64\.cache-\d+\.TMP-({random6})$',               '??????',               '@{rand6}',             'owner'),
(f'^{user_cache}/gnome-software/icons/({hexes38})-',                                '[0-9a-f]*[0-9a-f]',    '@{hex}',               'owner'),
(f'^{user_cache}/gstreamer-({ints})/',                                              '[0-9]*',               '@{int}',               'owner'),
(f'^{user_cache}/event-sound-cache\.tdb\.({md5})\.',                                '[0-9a-f]*[0-9a-f]',    '@{md5}',               'owner'),
(f'^{user_cache}/mesa_shader_cache/({hexes2})/',                                    '[0-9a-f][0-9a-f]',     '@{h}@{h}',             'owner'),
(f'^{user_cache}/mesa_shader_cache/{hexes2}/({hexes38})(?:|\.tmp)$',                '[0-9a-f]*[0-9a-f]',    '@{hex}',               'owner'),
(f'^{user_cache}/thumbnails/[^/]+/({md5}).png',                                     '*',                    '@{md5}',               'owner'),
(f'^{user_cache}/thumbnails/fail/gnome-thumbnail-factory/({md5}).png',              '*',                    '@{md5}',               'owner'),
(f'^@?{user_cache}/ibus/dbus-({random8})$',                                         '????????',             '@{rand8}',             'owner'),
(f'^{user_config}/#(\d+)$',                                                         '[0-9]*[0-9]',          '@{int}',               'owner'),
(f'^{user_config}/ibus/bus/({md5})-',                                               '[0-9a-f]*[0-9a-f]',    '@{md5}',               'owner'),
#(f'^{user_config}/ibus/bus/{md5}-unix({oWayland})-{ints}$',                         '{,-wayland}',           None,                  'owner'),
(f'^{user_config}/ibus/bus/{md5}-unix{oWayland}-({ints})$',                         '[0-9]*',               '@{int}',               'owner'),
(f'^{user_share}/gvfs-metadata/root-({random8})\.log$',                             '????????',             '@{rand8}',             'owner'),
(f'^{user_share}/kcookiejar/cookies\.({random6})$',                                 '??????',               '@{rand6}',             'owner'),
(f'^@/tmp/\.X11-unix/X(\d+)$',                                                      '[0-9]*',               '@{int}'),
(f'^@/tmp/\.ICE-unix/(\d+)$',                                                       '[0-9]*',               '@{int}'),
(f'^@/tmp/dbus-({random8})$',                                                       '????????',             '@{rand8}' ,            'owner'),
(f'^@/tmp/xauth_({random6})(?:|-c|-l)$',                                            '??????',               '@{rand6}',             'owner'),
(f'^/tmp/apt-changelog-({random6})/',                                               '??????',               '@{rand6}',             'owner'),
(f'^/tmp/apt-changelog-{random6}/\.apt-acquire-privs-test\.({random6})$',           '??????',               '@{rand6}',             'owner'),
(f'^/tmp/apt\.data\.({random6})$',                                                  '??????',               '@{rand6}',             'owner'),
(f'^/tmp/apt-key-gpghome\.({random10})/',                                           '??????????',           '@{rand10}',            'owner'),
(f'^/tmp/apt-key-gpghome\.{random10}/\.#lk0x({hexes16})\.',                         '[0-9a-f]*[0-9a-f]',    '@{hex}',               'owner'),
(f'^/tmp/apt-key-gpghome\.{random10}/\.#lk0x{hexes16}\.debian-stable\.(\d+)x?$',    '[0-9]*[0-9]',          '@{int}',               'owner'),
(f'^/tmp/aurules\.({random8})$',                                                    '????????',             '@{rand8}',             'owner'),
(f'^/tmp/kcminit\.({random6})$',                                                    '??????',               '@{rand6}',             'owner'),
(f'^/tmp/talpid-openvpn-({uuid})$',                                                 '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(f'^/tmp/Temp-({uuid})/',                                                           '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(f'^/tmp/tmp\.({random10})/',                                                       '??????????',           '@{rand10}',            'owner'),
(f'^/tmp/tmp({random8})/',                                                          '????????',             '@{rand8}',             'owner'),
(f'^/tmp/sort({random6})$',                                                         '??????',               '@{rand6}',             'owner'),
(f'^/tmp/systemd-private-({md5})-',                                                 '[0-9a-f]*[0-9a-f]',    '@{md5}',               'owner'),
(f'^/tmp/systemd-private-{md5}-[^/]+\.service-({random6})/',                        '??????',               '@{rand6}',             'owner'),
(f'^/tmp/({uuid})$',                                                                '[0-9a-f]*[0-9a-f]',    '@{uuid}',              'owner'),
(f'^{run}/gdm({o3})/',                                                              '{,3}',                  None),
(f'^{run}/log/journal/({md5})/',                                                    '[0-9a-f]*[0-9a-f]',    '@{md5}'),
(f'^{run}/netns/cni-({uuid})$',                                                     '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^{run}/NetworkManager/nm-openvpn-({uuid})$',                                     '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^{run}/systemd/seats/seat(\d+)$',                                                '[0-9]*',               '@{int}'),
(f'^{run}/systemd/netif/links/(\d+)$',                                              '[0-9]*',               '@{int}'),
(f'^{run}/systemd/sessions/(.+)\.ref$',                                             '*',                     None),
(f'^{run}/user/{users}/at-spi/bus_(\d+)$',                                          '[0-9]*',               '@{int}',               'owner'),
(f'^{run}/user/{users}/discover({random6})\.',                                      '??????',               '@{rand6}'),
(f'^{run}/user/{users}/kmozillahelper({random6})\.',                                '??????',               '@{rand6}',             'owner'),
(f'^{run}/user/{users}/kmozillahelper{random6}\.(\d+)\.',                           '[0-9]*[0-9]',          '@{int}',               'owner'),
(f'^{run}/user/{users}/wayland-(\d+)$',                                             '[0-9]*',               '@{int}',               'owner'),
(f'^{run}/user/{users}/xauth_({random6})$',                                         '??????',               '@{rand6}',             'owner'),
(f'^{sys}/bus/pci/slots/({ints})/',                                                 '[0-9]*',               '@{int}'),
(f'^{sys}/devices/pci\d+:\d+/({pciAddr})/',                                         '????:??:??.?',          None),
(f'^{sys}/devices/pci\d+:\d+/{pciAddr}/({pciAddr})/',                               '????:??:??.?',          None),
(f'^{sys}/devices/pci\d+:\d+/{pciAddr}/drm/card({ints})/',                          '[0-9]*',               '@{int}'),
(f'^{sys}/devices/pci\d+:\d+/{pciAddr}/drm/card{ints}/metrics/({uuid})/',           '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^{sys}/devices/pci(\d+:\d+)/',                                                   '[0-9]*',                None), # after previous
(f'^{sys}/devices/system/cpu/cpu({ints})/',                                         '[0-9]*',               '@{int}'),
(f'^{sys}/devices/system/cpu/cpufreq/policy({ints})/',                              '[0-9]*',               '@{int}'),
(f'^{sys}/devices/system/node/node({ints})/',                                       '[0-9]*',               '@{int}'),
(f'^{sys}/devices/virtual/hwmon/hwmon({ints})/',                                    '[0-9]*',               '@{int}'),
(f'^{sys}/devices/virtual/block/dm-({ints})/',                                      '[0-9]*',               '@{int}'),
(f'^{sys}/fs/btrfs/({uuid})/',                                                      '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^{sys}/firmware/efi/efivars/[^/]+-({uuid})$',                                    '[0-9a-f]*[0-9a-f]',    '@{uuid}'),
(f'^{sys}/kernel/iommu_groups/({ints})/',                                           '[0-9]*',               '@{int}'),
(f'^{proc}/{pids}/fdinfo/({ints})$',                                                '[0-9]*',               '@{int}',               'owner'),
(f'^{proc}/sys/net/ipv(4|6)/',                                                      '{4,6}',                 None),
(f'^{proc}/irq/({ints})/',                                                          '[0-9]*',               '@{int}'),
(f'^/dev/cpu/({ints})/',                                                            '[0-9]*',               '@{int}'),
(f'^/dev/dri/card(\d+)$',                                                           '[0-9]*',               '@{int}'),
(f'^/dev/input/event(\d+)$',                                                        '[0-9]*',               '@{int}'),
(f'^/dev/media(\d+)$',                                                              '[0-9]*',               '@{int}'),
(f'^/dev/pts/(\d+)$',                                                               '[0-9]*',               '@{int}',               'owner'),
(f'^/dev/tty(\d+)$',                                                                '[0-9]*',               '@{int}',               'owner'),
(f'^/dev/ttyS(\d+)$',                                                               '[0-9]*',               '@{int}',               'owner'),
(f'^/dev/vfio/(\d+)$',                                                              '[0-9]*',               '@{int}'),
(f'^/dev/video(\d+)$',                                                              '[0-9]*',               '@{int}'),
(f'/#(\d+)$',                                                                       '[0-9]*[0-9]',          '@{int}'),
(f'/\.goutputstream-({random6})$',                                                  '??????',               '@{rand6}'),
(f'/\.uuid\.TMP-({random6})$',                                                      '??????',               '@{rand6}'),
(f'/\.mutter-Xwaylandauth\.({random6})$',                                           '??????',               '@{rand6}'),
(f'/file({random6})$',                                                              '??????',               '@{rand6}'),
(f'/gnome-control-center-user-icon-({random6})$',                                   '??????',               '@{rand6}'),
(f'/blkid\.tab-({random6})$',                                                       '??????',               '@{rand6}'),
(f'/nvidia-xdriver-({random8})$',                                                   '????????',             '@{rand8}'),
(f'/socket-({random8})$',                                                           '????????',             '@{rand8}'),
(f'/pulse/({md5})-runtime(?:|\.tmp)$',                                              '[0-9a-f]*[0-9a-f]',    '@{md5}'),
(f'^(/home/{Any})/',                                                                '@{HOME}',               None,                  'owner'), # before the last; tunable isn't matching unix lines
(f'^@/home/({Any})/',                                                               '*',                     None,                  'owner'), # last; fallback for unix lines
(f'^(/{usr}lib(?:|exec|32|64))/',                                                    None,                  '@{lib}'),  # last <3
(f'^({BinC})/',                                                                      None,                  '@{bin}'),  # last <3
(f'^/({usr}s)bin/',                                                                 '{,usr/}{,s}',           None),     # last <3 (to match unhandled)
(f'^/({usr}local/)bin',                                                             '{,usr/}{,local/}',      None),     # last <3
(f'^/(|usr/)bin/',                                                                  '{,usr/}',               None),     # last <3
(f'^/(|usr/)lib/',                                                                  '{,usr/}',               None),     # last <3
    ]
    tunables = [  # default tunables only
#(f'^/{usr}lib/({multiarch})/',                                                      '@{multiarch}',          None),
(f'^({etc_ro})/',                                                                   '@{etc_ro}',             None),
(f'^/var/log/journal/{md5}/user-({users})(?:@|\.)',                                 '@{uid}',                None),
(f'^{homes}/(Desktop)/',                                                            '@{XDG_DESKTOP_DIR}',    None,                  'owner'),
(f'^{homes}/(Downloads)/',                                                          '@{XDG_DOWNLOAD_DIR}',   None,                  'owner'),
(f'^{homes}/(Templates)/',                                                          '@{XDG_TEMPLATES_DIR}',  None,                  'owner'),
(f'^{homes}/(Public)/',                                                             '@{XDG_PUBLICSHARE_DIR}',None,                  'owner'),
(f'^{homes}/(Documents)/',                                                          '@{XDG_DOCUMENTS_DIR}',  None,                  'owner'),
(f'^{homes}/(Music)/',                                                              '@{XDG_MUSIC_DIR}',      None,                  'owner'),
(f'^{homes}/(Pictures)/',                                                           '@{XDG_PICTURES_DIR}',   None,                  'owner'),
(f'^{homes}/(Videos)/',                                                             '@{XDG_VIDEOS_DIR}',     None,                  'owner'),
(f'^({user_shareC})/',                                                              '@{user_share_dirs}',    None,                  'owner'),
(f'^({run})/',                                                                      '@{run}',                None),
(f'^{run}/user/({users})/',                                                         '@{uid}',                None,                  'owner'),
(f'^{run}/systemd/users/({users})$',                                                '@{uid}',                None),
(f'^({sys})/',                                                                      '@{sys}',                None),
(f'^{sys}/fs/cgroup/user\.slice/user-({users})\.',                                  '@{uid}',                None),
(f'^{sys}/fs/cgroup/user\.slice/user-{users}\.slice/user@({users})\.',              '@{uid}',                None), # '@' is a string
(f'^({proc})/',                                                                     '@{PROC}',               None),
(f'^{proc}/({pids})/',                                                              '@{pid}',                None,                  'owner'),
(f'^{proc}/{pids}/task/({tids})/',                                                  '@{tid}',                None,                  'owner'),
(f'^/tmp/tracker-extract-3-files.({users})/',                                       '@{uid}',                None,                  'owner'),
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

        elif ruleStyle == 'roddhjav/apparmor.d' and \
             a:

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
    Any    = '(?!@{.+|{.+|\[0-9.+|\*)[^/]+'
    usersC = '(?:[0-9]|[1-9][0-9]{1,8}|[1-4][0-9]{9})'
    md5C   = '(?:[0-9a-fA-F]{32})'
    uuidC  = '(?:[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})'
    regexpToMacro = [
 # regex                                              # default  # apparmor.d
(f'^/org/freedesktop/ColorManager/devices/({Any})$',  '*',       None),
(f'^/org/freedesktop/UDisks2/drives/({Any})$',        '*',       None),
(f'^/org/freedesktop/UDisks2/block_devices/({Any})$', '*',       None),
(f'^/org/freedesktop/systemd1/unit/({Any})$',         '*',       None),
(f'^/org/freedesktop/login1/session/({Any})$',        '*',       None),
 # Capturing *any* goes above
(f'/User({usersC})(?:/|$)',                           '@{uid}',  None),
(f'/({uuidC})(?:/|$)',                                '*',       '@{uuid}'),
(f'/icc_({md5C})$',                                   '*',       '@{md5}'),
(f'/(\d+)$',                                          '[0-9]*',  '@{int}'),
(f'/(\d+)/',                                          '[0-9]*',  '@{int}'),  # separate to mitigate overlaping
(f'/_(\d+)$',                                         '[0-9]*',  '@{int}'),
(f'/Source_(\d+)(?:/|$)',                             '[0-9]*',  '@{int}'),
(f'/Client(\d+)(?:/|$)',                              '[0-9]*',  '@{int}'),
(f'/ServiceBrowser(\d+)(?:/|$)',                      '[0-9]*',  '@{int}'),
(f'/seat(\d+)$',                                      '[0-9]*',  '@{int}'),
(f'/prompt/u(\d+)$',                                  '[0-9]*',  '@{int}'),
(f'/Prompt/p(\d+)$',                                  '[0-9]*',  '@{int}'),
(f'/loop(\d+)$',                                      '[0-9]*',  '@{int}'),  # unreachable?
    ]

    for profile in lines:
        for l in lines[profile]:
            if not findLineType(l).startswith('DBUS'):
                raise ValueError('Using this function to handle non-DBus log lines could lead to silent errors.')

            if not l.get('path'):  # skip bind, eavesdrop, etc
                continue

            for r,d,a in regexpToMacro:
                if ruleStyle == 'roddhjav/apparmor.d' and a:
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
        # regex                 # default style     # apparmor.d style
        ('\.tmp$',             '{,.tmp}',           None),
        ('~$',                 '{,~}',              None),
        ('\.[A-Z0-9]{6}$',     '{,.??????}',        '{,.@{rand6}}'),
        ('\.tmp[A-Z0-9]{6}$',  '{,.tmp??????}',     '{,.tmp@{rand6}}'),
        ('\.tmp[0-9]{4}$',     '{,.tmp????}',       '{,.tmp@{int}}'),
    )
    # TODO
    # /usr/share/applications/mimeinfo.cache
    # /usr/share/applications/.mimeinfo.cache.JLI8D2

    for r,d,a in tempRegexesToMacro:
        suffixRe = re.search(r, filename)
        if suffixRe:
            tempTail = suffixRe.group(0)
            if ruleStyle == 'roddhjav/apparmor.d' and a:
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
    sensitivePatterns = (  # with Red; re.I
        '/\.ssh/(id[^.]+)(?!.*\.pub)(?:/|$)',
        '/(ssh_host_[^/]+_key(?:[^.]|))(?!.*\.pub)',
        '(?<!pubring\.orig\.)(?<!pubring\.)(?<!mouse)(?<!turn|whis|flun|dove|alar|rick|apt-|gtk-)(?<!hoc|don|mon|tur|coc|joc|lac|buc|soc|haw|pun|tac|flu|dar|sna|smo|cri|coo|pin|din|dic)(?<!ca|mi)(key)(?!button|stroke|board|punch|less|code|pal|pad|gen|\.pub|word\.cpython|-manager-qt_ykman.png|-personalization-gui.png|-personalization-gui_yubikey-personalization-gui.png)', # only key; NOT: turkey, keyboard, keygen, etc
        '(?<!grass|snake|birth|colic|coral|arrow|blood|orris|bread|squaw|fever|itter|inger)(?<!worm|alum|rose|club|pink|beet|poke|musk|fake)(?<!tap|che|red|she)(?<!sc|ch)(root)(?!stalk|worm|stock|less|s)', # only root; NOT: grassroots, rootless, chroot, etc
        '(?<!non)(secret)(?!agogue|ion|ary|ari)', # only secret, secrets; NOT: nonsecret, secretary, etc
        '(?<!non|set)(priv)(?!atdocent|atdozent|iledge|ates|ation|ateer|atise|arize|atist|ation|er|et|es|ed|ie|al|y|e)', # only priv, private; NOT: nonprivate, privatise, etc
        '(?<!com|sur|out)(pass)(?!epied|erine|enger|along|ible|erby|able|less|band|ivi|ive|age|ade|ion|ed|el|er|wd)', # only pass, password; NOT: compass, passage, etc
        '(?<!over|fore)(?<!be)(shadow)(?!graph|iest|like|less|ing|ily|ers|box|ier|er|ed|y|s)', # only shadow; NOT: foreshadow, shadows, etc
        '(?<!na|sa|ac)(cred)(?!ulous|ulity|uliti|enza|ence|ibl|ibi|al|it|o)', # only cred, creds, credentials; NOT: sacred, credence, etc
        '(?:/|^)(0)(?:/|$)', # standalone zero: 0, /0, /0/; NOT: a0, 0a, 01, 10, 101, etc
        '^(?:/proc|@{PROC})/(1)/',
        '^(?:/proc|@{PROC})(?:/\d+|/@{pids?})?/(cmdline)$',
        '(cookies)\.sqlite(?:-wal|)$',
        '(cookiejar)',
        )
    random6  = '(?![0-9]{6}|[a-z]{6}|[A-Z]{6}|[A-Z][a-z]{5}|[A-Z][a-z]{4}[0-9]|base\d\d|\d{5}x)[0-9a-zA-Z]{6}' # aBcXy9, AbcXyz, abcxy9, ABCXY9; NOT 123789, abcxyz, ABCXYZ, Abcxyz, Abcxy1, base35, 12345x
    random8  = '(?![0-9]{8}|[a-z]{8}|[A-Z]{8}|[A-Z][a-z]{7}|[A-Z][a-z]{6}[0-9])[0-9a-zA-Z]{8}' # aBcDwXy9, AbcdWxyz, abcdwxy9, ABCDWXY9; NOT: 12346789, abcdwxyz, ABCDWXYZ, Abcdwxyz, Abcdwxy1
    random10 = '(?![0-9]{10}|[a-z]{10}|[A-Z]{10}|[A-Z][a-z]{9}|[A-Z][a-z]{8}[0-9]|PackageKit)[0-9a-zA-Z]{10}' # aBcDeVwXy9, AbcdeVwxyz, abcdevwxy9, ABCDEVWXY9; NOT: 1234567890, abcdevwxyz, ABCDEVWXYZ, Abcdevwxyz, Abcdevwxy1, PackageKit
    volatilePatterns = (  # with Yellow
        '/#(\d+)$',  # trailing number with leading hash sign
       f'[-.]({random6})(?:/|$)',
       f'[-.]({random8})(?:/|$)',
       f'[-.]({random10})(?:/|$)',
        '[-.](?![0-9]{8}|[a-z]{8})([0-9a-z]{8})\.log$',
        '[-.](?![0-9]{8}|[A-Z]{8})([0-9A-Z]{8})\.log$',
        '(?=[^0-9a-fA-F]0x([0-9a-fA-F]{16})(?:[^0-9a-fA-F]|$))', # hex address
        '(?=[^0-9a-fA-F]([0-9a-fA-F]{32})(?:[^0-9a-fA-F]|$))',   # standalone MD5
        '(?=[^0-9a-fA-F]([0-9a-fA-F]{38})(?:[^0-9a-fA-F]|$))',   # ??
        '(?=[^0-9a-fA-F]([0-9a-fA-F]{56})(?:[^0-9a-fA-F]|$))',   # standalone SHA224
        '(?=[^0-9a-fA-F]([0-9a-fA-F]{64})(?:[^0-9a-fA-F]|$))',   # standalone SHA256
        '(?=[^0-9a-fA-F]([0-9a-fA-F]{96})(?:[^0-9a-fA-F]|$))',   # standalone SHA384
        '(?=[^0-9a-fA-F]([0-9a-fA-F]{128})(?:[^0-9a-fA-F]|$))',  # standalone SHA512
        '(?=[^0-9a-fA-F]([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})(?:[^0-9a-fA-F]|$))', # standalone UUID
        '^@?/home/([^/]+)/', # previously unmatched homes
    )

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

def adaptProfileAutoTransitions(l):

    always_ix = { # only for '/usr/bin/' and '/bin/'; not for programs with network access or large scope
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
    }

    # Move automatic transition to the parent
    if '▶' in l.get('profile'):             # only for 'profile'
        split = l.get('profile').split('▶')
        if split[-1] in always_ix     and \
           split[-1] == l.get('comm'):      # if present in 'always_ix' and equals to 'comm'

            del split[-1]  # delete last automatic transition id
            l['profile'] = '▶'.join(split)  # identify as parent
            l['comm']    = colorize(l.get('comm'), 'Blue')  # colorize imidiately

            if getBaseBin(l.get('name')) in always_ix:
                l['requested_mask'] += 'I'  # mark as possible 'ix' candidate

    return l

def isBaseAbstractionTransition(l, profile_):
    '''Only for file lines. Must be done after normalization and before adaption. Temporary solution?'''
    multiarch   = '(?:[^/]+-linux-gnu(?:[^/]+|)|@{multiarch})'
    proc        = '(?:/proc|@{PROC})'
    etc_ro      = '(?:/usr/etc|/etc|@{etc_ro})'
    run         = '(?:/var/run|/run|@{run})'
    sys         = '(?:/sys|@{sys})'

    baseAbsRules = {  # re.match
       f'^/dev/log$': {'w'},
       f'^/dev/u?random$': {'r'},
       f'^{run}/uuidd/request$': {'r'},
       f'^{etc_ro}/locale/.+': {'r'},
       f'^{etc_ro}/locale\.alias$': {'r'},
       f'^{etc_ro}/localtime$': {'r'},
       f'^/etc/writable/localtime$': {'r'},
       f'^/usr/share/locale-bundle/.+': {'r'},
       f'^/usr/share/locale-langpack/.+': {'r'},
       f'^/usr/share/locale/.+': {'r'},
       f'^/usr/share/.+/locale/.+': {'r'},
       f'^/usr/share/zoneinfo/.*': {'r'},
       f'^/usr/share/X11/locale/.+': {'r'},
       f'^{run}/systemd/journal/dev-log$': {'w'},
       f'^{run}/systemd/journal/socket$': {'w'},
       f'^{run}/systemd/journal/stdout$': {'r', 'w'},
       f'^/(|usr/)lib(|32|64)/locale/.+': {'m', 'r'},
       f'^/(|usr/)lib(|32|64)/gconv/[^/]+\.so$': {'m', 'r'},
       f'^/(|usr/)lib(|32|64)/gconv/gconv-modules(|[^/]+)$': {'m', 'r'},
       f'^/(|usr/)lib/{multiarch}/gconv/[^/]+\.so$': {'m', 'r'},
       f'^/(|usr/)lib/{multiarch}/gconv/gconv-modules(|[^/]+)$': {'m', 'r'},
       f'^{etc_ro}/bindresvport\.blacklist$': {'r'},
       f'^{etc_ro}/ld\.so\.cache$': {'m', 'r'},
       f'^{etc_ro}/ld\.so\.conf$': {'r'},
       f'^{etc_ro}/ld\.so\.conf\.d/(|[^/]+\.conf)$': {'r'},
       f'^{etc_ro}/ld\.so\.preload$': {'r'},
       f'^/(|usr/)lib(|32|64)/ld(|32|64)-[^/]+\.so$': {'m', 'r'},
       f'^/(|usr/)lib/{multiarch}/ld(|32|64)-[^/]+\.so$': {'m', 'r'},
       f'^/(|usr/)lib/tls/i686/(cmov|nosegneg)/ld-[^/]+\.so$': {'m', 'r'},
       f'^/(|usr/)lib/i386-linux-gnu/i686/(cmov|nosegneg)/ld-[^/]+\.so$': {'m', 'r'},
       f'^/opt/[^/]+-linux-uclibc/lib/ld-uClibc(|[^/]+)so(|[^/]+)$': {'m', 'r'},
       f'^/(|usr/)lib(|32|64)/.+': {'r'},
       f'^/(|usr/)lib(|32|64)/.+\.so(|[^/]+)$': {'m', 'r'},
       f'^/(|usr/)lib/{multiarch}/.+': {'r'},
       f'^/(|usr/)lib/{multiarch}/.+\.so(|[^/]+)$': {'m', 'r'},
       f'^/(|usr/)lib/tls/i686/(cmov|nosegneg)/[^/]+\.so(|[^/]+)$': {'m', 'r'},
       f'^/(|usr/)lib/i386-linux-gnu/i686/(cmov|nosegneg)/[^/]+\.so(|[^/]+)$': {'m', 'r'},
       f'^/(|usr/)lib(|32|64)/\.lib[^/]+\.so[^/]+\.hmac$': {'r'},
       f'^/(|usr/)lib/{multiarch}/\.lib[^/]+\.so[^/]+\.hmac$': {'r'},
       f'^/dev/null$': {'r', 'w',},
       f'^/dev/zero$': {'r', 'w',},
       f'^/dev/full$': {'r', 'w',},
       f'^{proc}/sys/kernel/version$': {'r'},
       f'^{proc}/sys/kernel/ngroups_max$': {'r'},
       f'^{proc}/meminfo$': {'r'},
       f'^{proc}/stat$': {'r'},
       f'^{proc}/cpuinfo$': {'r'},
       f'^{sys}/devices/system/cpu/(|online)$': {'r'},
       f'^{proc}/\d+/(maps|auxv|status)$': {'r'},
       f'^{proc}/crypto/[^/]+$': {'r'},
       f'^/usr/share/common-licenses/.+': {'r'},
       f'^{proc}/filesystems$': {'r'},
       f'^{proc}/sys/vm/overcommit_memory$': {'r'},
       f'^{proc}/sys/kernel/cap_last_cap$': {'r'},
       # crypto include (oldest)
       f'^{etc_ro}/gcrypt/random\.conf$': {'r'},
       f'^{proc}/sys/crypto/[^/]+$': {'r'},
       f'^/(etc/|usr/share/)crypto-policies/[^/]+/[^/]+\.txt$': {'r'},
    }

    result = False
    if '▶' in profile_   or \
      isTransitionComm(l.get('comm')):  # transition features

        path      = l.get('path')
        pathMasks = l.get('mask')
        for regex,mask in baseAbsRules.items():
            if 'a' in pathMasks and \
               'w' in mask:     # 'w' consumes 'a'

                mask.add('a')

            if re.match(regex, path)   and \
               pathMasks.issubset(mask):
 
                result = True

    return result

def grabLogsByBootId(id_, isKeepStatus):

    j = journal.Reader()
    #j.this_boot(bootid=id_)
    j.this_boot()
    j.this_machine()
    j.add_match('SYSLOG_IDENTIFIER=kernel',
                'SYSLOG_IDENTIFIER=audit',
                'SYSLOG_IDENTIFIER=dbus-daemon')  # try to limit spoofing surface
    lineDicts = []
    for entry in j:
        if re.search('apparmor="?(ALLOWED|DENIED)', entry['MESSAGE']):
            processedLine = findLogLine(entry['MESSAGE'], isKeepStatus)
            if not processedLine in lineDicts:
                # Ascending order to flag the lowest
#                if not processedLine.get('operation').startswith('dbus') and \
#                       entry['SYSLOG_IDENTIFIER'] == 'dbus-daemon':  # came from DBus, but not a DBus line
#
#                    processedLine['trust'] = 2
#
#                elif entry.get('_AUDIT_TYPE_NAME') == 'USER_AVC':
#                    processedLine['trust'] = 5
#
#                elif processedLine.get('operation').startswith('dbus'):
#                    processedLine['trust'] = 6
 
                lineDicts.append(processedLine)

    return lineDicts

def findTrustLevels(line):

    return None

def findLogLine(rawLine, isKeepStatus):
    '''Make dictionary from raw log line'''
    toSkipKeys = {'audit:', 'AVC', 'capability', 'denied_mask', 'ouid', 'sauid', 'fsuid', 'pid', 'peer_pid', 'type', 'class'}
    if not isKeepStatus:
        toSkipKeys.add('apparmor')

    lineList = shlex.split(rawLine)

    # Unwrap nested message
    for i in lineList:
        if re.match('msg=apparmor="?(ALLOWED|DENIED)', i):
            cleaned = i.removeprefix('msg=').strip()
#            cleaned += ' trust=4'  # needed? TODO
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
             re.match(':\d+\.\d+', val):

            adaptedName = re.sub('\.\d+$', '.[0-9]*', val)
            lineDict.update({key: adaptedName})

        elif val:
            lineDict.update({key: val})

    return lineDict

def normalizeProfileName(l):
    '''Dealing early with regular operation format (string)'''
    if l.get('operation').startswith('dbus'):
        l['profile'] = l.pop('label')

        if 'peer_label' in l.keys():
            l['peer'] = l.pop('peer_label')

    # Remove 'target' if it's the same as 'name' (path)
    delimeter = '//null-'
    if l.get('target'):
        if delimeter in l.get('target'):
            split = l.get('target').split(delimeter)
            realTarget = split[-1]
            if l.get('name') == realTarget:
                l.pop('target')

    # Make automatic transition more readable
    toChangeKeys = ['profile', 'peer', 'target']
    for k in toChangeKeys:
        if l.get(k):
            if delimeter in l.get(k):
                profileNames = []
                split = l.pop(k).split(delimeter)
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

    regexp = re.match('^/(?:|usr/)bin/([^/]+)$', path)  # 'sbin' isn't covered
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
        if '*diffs' in keysToHide:
            toDropKeys = ('path_diffs', 'srcpath_diffs', 'target_diffs', 'addr_diffs', 'peer_addr_diffs')
            keysToHide.extend(toDropKeys)
        [l.pop(k) for k in keysToHide if l.get(k)]

    toDropStalePrefixesKeys = ('path_prefix', 'srcpath_prefix', 'target_prefix', 'addr_prefix', 'peer_addr_prefix')
    [l.pop(k) for k in toDropStalePrefixesKeys if l.get(k)]  # drop prefixes which unrelevant anymore

    s = ''
    for k,v in l.items():
        if isinstance(v, set):
            if 'file_inherit' in v:
                v.remove('file_inherit')
                v.add(colorize('file_inherit', 'Yellow'))
            v = ','.join(sorted(v))

        if not isinstance(v, int):
            if ' ' in v:
                v = f"'{v}'"

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
        raise ValueError('Incorrect color specified.')

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
        #',': 'Blue',  # breaks other colors in the middle; TODO?
        #'*': 'Red',
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
            while path_.endswith('\x00'):  # trim trailing zeroes ; TODO testing
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
            raise ValueError('No capturing group. Check your regexes.')
        elif len(whatRe.groups()) >= 2:
            raise NotImplementedError('More than one capturing group is not supported. Check your regexes.')
        elif subWith == 'owner':
            raise ValueError('Looks like an error. Check missing commas in your regex tuples.')
#        elif whatRe.group(1).startswith('@{') or \
#             whatRe.group(1).startswith('{')  or \
#             whatRe.group(1).startswith('['):
#            print(whatRe,          file=sys.stderr)
#            print(whatRe.group(1), file=sys.stderr)
#            raise ValueError('Second attempt to capture an already substituted match. This is unnecessary and will lead to malformed diffs. Check your regexes.')
    #    elif not oldDiff:
    #        raise ValueError('Capturing group is empty! Check your regexes.')  # TODO?

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

    if   operation in fileOperations and \
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
    dangerousCombinations = (  # dangerous combinations to highlight
        ('x', 'wadclk'),
        ('m', 'wadclk'),
    )
    toColorize = {}

    is_ix_candidate = False
    if 'I' in maskSet:  # possible 'ix' candidate
        maskSet.remove('I')  # remove previous marking
        is_ix_candidate = True

    if 'N' in maskSet:
        maskSet.remove('N')
        maskSet.add('P')
        toColorize['P'] = ('Bright Black', '7')  # background

    # Determine additional mask from automatic transition
    if transitionMask:
        maskDiff = maskSet.intersection(transitionMask)
        for i in maskDiff:
            toColorize[i] = ('Blue', '0')  # regular

            if is_ix_candidate and \
               'x' in maskSet:

                maskSet.add('i')
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

    # Preserve unknown masks
    maskString = ''.join(maskList)
    if maskSet:
        suffix = ''.join(sorted(maskSet))
        maskString += suffix

    # Determine what to colorize
    toReplaceChars = set()
    for s1,s2 in dangerousCombinations:
        if len(s1) >= 2:  # sanity
            raise ValueError('Leading mask for comparison could only be a single character.')

        for subS in s2:
            if   s1 in maskString and \
               subS in maskString:
                toReplaceChars.update([s1, subS])

    # Colorize dangerous combinations
    for s in maskString:
        if s in toReplaceChars:
            highlight = colorize(s, 'Red', '7')  # background
            maskString = maskString.replace(s, highlight)

    # Colorize unpacked items
    for k,v in toColorize.items():
        if k in maskString:
            color      = v[0]
            colorStyle = v[1]
            highlight = colorize(k, color, colorStyle)
            maskString = maskString.replace(k, highlight)

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
                    l['member'] = 'BUG'.join(l.pop('member'))

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
        #nestedDifferences_byId = {}
        #nestedSuffixes_byId = {}
        newLogLines_forProfile = []
        for l in lines[profile]:
            if not l.get(key):
                newLogLines_forProfile.append(l)  # save non-mergable
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

def mergeDownCommMasks(lines):
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
    if not requestedProfiles: # all
        result = True

    elif not currentProfile:  # no 'profile_peer' key
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

def normalizeAndSplit(lines, args_):
    '''Split lines by type and convert specific values to sets for further merging'''
    toDropDbusKeyValues_inLines = {
        'hostname': '?',
        'addr':     '?',
        'terminal': '?',
        'exe':      '/usr/bin/dbus-daemon',
    }
    toAdaptPathKeys = ('path', 'srcpath', 'target', 'interface', 'addr', 'peer_addr') # must be done after normalization and before stacking

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
        if not isRequestedProfile(profile, args_.profile):
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
            if not isRequestedProfile(l.get('peer'), args_.peer):
                continue

            if args_.drop_comm:
                if l.get('comm'):
                    l.pop('comm')
            elif l.get('comm'):
                l['comm'] = {hexToString(l.pop('comm'))}

            l['operation'] = {l.pop('operation')}

            # Stacks or sinkholes based on params
            if findLineType(l) == 'FILE':
                if 'file' in args_.type:
                    l['path'] = l.pop('name')
                    l['mask'] = set(list(l.pop('requested_mask')))

                    if not args_.keep_base_abs_transitions:
                        if isBaseAbstractionTransition(l, profile):
                            continue

                    [adaptFilePath(l, k, args_.style) for k in toAdaptPathKeys if l.get(k)]
                    fileL.append(l)

            elif findLineType(l).startswith('DBUS'):
                if 'dbus' in args_.type:
                    [l.pop(k) for k,v in toDropDbusKeyValues_inLines.items() if l.get(k) == v] # drop non-informative DBus data
                    if l.get('member'):
                        l['member'] = {l.pop('member')}
 
                    dbusL.append(l)

            elif findLineType(l) == 'NETWORK':
                if 'network' in args_.type:
                    l.pop('protocol')
                    l['mask'] = set(l.pop('requested_mask').split())
                    networkL.append(l)

            elif findLineType(l) == 'UNIX':
                if 'unix' in args_.type:
                    if l.get('protocol') == '0':
                        l.pop('protocol')
 
                    l['mask'] = set(l.pop('requested_mask').split())
                    [adaptFilePath(l, k, args_.style) for k in toAdaptPathKeys if l.get(k)]
                    unixL.append(l)

            elif findLineType(l) == 'CAPABILITY':
                if 'cap' in args_.type:
                    capL.append(l)

            elif findLineType(l) == 'SIGNAL':
                if 'signal' in args_.type:
                    l['signal'] = {l.pop('signal')}
                    signalL.append(l)

            elif findLineType(l) == 'PTRACE':
                if 'ptrace' in args_.type:
                    l['mask'] = set(l.pop('requested_mask').split())
                    ptraceL.append(l)

            elif findLineType(l) == 'MOUNT':
                if 'mount' in args_.type:
                    if l.get('name'):
                        l['path'] = l.pop('name')
                    if l.get('srcname'):
                        l['srcpath'] = l.pop('srcname')

                    [adaptFilePath(l, k, args_.style) for k in toAdaptPathKeys if l.get(k)]
                    mountL.append(l)

            elif findLineType(l) == 'PIVOT':
                if 'pivot' in args_.type:
                    if l.get('name'):
                        l['path'] = l.pop('name')
                    if l.get('srcname'):
                        l['srcpath'] = l.pop('srcname')

                    [adaptFilePath(l, k, args_.style) for k in toAdaptPathKeys if l.get(k)]
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

def composeRule(l, args_):
    '''Compose final rule and insert it into dictionary line.'''
    if findLineType(l) == 'FILE':
        if l.get('transition_mask'):
            transitionMask = l.pop('transition_mask')
        else:
            transitionMask = None

        mask = composeFileMask(l.pop('mask'), transitionMask, args_.convert_file_masks)
        if ' ' in l.get('path'):
            path = f'"{l.pop("path")}"'
        else:
            path = l.pop('path')

        if l.get('path_prefix'):
            prefix = f"{l.pop('path_prefix')} "
        else:
            prefix = ''

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
            comment = colorize('# no peer label', 'Cyan')
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
    l['rule'] = f'[{rule}]'

    return l  # leftovers

def sortLines(fileL,   dbusL,  networkL,
              unixL,   capL,   signalL,
              ptraceL, mountL, pivotL,  unknownL, args_):

    allDicts = mergeNestedDictionaries(fileL,    dbusL)
    allDicts = mergeNestedDictionaries(allDicts, networkL)
    allDicts = mergeNestedDictionaries(allDicts, unixL)
    allDicts = mergeNestedDictionaries(allDicts, capL)
    allDicts = mergeNestedDictionaries(allDicts, signalL)
    allDicts = mergeNestedDictionaries(allDicts, ptraceL)
    allDicts = mergeNestedDictionaries(allDicts, mountL)
    allDicts = mergeNestedDictionaries(allDicts, pivotL)
    if 'unknown' in args_.type:
        allDicts = mergeNestedDictionaries(allDicts, unknownL)

    # Convert dict of dicts to list of dicts
    allDicts_inlined = []
    for profile in allDicts:
        for l in allDicts[profile]:
            l['profile'] = profile
            allDicts_inlined.append(l)

    # Sort by peer, member, interface, then path if exists, finally grouping by profile
    if args_.sort == 'profile':
        [l.pop('timestamp') for l in allDicts_inlined]
        sortedList = sorted(allDicts_inlined, key=lambda l: ('peer' not in l, l.get('peer', None)))
        sortedList = sorted(sortedList,       key=lambda l: ('member'       not in l, l.get('member',       None)))
        sortedList = sorted(sortedList,       key=lambda l: ('interface'    not in l, l.get('interface',    None)))
        sortedList = sorted(sortedList,       key=lambda l: ('path'         not in l, l.get('path',         None)))
        sortedList = sorted(sortedList,       key=lambda l: ('addr'         not in l, l.get('addr',         None)))
        sortedList = sorted(sortedList,       key=lambda l:                           l.get('profile'))

    # Sort by order of appearance
    elif args_.sort == 'timestamp':
        sortedList = sorted(allDicts_inlined, key=lambda l: l.get('timestamp'))
        [l.pop('timestamp') for l in sortedList]

    # Sort by path if exists ignoring profile names
    elif args_.sort == 'path':
        [l.pop('timestamp') for l in allDicts_inlined]
        sortedList = sorted(allDicts_inlined, key=lambda l: ('path' not in l, l.get('path', None)))

    # Sort by profile's peer name (label) if exists ignoring profile names
    elif args_.sort == 'peer':
        [l.pop('timestamp') for l in allDicts_inlined]
        sortedList = sorted(allDicts_inlined, key=lambda l: ('peer' not in l, l.get('peer', None)))

    # Sort by DBus interface if exists ignoring profile names
    elif args_.sort == 'interface':
        [l.pop('timestamp') for l in allDicts_inlined]
        sortedList = sorted(allDicts_inlined, key=lambda l: ('interface' not in l, l.get('interface', None)))

    # Sort by DBus member if exists ignoring profile names
    elif args_.sort == 'member':
        [l.pop('timestamp') for l in allDicts_inlined]
        sortedList = sorted(allDicts_inlined, key=lambda l: ('member' not in l, l.get('member', None)))

    return sortedList

def colorizeLines(plainLines):

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
        #'path_diffs', # expand? TODO
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

        if l.get('info') == 'profile transition not found':
            l['mask'].add('N')

        if findLineType(l).startswith('DBUS'):
            if re.match(':\d+\.\[0-9\]\*$', l.get('name')):
                colorized = colorize('[0-9]*', 'Green')
                l['name'] = l.get('name').removesuffix('[0-9]*') + colorized

            members = l.get('member')
            if members:
                if members.startswith('{') and \
                   members.endswith('}'):  # multiple changed members

                    l['member'] = colorize(members, 'White')

        toChangeKeys = ['profile', 'peer', 'target']
        for k in toChangeKeys:
            if l.get(k):
                if '▶' in l.get(k):
                    l[k] = l.get(k).replace('▶', colorize('▶', 'Blue'))
#                elif '▷' in l.get(k):
#                    l[k] = l.get(k).replace('▷', colorize('▷', 'Blue'))

    return plainLines

def findPadding(plainLines):

    padding = {}
#    for l in plainLines:
#        for k,v in l.items():
#            padding[k] = len(v)

    return padding

def display(plainLines, padding_, args_):

    [composeRule(l, args) for l in plainLines]
    previousProfile = None
    for l in plainLines:
        if previousProfile != l.get('profile'):
            isNextProfile = True
        else:
            isNextProfile = False
        previousProfile = l.get('profile')

        if args_.sort == 'profile':
            prefix = ''
            profile = l.pop('profile')
            if isNextProfile:
                print(f"\n  {profile}")

        else:
            pP = adjustPadding(l.get('profile'), 29)
            prefix = f"{l.pop('profile'):{pP}} "

        rule = l.pop('rule')

        if rule.startswith('[unix '):  # :/
            P = adjustPadding(rule, 120)
        else:
            P = adjustPadding(rule, 50)

        if l:  # if have leftovers
            suffix = composeSuffix(l, args_.hide_keys)
            toDisplay = f'{prefix}{rule:{P}} {suffix}'
        else:
            toDisplay = f'{prefix}{rule}'

        print(toDisplay)

    return None

def adjustPadding(str_, targetPadding_):
    '''By decolorizing (a copy). Temp?'''

    strRe = re.findall('\\033\[\d;\d{2}m|\\033\[0m', str_)
    if strRe:
        result = targetPadding_ + len(''.join(strRe))
    else:
        result = targetPadding_

    return result

def warnIfNotSupportedDistro():

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

    if not isSupported:
        not_supported = colorize('not supported', 'Yellow')
        print(f'This distro is {not_supported}. Watch out for inconsistencies.', file=sys.stderr)

    return None

def failIfNotConfined():
    '''Only covers confinement, not necessary enforcement'''
    randomTail = ''.join(random.choice(string.ascii_letters) for i in range(8))
    path = f'/tmp/aa_suggest.am_i_confined.{randomTail}'

    try:
        with open(path, 'w') as f:
            f.write("DELETEME\n")
    except Exception:  # expected behavior
        pass

    file = pathlib.Path(path)
    if file.is_file():
        file.unlink()
        raise EnvironmentError('The process is not confined by AppArmor. Refusing to function.')

    return None

def handleArgs():

    allLineTypes  = ['file', 'dbus', 'unix', 'network', 'signal', 'ptrace', 'cap', 'mount', 'pivot', 'unknown']
    allSuffixKeys = ['comm', 'operation', 'mask', '*diffs', 'error', 'info', 'class']

    parser = argparse.ArgumentParser(description='Suggest AppArmor rules')
    parser.add_argument('-v', '--version', action='version', version='aa_suggest.py 0.8')
#    parser.add_argument('-b', '--boot-id', action='store', type=int,
#                        choices=range(-14, 1),
#                        default=0,
#                        help='Specify (previous) boot id')
    parser.add_argument('-t', '--type', action='append',
                        choices=allLineTypes,
                        help='Handle only specified rule type')
    parser.add_argument('-p', '--profile', action='append',
                        default=[],
                        help='Handle only specified profile')
    parser.add_argument('-l', '--peer', action='append',
                        help='Handle only specified peer profile')
#    parser.add_argument('--operation', action='append',
#                        help='Display only lines containing specified operation')
    parser.add_argument('--hide-keys', action='append',
                        choices=allSuffixKeys + ['ALL'],
                        default=[],
                        help='Hide specified keys in suffix. Does not affect merging')
#    parser.add_argument('--hide-transitions', action='store_true',
#                        help='Do not expand automatic profile transitions when filtering by specific profile')
    parser.add_argument('--keep-base-abs-transitions', action='store_true',
                        default=False,
                        help="Do not drop automatic transition lines '▶' which rules are present in 'base' abstraction")
    parser.add_argument('--drop-comm', action='store_true',
                        default=False,
                        help='Drop comm key to affect further merging')
    parser.add_argument('--keep-status', action='store_true',
                        help="Do not drop 'apparmor' status key. Affects merging")
    parser.add_argument('-c', '--convert-file-masks', action='store_true',
                        help='Convert requested file masks to currently supported variants. Will be deprecated (changed)')
    parser.add_argument('--style', action='store',
                        choices=['default', 'roddhjav/apparmor.d'],
                        default='default',
                        help='Style preset. Affects custom tunables')
    parser.add_argument('-s', '--sort', action='store',
                        choices=['profile', 'peer', 'path', 'interface', 'member', 'timestamp'],
                        default='profile',
                        help="Sort by. 'profile' is the default")

    args = parser.parse_args()
    if not args.type:
        args.type = allLineTypes

    if 'ALL' in allSuffixKeys:
        args.hide_keys = allSuffixKeys

    return args

if __name__ == '__main__':

    failIfNotConfined()

    try:
        from systemd import journal
    except ModuleNotFoundError:
        raise ModuleNotFoundError("'systemd' module not found! Install with:\nsudo apt install python3-systemd")

    warnIfNotSupportedDistro()

    args = handleArgs()

    logLines = grabLogsByBootId(None, args.keep_status)
    unsortedLines = []
    for n,l in enumerate(logLines):
        normalizeProfileName(l)
        if findLineType(l) == 'FILE':
            adaptProfileAutoTransitions(l)

        l['timestamp'] = n
        unsortedLines.append(l)

    allLines = groupLinesByProfile(unsortedLines)

    splitLines_Out = normalizeAndSplit(allLines, args)
    fileLines    = splitLines_Out[0]
    dbusLines    = splitLines_Out[1]
    networkLines = splitLines_Out[2]
    unixLines    = splitLines_Out[3]
    capLines     = splitLines_Out[4]
    signalLines  = splitLines_Out[5]
    ptraceLines  = splitLines_Out[6]
    mountLines   = splitLines_Out[7]
    pivotLines   = splitLines_Out[8]
    unknownLines = splitLines_Out[9]

    if 'file'    in args.type:
        fileLines = adaptTempPaths(fileLines, args.style)
        fileLines = mergeDictsByKeyPair(fileLines, 'mask', 'operation')
        fileLines = mergeDownCommMasks(fileLines)
        #fileLines = mergeDiffs(fileLines)

    if 'dbus'    in args.type:
        dbusLines = adaptDbusPaths(dbusLines, args.style)
        dbusLines = mergeDictsBySingleKey(dbusLines, 'member')
        dbusLines = composeMembers(dbusLines)

    if 'network' in args.type:
        networkLines = mergeDictsByKeyPair(networkLines, 'mask', 'operation')

    if 'unix'    in args.type:
        unixLines   = mergeDictsByKeyPair(unixLines, 'mask', 'operation')
        #unixLines   = mergeDownCommMasks(unixLines)

    if 'signal'  in args.type:
        signalLines = mergeDictsBySingleKey(signalLines, 'signal')

    if 'ptrace'  in args.type:
        ptraceLines = mergeDictsBySingleKey(ptraceLines, 'mask')

    #if 'cap'     in args.type:
    #if 'mount'   in args.type:
    #if 'pivot'   in args.type:
    #if 'unknown' in args.type:

    sortedLines = sortLines(fileLines,   dbusLines,  networkLines,
                            unixLines,   capLines,   signalLines,
                            ptraceLines, mountLines, pivotLines,  unknownLines, args)

    padding        = findPadding(sortedLines)
    colorizedLines = colorizeLines(sortedLines)

    display(colorizedLines, padding, args)
