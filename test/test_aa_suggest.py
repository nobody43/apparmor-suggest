#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-License-Identifier: GPL-3.0-only

import unittest
import copy
from aa_suggest import *

class simpleTests(unittest.TestCase):

    def test_hexToString(self):
        whitespaceHex   = '2F746D702F556E7469746C656420466F6C6465722F7069632E706E67'
        localizedHex    = '2F746D702FD0BAD0B0D0BA2DD0B2D18BD183D187D0B8D182D18C2D6370702DD0B7D0B02D32312DD0B4D0B5D0BDD18C2E706E67'
        unixAddr_nvidia = '@7661722F72756E2F6E76696469612D786472697665722D37313634393538330000000000000000000000000000000000000000000000000000000000000000'

        self.assertIsNotNone(hexToString('/tmp/pic.png'))
        self.assertEqual(hexToString(whitespaceHex),    '/tmp/Untitled Folder/pic.png')
        self.assertEqual(hexToString(localizedHex),     '/tmp/как-выучить-cpp-за-21-день.png')
        self.assertEqual(hexToString(unixAddr_nvidia),  '@var/run/nvidia-xdriver-71649583')
        self.assertEqual(hexToString('/tmp/123.txt'),   '/tmp/123.txt')
        self.assertEqual(hexToString('/00000000'),      '/00000000')
        self.assertEqual(hexToString('5B70616E676F5D204663496E6974'), '[pango] FcInit')
        self.assertEqual(hexToString('/abcdef0'),       '/abcdef0')
        self.assertEqual(hexToString('abcdef0'),        'abcdef0')        # ??
        self.assertEqual(hexToString('ABCDEF00000000'), 'ABCDEF00000000') # ??? TODO
        self.assertNotEqual(hexToString(whitespaceHex), whitespaceHex)

    def test_findTempTailPair(self):
        self.assertEqual(findTempTailPair('file0',              'default'),             (None,         None))
        self.assertEqual(findTempTailPair('file1.T84F32',       'default'),             ('.T84F32',    '{,.??????}'))
        self.assertEqual(findTempTailPair('file2.tmpR7NB38',    'default'),             ('.tmpR7NB38', '{,.tmp??????}'))
        self.assertEqual(findTempTailPair('file3.tmp',          'default'),             ('.tmp',       '{,.tmp}'))
        self.assertEqual(findTempTailPair('file4~',             'default'),             ('~',          '{,~}'))
        self.assertEqual(findTempTailPair('file5.tmp1234',      'default'),             ('.tmp1234',   '{,.tmp????}'))
        self.assertEqual(findTempTailPair('file9.abcxy9',       'default'),             (None,         None))  # nothing for lowercase
        self.assertEqual(findTempTailPair('file5.tmp12345',     'default'),             (None,         None))
        self.assertEqual(findTempTailPair('file5.tmp123',       'default'),             (None,         None))
        self.assertNotEqual(findTempTailPair('file1.T84F32',    'default'),             (None,         None))
        self.assertNotEqual(findTempTailPair('file3~',          'default'),             (None,         None))
        # Rule styles
        self.assertEqual(findTempTailPair('file1.T84F32',       'AppArmor.d'), ('.T84F32',    '{,.@{rand6}}'))
        self.assertEqual(findTempTailPair('file2.tmpR7NB38',    'AppArmor.d'), ('.tmpR7NB38', '{,.tmp@{rand6}}'))
        self.assertEqual(findTempTailPair('file3.tmp',          'AppArmor.d'), ('.tmp',       '{,.tmp}'))
        self.assertEqual(findTempTailPair('file4~',             'AppArmor.d'), ('~',          '{,~}'))
        self.assertEqual(findTempTailPair('file5.tmp1234',      'AppArmor.d'), ('.tmp1234',   '{,.tmp@{int}}'))

    def test_composeFileMask(self):
        redg = '\x1b[7;31m' # background red
        gryg = '\x1b[7;90m' # background grey
        wht  = '\x1b[0;37m' # white
        whtb = '\x1b[1;37m' # bold white
        grn  = '\x1b[0;32m' # regular green
        mgn  = '\x1b[0;35m' # regular magenta
        blu  = '\x1b[0;34m' # regular blue
        rst  = '\x1b[0m'    # reset
        self.assertEqual(composeFileMask({'c', 'w', 'r', 'd'}, None, False), f'rwdc')
        self.assertEqual(composeFileMask({'c', 'w', 'r'},      None, True),  f'r{grn}w{rst}') # adapted to usable
        self.assertEqual(composeFileMask({'c', 'd'},           None, True),  f'{grn}w{rst}')
        self.assertEqual(composeFileMask({'r', 'x', 'm'},      None, False), f'mrx')
        self.assertEqual(composeFileMask({'a', 'r', 'c'},      None, False), f'rac')
        self.assertEqual(composeFileMask({'a', 'w'},           None, False), f'w')            # 'a' and 'w' are mutually exclusive
        self.assertEqual(composeFileMask({'a', 'r', 'c'},      None, True),  f'r{grn}w{rst}') # adapted, exclusive
        self.assertEqual(composeFileMask({'P', 'x', 'r'},      None, False), f'r{whtb}P{rst}x')
        self.assertEqual(composeFileMask({'x', 'U', 'P', 'r'}, None, True),  f'r{whtb}P{rst}Ux')
        self.assertEqual(composeFileMask({'U', 'P', 'x'},      None, False), f'{whtb}r{rst}{whtb}P{rst}Ux')  # accompanied mask; transition suggestion
        self.assertEqual(composeFileMask({'Y', 'H', '9'},      None, False), f'9HY')  # preserved, sorted unknown masks
        self.assertEqual(composeFileMask({'Y', 'r', 'c'},      None, False), f'rcY')  # not adapted, not colorized with unknown mask
        self.assertEqual(composeFileMask({'r', 'Y', 'c'},      None, True),  f'r{grn}w{rst}Y')
        self.assertEqual(composeFileMask({'w', 'r', 'x'},      None, False), f'r{redg}x{rst}{redg}w{rst}') # colorized dangerous combinations
        self.assertEqual(composeFileMask({'r', 'c', 'm'},      None, False), f'{redg}m{rst}r{redg}c{rst}')
        self.assertEqual(composeFileMask({'c', 'r', 'x'},      None, True),  f'r{redg}x{rst}{redg}w{rst}') # adapted dangerous combination, W^X took precedence
        self.assertEqual(composeFileMask({'r', 'x', 'T'},      None, False), f'r{gryg}P{rst}x')  # target not found hinting with 'T'
        self.assertEqual(composeFileMask({'r', 'x', 'T', 'P'}, None, False), f'r{gryg}P{rst}x')  # target not found hinting with 'T'; suggestion consumed
        self.assertNotEqual(composeFileMask({'w', 'r', 'x'},   None, False), f'rxw')  # not highlighted
        self.assertNotEqual(composeFileMask({'w', 'r', 'x'},   None, True),  f'rxw')
        self.assertNotEqual(composeFileMask({'r', 'c', 'm'},   None, False), f'mrc')
        self.assertNotEqual(composeFileMask({'r', 'c', 'm'},   None, True),  f'mrw')
        self.assertNotEqual(composeFileMask({'c', 'r', 'w'},   None, False), f'crw')  # incorrect precedence
        self.assertNotEqual(composeFileMask({'z', 'y', '9'},   None, False), f'zy9')
        self.assertNotEqual(composeFileMask({'r'},             None, False),  {'r'})
        self.assertIsNotNone(composeFileMask({'x', 'm'},       None, False))
        self.assertIsNotNone(composeFileMask({'r'},            None, False))
        self.assertEqual(composeFileMask({'x'},                None, False), f'{whtb}r{rst}x')  # accompanied read
        self.assertEqual(composeFileMask({'w', 'c'},           None, False), f'wc')             # not adapted
        self.assertEqual(composeFileMask({'w', 'c'},           None, True),  f'{grn}w{rst}')    #     adapted
        self.assertEqual(composeFileMask({'r', 'x'},           None, False), f'rx')
        self.assertEqual(composeFileMask({'r', ':', 'x'},      None, True),  f'rx')
        self.assertEqual(composeFileMask({'r', ':', 'x'},      None, False), f'rx')
        self.assertEqual(composeFileMask({'k', 'm', 'r', 'x', 'w', 'a', 'd', 'c', 'l'}, None, False), f'{redg}m{rst}r{redg}x{rst}{redg}w{rst}{redg}d{rst}{redg}c{rst}{redg}l{rst}{redg}k{rst}')  # all possible
        self.assertEqual(composeFileMask({'k', 'm', 'r', 'x', 'w', 'a', 'd', 'c', 'l'}, None, True),  f'{redg}m{rst}r{redg}x{rst}{redg}w{rst}{redg}l{rst}{redg}k{rst}')  # all possible, adaption consumed by W^X
        # Automatic transitions
        self.assertEqual(composeFileMask({'w', 'c'},     {'w', 'c'}, True),  f'{grn}w{rst}')               # transition consumed by adaption
        self.assertEqual(composeFileMask({'m', 'r'},     {'m', 'r'}, True),  f'{blu}m{rst}{blu}r{rst}')    # mask and transition mask are the same with adapted flag
        self.assertEqual(composeFileMask({'m', 'r'},     {'r', 'm'}, False), f'{blu}m{rst}{blu}r{rst}')    # same but different precedence without adapted flag
        self.assertEqual(composeFileMask({'m', 'c'},     {'m', 'c'}, True),  f'{redg}m{rst}{redg}w{rst}')  # adapted, W^X took precedence
        self.assertEqual(composeFileMask({'m', 'c'},     {'m', 'c'}, False), f'{redg}m{rst}{redg}c{rst}')  # not adapted, W^X took precedence
        self.assertEqual(composeFileMask({'w', 'c'},     {'w', 'c'}, False), f'{blu}w{rst}{blu}c{rst}')
        self.assertEqual(composeFileMask({'r', 'x', 'i'},     {'r'}, False), f'{blu}r{rst}{whtb}i{rst}x')  # hinting with 'i' as ix candidate
        self.assertEqual(composeFileMask({'r', 'x'},          {'x'}, False), f'r{blu}x{rst}')              # not ix
        self.assertEqual(composeFileMask({'k', 'm', 'r', 'i', 'x', 'w', 'a', 'd', 'c', 'l'}, {'k', 'm', 'r', 'i', 'x', 'w', 'a', 'd', 'c', 'l'}, False), f'{redg}m{rst}{blu}r{rst}{whtb}i{rst}{redg}x{rst}{redg}w{rst}{redg}d{rst}{redg}c{rst}{redg}l{rst}{redg}k{rst}')  # all possible, transition
        self.assertEqual(composeFileMask({'k', 'm', 'r', 'i', 'x', 'w', 'a', 'd', 'c', 'l'}, {'k', 'm', 'r', 'i', 'x', 'w', 'a', 'd', 'c', 'l'}, True),  f'{redg}m{rst}{blu}r{rst}{whtb}i{rst}{redg}x{rst}{redg}w{rst}{redg}l{rst}{redg}k{rst}')  # all possible, adapted, transition
        self.assertEqual(composeFileMask({'k', 'm', 'r', 'i', 'x', 'w', 'a', 'd', 'c', 'l'}, {'m', 'i', 'x', 'w', 'a', 'd', 'c', 'l'}, True),            f'{redg}m{rst}r{whtb}i{rst}{redg}x{rst}{redg}w{rst}{redg}l{rst}{redg}k{rst}')  # almost all possible, adapted, transition

    def test_isRequestedProfile(self):     # Current profile [line]     # Requested profile(s)
        self.assertTrue(isRequestedProfile( 'dconf',                    []))  # all
        self.assertTrue(isRequestedProfile( 'dconf',                    ['*']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['dconf']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['dconf*']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['*dconf']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['dconf', 'xrdb']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['xrdb', 'dconf']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['d*']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['*f']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['d*f']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['xrdb', 'd*f']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['xrdb', 'dconf', 'synth']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['xrdb', 'd*f', 'd*']))
        self.assertTrue(isRequestedProfile( 'dconf',                    ['xrdb', 'd*', 'synth']))
        self.assertFalse(isRequestedProfile('dconf',                    ['xrdb']))
        self.assertFalse(isRequestedProfile('dconf',                    ['xrdb', 'synth']))
        self.assertFalse(isRequestedProfile('dconf',                    ['dconfd*']))
        self.assertFalse(isRequestedProfile('dconf',                    ['xrdb', '*d']))
        self.assertFalse(isRequestedProfile(None,                       ['dconf']))  # no 'profile_peer' key
        self.assertTrue(isRequestedProfile( None,                       []))         # all
        self.assertTrue(isRequestedProfile( 'run-parts',                ['run-parts']))
        self.assertTrue(isRequestedProfile( 'run-parts',                ['run-parts*']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd',          ['run-parts//*']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd',          ['run-parts//motd']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc',       ['run-parts']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc',       ['run-parts*']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc',       ['run-parts//motd*']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc',       ['run-parts//motd▶wc']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc▶synth', []))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc▶synth', ['run-parts']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc▶synth', ['run-parts*']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc▶synth', ['run-parts//motd▶wc▶synth']))
        self.assertTrue(isRequestedProfile( 'run-parts▶/sbin/synth',    ['run-parts']))
        self.assertTrue(isRequestedProfile( 'run-parts▶/sbin/synth',    ['run-parts*']))
        self.assertTrue(isRequestedProfile( 'synth-parts//motd',        ['*motd']))
        self.assertTrue(isRequestedProfile( 'wc▶synth',                 ['*synth']))
        self.assertTrue(isRequestedProfile( 'wc▶synth',                 ['wc']))
        self.assertTrue(isRequestedProfile( 'wc▶synth',                 ['wc*']))
#        self.assertTrue(isRequestedProfile( 'wc▶synth',                 ['*wc']))
        self.assertFalse(isRequestedProfile('run-parts',                ['run-parts//motd']))
        self.assertFalse(isRequestedProfile('run-parts',                ['run-parts//motd*']))
        self.assertFalse(isRequestedProfile('run-parts//motd',          ['run-parts//motd▶wc']))
        self.assertFalse(isRequestedProfile('run-parts//motd▶wc',       ['run-parts//motd▶wc▶synth']))
        self.assertFalse(isRequestedProfile('run-parts',                ['run-parts//motd▶wc▶synth']))
        self.assertFalse(isRequestedProfile('run-parts',                ['run-parts//motd▶wc*']))

        self.assertTrue(isRequestedProfile( 'run-parts',                ['synth', 'run-parts', 'wc']))
        self.assertTrue(isRequestedProfile( 'run-parts//motd',          ['synth', 'run-parts', 'wc']))
        self.assertTrue(isRequestedProfile( 'run-parts▶synth',          ['thnys', 'run-parts', 'wc']))
        self.assertTrue(isRequestedProfile( 'run-parts',                ['synth', 'ru*arts', 'wc']))
#        self.assertTrue(isRequestedProfile( 'run-parts//motd▶wc',       ['synth', 'ru*arts', 'wc']))
#        self.assertTrue(isRequestedProfile( 'run-parts▶synth',          ['thnys', 'ru*arts', 'wc']))
#        self.assertTrue(isRequestedProfile( 'run-parts//motd',          ['synth', 'ru*arts', 'wc']))
        self.assertFalse(isRequestedProfile('run-parts//motd▶wc▶synth', ['synth*', '*wc']))
        self.assertRaises(NotImplementedError, isRequestedProfile, 'dconf', ['d*o*f'])
        self.assertRaises(NotImplementedError, isRequestedProfile, 'dconf', ['d*o*f', 'synth'])
        self.assertRaises(NotImplementedError, isRequestedProfile, 'dconf', ['synth', 'd*o*f'])

    def test_isRequestedOperation(self):     # Current operation(s)                       # Requested operations(s), synthetic
        self.assertTrue(isRequestedOperation({'dbus_bind', 'dbus_send', 'dbus_receive'},  ['dbus_bind', 'open']))
        self.assertTrue(isRequestedOperation({'dbus_send', 'dbus_bind', 'dbus_receive'},  ['dbus_bind', 'open']))
        self.assertTrue(isRequestedOperation({'dbus_bind', 'dbus_send', 'dbus_receive'},  ['open', 'dbus_bind']))
        self.assertTrue(isRequestedOperation({'dbus_send', 'dbus_bind', 'dbus_receive'},  ['open', 'dbus_bind']))
        self.assertTrue(isRequestedOperation({'dbus_receive', 'dbus_bind', 'dbus_send'},  ['mknod', 'dbus_bind', 'open']))
        self.assertTrue(isRequestedOperation({'dbus_receive', 'dbus_bind', 'dbus_send'},  ['dbus_send', 'dbus_bind', 'open']))
        self.assertFalse(isRequestedOperation({'dbus_receive', 'dbus_bind', 'dbus_send'}, ['open']))
        self.assertFalse(isRequestedOperation({'dbus_receive', 'dbus_bind'},              ['dbus_send', 'open']))
        self.assertFalse(isRequestedOperation({'dbus_receive', 'dbus_bind'},              ['open', 'dbus_send']))
        self.assertRaises(NotImplementedError, isRequestedOperation, {'dbus_bind'}, ['dbus*'])
        self.assertRaises(NotImplementedError, isRequestedOperation, {'dbus_bind'}, ['open', 'dbus*'])
        self.assertRaises(NotImplementedError, isRequestedOperation, {'dbus_bind'}, ['dbus*', 'open'])

    def test_makeHashable(self):
        self.assertEqual(makeHashable({'path': '@{run}/user/@{uid}/doc/', 'comm': {'synth1', 'synth2'}, 'path_diffs': [[(0, 6), '/run'], [(12, 18), '0']]}),
                                       "[('comm', ['synth1', 'synth2']), ('path', '@{run}/user/@{uid}/doc/'), ('path_diffs', [[(0, 6), '/run'], [(12, 18), '0']])]")
        self.assertEqual(makeHashable({'path': '@{run}/user/@{uid}/doc/', 'comm': {'synth2', 'synth1'}, 'path_diffs': [[(0, 6), '/run'], [(12, 18), '0']]}),
                                       "[('comm', ['synth1', 'synth2']), ('path', '@{run}/user/@{uid}/doc/'), ('path_diffs', [[(0, 6), '/run'], [(12, 18), '0']])]")
        self.assertEqual(makeHashable({'path': '/tmp/synth', 'subdict': {'synth1': 'val1', 'synth2': 'val2'}}),
                                       "[('path', '/tmp/synth'), ('subdict', [('synth1', 'val1'), ('synth2', 'val2')])]")
        self.assertEqual(makeHashable({'path': '/tmp/synth', 'subdict': {'synth2': 'val2', 'synth1': 'val1'}, 'comm': {'synth2', 'synth1'}}),
                                       "[('comm', ['synth1', 'synth2']), ('path', '/tmp/synth'), ('subdict', [('synth1', 'val1'), ('synth2', 'val2')])]")
        self.assertEqual(makeHashable({'path': '/tmp/synth', 'subdict': {'synth2': '2', 'synth1': '1'}, 'comm': {'2', '1'}}),
                                       "[('comm', ['1', '2']), ('path', '/tmp/synth'), ('subdict', [('synth1', '1'), ('synth2', '2')])]")
        self.assertEqual(makeHashable({'path': '/tmp/synth', 'subdict': {'synth2': 2, 'synth1': 1}, 'comm': {2, 1}}),
                                       "[('comm', [1, 2]), ('path', '/tmp/synth'), ('subdict', [('synth1', 1), ('synth2', 2)])]")
        self.assertNotEqual(makeHashable({'path': '/tmp/synth', 'comm': {'synth2', 'synth1'}}),
                                       "[('comm', ['synth2', 'synth1']), ('path', '/tmp/synth')]")
        self.assertNotEqual(makeHashable({'path': '/tmp/synth', 'subdict': {'synth2': 'val2', 'synth1': 'val1'}}),
                                       "[('path', '/tmp/synth'), ('subdict', [('synth2', 'val2'), ('synth1', 'val1')])]")
        self.assertNotEqual(makeHashable({'path': '/tmp/synth', 'subdict': {'synth2': '2', 'synth1': '1'}, 'comm': {'2', '1'}}),
                                       "[('comm', ['2', '1']), ('path', '/tmp/synth'), ('subdict', [('synth2', '2'), ('synth1', '1')])]")
        self.assertNotEqual(makeHashable({'path': '/tmp/synth', 'subdict': {'synth2': 2, 'synth1': 1}, 'comm': {2, 1}}),
                                       "[('comm', [2, 1]), ('path', '/tmp/synth'), ('subdict', [('synth2', 2), ('synth1', 1)])]")
        self.assertRaises(ValueError, makeHashable, {'path': '@{run}/user/@{uid}/doc/', 'comm': {'synth1', 'synth2'}, 'path_diffs': [[(0, 6), '/run'], [(12, 18), '0']], 'timestamp': 1})

    def test_isTransitionComm(self):
        blu  = '\x1b[0;34m'
        rst  = '\x1b[0m'
        self.assertTrue(isTransitionComm({f'{blu}synth{rst}'}))
        self.assertFalse(isTransitionComm({'synth'}))
        self.assertFalse(isTransitionComm({     'one',      'two',      'three'}))
        self.assertTrue(isTransitionComm({f'{blu}one{rst}', 'two',      'three'}))
        self.assertTrue(isTransitionComm({      'one',f'{blu}two{rst}', 'three'}))
        self.assertTrue(isTransitionComm({      'one',      'two',f'{blu}three{rst}'}))

    def test_adaptProfileAutoTransitions(self):
        blu  = '\x1b[0;34m'
        rst  = '\x1b[0m'
        line_pairs = (
   (
{'operation': 'file_inherit', 'name': '/dev/null',  'comm':       'test',      'requested_mask': 'w',  'profile': 'apt▶test'},
{'operation': 'file_inherit', 'name': '/dev/null',  'comm': f'{blu}test{rst}', 'requested_mask': 'w',  'profile': 'apt'}  # transition
), (
{'operation': 'exec',      'name': '/usr/bin/echo', 'comm': 'sh',              'requested_mask': 'x',  'profile': 'apt'},
{'operation': 'exec',      'name': '/usr/bin/echo', 'comm': 'sh',              'requested_mask': 'x',  'profile': 'apt'}  # not a transition
), (
{'operation': 'file_mmap', 'name': '/usr/bin/test', 'comm':       'test',      'requested_mask': 'r',  'profile': 'apt▶test'},
{'operation': 'file_mmap', 'name': '/usr/bin/test', 'comm': f'{blu}test{rst}', 'requested_mask': 'ri', 'profile': 'apt'}  # ix candidate
), (
{'operation': 'file_mmap', 'name': '/bin/test',     'comm':       'test',      'requested_mask': 'r',  'profile': 'apt▶test'},
{'operation': 'file_mmap', 'name': '/bin/test',     'comm': f'{blu}test{rst}', 'requested_mask': 'ri', 'profile': 'apt'}  # different path
), (
{'operation': 'file_mmap', 'name': '/usr/local/bin/test', 'comm':       'test',      'requested_mask': 'r', 'profile': 'apt▶test'},
{'operation': 'file_mmap', 'name': '/usr/local/bin/test', 'comm': f'{blu}test{rst}', 'requested_mask': 'r', 'profile': 'apt'}  # transition, possible ix candidate, but wrong path
), (
{'operation': 'file_mmap', 'name': '/usr/bin/dash', 'comm': 'im-launch',       'requested_mask': 'r', 'profile': 'gnome-session-binary▶im-launch'},
{'operation': 'file_mmap', 'name': '/usr/bin/dash', 'comm': 'im-launch',       'requested_mask': 'r', 'profile': 'gnome-session-binary▶im-launch'}  # transition, but not an ix candidate
), (
{'operation': 'file_inherit', 'name': '/var/lib/unattended-upgrades/kept-back', 'comm':       'wc',      'requested_mask': 'r', 'timestamp': 1712748312919872, 'trust': 10, 'profile': 'run-parts//motd▶wc'},
{'operation': 'file_inherit', 'name': '/var/lib/unattended-upgrades/kept-back', 'comm': f'{blu}wc{rst}', 'requested_mask': 'r', 'timestamp': 1712748312919872, 'trust': 10, 'profile': 'run-parts//motd'}
),
        )
        for inpt,result in line_pairs:
            self.assertEqual(adaptProfileAutoTransitions(inpt), result)

    def test_findExecType(self):
        self.assertEqual(findExecType('echo'),          'i')
        self.assertEqual(findExecType('awk'),           'i')
        self.assertEqual(findExecType('grep'),          'i')
        self.assertEqual(findExecType('sort'),          'i')
        self.assertEqual(findExecType('ps'),            'P')
        self.assertEqual(findExecType('spice-vdagent'), 'P')
        self.assertIsNone(findExecType('nonexistent'))

    def test_getBaseBin(self):
        grn  = '\x1b[0;32m' # regular green
        rst  = '\x1b[0m'
        self.assertEqual(getBaseBin('/usr/bin/echo'), 'echo')
        self.assertEqual(getBaseBin('/bin/echo'),     'echo')
        self.assertEqual(getBaseBin(f'/{grn}{{,usr/}}{rst}bin/echo'), 'echo')
        self.assertEqual(getBaseBin(f'/{grn}{{usr/,}}{rst}bin/echo'), 'echo')
        self.assertEqual(getBaseBin(f'{grn}@{{bin}}{rst}/echo'),      'echo')
        self.assertIsNone(getBaseBin('/usr/sbin/echo'))
        self.assertIsNone(getBaseBin('/sbin/echo'))
        self.assertIsNone(getBaseBin('/usr/bin/dir/echo'))
        self.assertIsNone(getBaseBin('/usr/local/bin/echo'))
        self.assertIsNone(getBaseBin('/opt/bin/echo'))

class colorizationTests(unittest.TestCase):

    def test_updatePostcolorizationDiffs(self):
        postcolorizationDiffs = (
(({'addr': '@/tmp/dbus-????????'}, (11, 19), 'l49GNGRo', 'addr'), {'addr': '@/tmp/dbus-????????', 'addr_diffs': [[(11, 19), 'l49GNGRo']]}),  # single replacement
(({'path': '/run/user/@{uid}/at-spi/bus'},                                       (10, 16), '1000', 'path'), {'path': '/run/user/@{uid}/at-spi/bus',   'path_diffs': [[(10, 16), '1000']]}),
(({'path': '@{run}/user/@{uid}/at-spi/bus', 'path_diffs': [[(10, 16), '1000']]}, (0, 6),   '/run', 'path'), {'path': '@{run}/user/@{uid}/at-spi/bus', 'path_diffs': [[(0, 6), '/run'], [(12, 18), '1000']]}),  # diffs in input with differently-sized replacement - shift had happened in the result
((  {'path': '@{user_config_dirs}/ibus/bus/@{hex32}-unix{,-wayland}-@{int}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(66, 77), '-wayland'], [(78, 84), '0']]}, (29, 35), 'e561af98c3584a29a4eab8a761aceaf9', 'path'),
    {'path': '@{user_config_dirs}/ibus/bus/@{hex32}-unix{,-wayland}-@{int}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(29, 35), 'e561af98c3584a29a4eab8a761aceaf9'], [(40, 51), '-wayland'], [(52, 58), '0']]}),  # item was inserted in the middle and all items to the right were shifted
(({'target': '/usr/lib/xorg/Xorg', 'path': '@{lib}/xorg/Xorg'}, (0, 6), '/usr/lib', 'path'), {'target': '/usr/lib/xorg/Xorg', 'path': '@{lib}/xorg/Xorg', 'path_diffs': [[(0, 6), '/usr/lib']]}),  # multiple eligible keys - neighbor entity must NOT be affected
(({'path': '/etc/gdm{,3}/custom.conf'},    (8, 12),  '',       'path'), {'path': '/etc/gdm{,3}/custom.conf',    'path_diffs': [[(8, 12),  '']]}),  # empty capturing group
(({'path': '/etc/gdm/custom.conf.??????'}, (22, 28), 'aBcXy9', 'path'), {'path': '/etc/gdm/custom.conf.??????', 'path_diffs': [[(22, 28), 'aBcXy9']]}),  # temp tail first
(({'path': '/etc/gdm{,3}/custom.conf.??????', 'path_diffs': [[(22, 28), 'aBcXy9']]}, (8, 12), '', 'path'), {'path': '/etc/gdm{,3}/custom.conf.??????', 'path_diffs': [[(8, 12), ''], [(26, 32), 'aBcXy9']]}),  # another replacement to the left before right one
        )
        for i,r in postcolorizationDiffs:
            self.assertEqual(updatePostcolorizationDiffs(i[0], i[1], i[2], i[3]), r)

    def test_highlightWords(self):
        '''"/" means regular directory, not necessary root directory'''
        red = '\x1b[0;31m'
        ylw = '\x1b[0;33m'
        rst = '\x1b[0m'
        num_ = '[0-9]{,[0-9]}'
        int_ = '@{int}'
        pathsAndResults = (
# Sensitive
('/proc/0/', f'/proc/{red}0{rst}/'),
('/proc/1/', f'/proc/{red}1{rst}/'),
('@{PROC}/1/', f'@{{PROC}}/{red}1{rst}/'),
('@{PROC}/2/', f'@{{PROC}}/2/'),
('/proc/1/cmdline', f'/proc/{red}1{rst}/cmdline'),
('/proc/1234/cmdline', f'/proc/1234/{red}cmdline{rst}'),
('/proc/cmdline', f'/proc/{red}cmdline{rst}'),
('@{PROC}/@{pid}/cmdline', f'@{{PROC}}/@{{pid}}/{red}cmdline{rst}'),
('@{PROC}/cmdline', f'@{{PROC}}/{red}cmdline{rst}'),
('/dir/proc/1/', '/dir/proc/1/'),
('/.ssh/id_rsa',         f'/.ssh/{red}id_rsa{rst}'),
('/.ssh/id_rsa.pub',     f'/.ssh/id_rsa.pub'),
('/.ssh/id_rsa_custom',  f'/.ssh/{red}id_rsa_custom{rst}'),
('/.ssh/id_ed25519.pub', f'/.ssh/id_ed25519.pub'),
('/.ssh/id_dsa',         f'/.ssh/{red}id_dsa{rst}'),
('/.ssh/id_ecdsa',       f'/.ssh/{red}id_ecdsa{rst}'),
('/.ssh/id_ecdsa-sk',    f'/.ssh/{red}id_ecdsa-sk{rst}'),
('/.ssh/id_ed25519',     f'/.ssh/{red}id_ed25519{rst}'),
('/.ssh/id_ed25519-sk',  f'/.ssh/{red}id_ed25519-sk{rst}'),
('/ssh_host_dsa_key',       f'/{red}ssh_host_dsa_{red}key{rst}{rst}'),
('/ssh_host_rsa_key',       f'/{red}ssh_host_rsa_{red}key{rst}{rst}'),
('/ssh_host_ecdsa_key',     f'/{red}ssh_host_ecdsa_{red}key{rst}{rst}'),
('/ssh_host_ed25519_key',   f'/{red}ssh_host_ed25519_{red}key{rst}{rst}'),
('/ssh_host_rsa_key.pub',            f'/ssh_host_rsa_key.pub'),
('/ssh_host_rsa_cus.tom_key.pub',     '/ssh_host_rsa_cus.tom_key.pub'),
('/ssh_host_rsa_cus.tom_key',        f'/{red}ssh_host_rsa_cus.tom_{red}key{rst}{rst}'),
('/ssh_host_ed25519_key_custom',     f'/{red}ssh_host_ed25519_{red}key{rst}_{rst}custom'),
('0', f'{red}0{rst}'),
('/0', f'/{red}0{rst}'),
('/0/', f'/{red}0{rst}/'),
('0/', f'{red}0{rst}/'),
('10', '10'),
('01', '01'),
('000', '000'),
('101', '101'),
('/arphic-bkai00mp/', '/arphic-bkai00mp/'),
('cookies', 'cookies'),
('cookies.sqlite', f'{red}cookies{rst}.sqlite'),
('cookies.sqlite-wal', f'{red}cookies{rst}.sqlite-wal'),
('/creds.txt', f'/{red}cred{rst}s.txt'),
('credence', 'credence'),
('sacred', 'sacred'),
('accredited', 'accredited'),
('hotkey', 'hotkey'),
('keypass', f'{red}key{rst}{red}pass{rst}'),
('keygen', 'keygen'),
('passkey', f'{red}pass{rst}{red}key{rst}'),
('/etc/shadow', f'/etc/{red}shadow{rst}'),
('shadows', 'shadows'),
('foreshadowing', 'foreshadowing'),
('shadowcoord', 'shadowcoord'),
('shadowmap', 'shadowmap'),
('/pass.txt', f'/{red}pass{rst}.txt'),
('/usr/share/pass.txt', f'/usr/share/pass.txt'),
('/etc/usr/share/pass.txt', f'/etc/usr/share/{red}pass{rst}.txt'),
('passage', 'passage'),
('compass', 'compass'),
('Private', f'{red}Priv{rst}ate'),
('/System.Private.CoreLib.dll', '/System.Private.CoreLib.dll'),
('privatise', 'privatise'),
('nonprivate', 'nonprivate'),
('secret.txt', f'{red}secret{rst}.txt'),
('nonsecret', 'nonsecret'),
('secretary', 'secretary'),
('/ISRG_Root_X1.crt', '/ISRG_Root_X1.crt'),
('/root/', f'/{red}root{rst}/'),
('roots', 'roots'),
('chroot', 'chroot'),
('fakeroot', 'fakeroot'),
('/site.key', f'/site.{red}key{rst}'),
('keyboard', 'keyboard'),
('turkey', 'turkey'),
#('rooturkey', f'{red}root{rst}ur{red}key{rst}'),  # masking injection attempt; TODO
('/turkey/site.key', f'/turkey/site.{red}key{rst}'),  # one assertion and one substitution
# Volatile
('/.mozilla/firefox/wjdycmdr.default', f'/.mozilla/firefox/{ylw}wjdycmdr{rst}.default'),
('/#123', f'/#{ylw}123{rst}'),
('/usr/share/#123', f'/usr/share/#123'),
('/#123abc', f'/#123abc'),
('aBcXy9', 'aBcXy9'),  # isolated
('-aBcXy9XXZ', '-aBcXy9XXZ'),  # dirty overlap; unreliable
('-AbcXyz', f'-{ylw}AbcXyz{rst}'),
('-AbcXyz/', f'-{ylw}AbcXyz{rst}/'),
('-aBcXy90', '-aBcXy90'),
('/123-AbcXyz', f'/123-{ylw}AbcXyz{rst}'),
('.aBcXy9/', f'.{ylw}aBcXy9{rst}/'),
('-123789', '-123789'),
('/123.abcxyz', '/123.abcxyz'),
('-ABCXYZ', '-ABCXYZ'),
('.ABCXYZ', '.ABCXYZ'),
('-ABCXY9', f'-{ylw}ABCXY9{rst}'),
('.ABCXY9', f'.{ylw}ABCXY9{rst}'),
('.Abcxyz', '.Abcxyz'),
('-Abcxy1', '-Abcxy1'),
('-errors', '-errors'),
('123.daemon/', '123.daemon/'),
('.Daemon', '.Daemon'),
('.Socket', '.Socket'),
('.network1', '.network1'),
('-abcxy9', f'-abcxy9'),
('.ABCXY9', f'.{ylw}ABCXY9{rst}'),
('-aBcDwXy9', f'-{ylw}aBcDwXy9{rst}'),
('.AbcdWxyz', f'.{ylw}AbcdWxyz{rst}'),
('-abcdwxy9', f'-abcdwxy9'),
('.12346789/', '.12346789/'),
('/123-abcdwxyz', '/123-abcdwxyz'),
('/123.ABCDWXYZ/', '/123.ABCDWXYZ/'),
('-Abcdwxyz/', '-Abcdwxyz/'),
('.Factory1', '.Factory1'),
('-base35', '-base35'),
('.aBcDeVwXy9', f'.{ylw}aBcDeVwXy9{rst}'),
('.AbcdeVwxyz', f'.{ylw}AbcdeVwxyz{rst}'),
('-abcdevwxy9', f'-{ylw}abcdevwxy9{rst}'),
('/usr/share/123-abcdevwxy9', f'/usr/share/123-abcdevwxy9'),
('/etc/usr/share/123-abcdevwxy9', f'/etc/usr/share/123-{ylw}abcdevwxy9{rst}'),
('.1234567890', '.1234567890'),
('.abcdevwxyz', '.abcdevwxyz'),
('.ABCDEVWXYZ', '.ABCDEVWXYZ'),
('.Abcdevwxyz/', '.Abcdevwxyz/'),
('-Abcdevwxy1', '-Abcdevwxy1'),
('.PackageKit', '.PackageKit'),
('.PolicyKit1', '.PolicyKit1'),
('.GeoClue2', '.GeoClue2'),
('.login1', '.login1'),
('Mutter/IdleMonitor', 'Mutter/IdleMonitor'),
('/.#lk0x00005578fbd925d0.', f'/.#lk0x{ylw}00005578fbd925d0{rst}.'),
('d8e8fca2dc0f896fd7cb4cb0031ba249', 'd8e8fca2dc0f896fd7cb4cb0031ba249'),
('.d8e8fca2dc0f896fd7cb4cb0031ba249/', f'.{ylw}d8e8fca2dc0f896fd7cb4cb0031ba249{rst}/'),
('@d8e8fca2dc0f896fd7cb4cb0031ba249-', f'@{ylw}d8e8fca2dc0f896fd7cb4cb0031ba249{rst}-'),
('-D8E8FCA2DC0F896FD7CB4CB0031BA249/', f'-{ylw}D8E8FCA2DC0F896FD7CB4CB0031BA249{rst}/'),
('/D8E8FCA2DC0F896FD7CB4CB0031BA249', f'/{ylw}D8E8FCA2DC0F896FD7CB4CB0031BA249{rst}'),
('WD8E8FCA2DC0F896FD7CB4CB0031BA249X', f'W{ylw}D8E8FCA2DC0F896FD7CB4CB0031BA249{rst}X'),
('52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec', '52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec'),
('/52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec', f'/{ylw}52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec{rst}'),
('/52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec-', f'/{ylw}52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec{rst}-'),
('.52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec/', f'.{ylw}52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec{rst}/'),
('f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2', 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2'),
('/f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2', f'/{ylw}f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2{rst}'),
('-f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2X', f'-{ylw}f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2{rst}X'),
('.F2CA1BB6C7E907D06DAFE4687E579FCE76B37E4E93B7605022DA52E6CCC26FD2X', f'.{ylw}F2CA1BB6C7E907D06DAFE4687E579FCE76B37E4E93B7605022DA52E6CCC26FD2{rst}X'),
('109bb6b5b6d5547c1ce03c7a8bd7d8f80c1cb0957f50c4f7fda04692079917e4f9cad52b878f3d8234e1a170b154b72d', '109bb6b5b6d5547c1ce03c7a8bd7d8f80c1cb0957f50c4f7fda04692079917e4f9cad52b878f3d8234e1a170b154b72d'),
('/109bb6b5b6d5547c1ce03c7a8bd7d8f80c1cb0957f50c4f7fda04692079917e4f9cad52b878f3d8234e1a170b154b72dx', f'/{ylw}109bb6b5b6d5547c1ce03c7a8bd7d8f80c1cb0957f50c4f7fda04692079917e4f9cad52b878f3d8234e1a170b154b72d{rst}x'),
('-109bb6b5b6d5547c1ce03c7a8bd7d8f80c1cb0957f50c4f7fda04692079917e4f9cad52b878f3d8234e1a170b154b72d/', f'-{ylw}109bb6b5b6d5547c1ce03c7a8bd7d8f80c1cb0957f50c4f7fda04692079917e4f9cad52b878f3d8234e1a170b154b72d{rst}/'),
('0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123', '0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123'),
('/0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123x', f'/{ylw}0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123{rst}x'),
('W0E3E75234ABC68F4378A86B3F4B32A198BA301845B0CD6E50106E874345700CC6663A86C1EA125DC5E92BE17C98F9A0F85CA9D5F595DB2012F7CC3571945C123X', f'W{ylw}0E3E75234ABC68F4378A86B3F4B32A198BA301845B0CD6E50106E874345700CC6663A86C1EA125DC5E92BE17C98F9A0F85CA9D5F595DB2012F7CC3571945C123{rst}X'),
('-0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123', f'-{ylw}0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123{rst}'),
('/0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123/', f'/{ylw}0e3e75234abc68f4378a86b3f4b32a198ba301845b0cd6e50106e874345700cc6663a86c1ea125dc5e92be17c98f9a0f85ca9d5f595db2012f7cc3571945c123{rst}/'),
('593f03b6-656f-4c28-9be8-2153364750ca', '593f03b6-656f-4c28-9be8-2153364750ca'),
('/593f03b6-656f-4c28-9be8-2153364750ca', f'/{ylw}593f03b6-656f-4c28-9be8-2153364750ca{rst}'),
('W593F03B6-656F-4C28-9BE8-2153364750CAX', f'W{ylw}593F03B6-656F-4C28-9BE8-2153364750CA{rst}X'),
('-593f03b6-656f-4c28-9be8-2153364750cax', f'-{ylw}593f03b6-656f-4c28-9be8-2153364750ca{rst}x'),
('/234623d5318541e098cf2f33abc9a01e0e1269', f'/{ylw}234623d5318541e098cf2f33abc9a01e0e1269{rst}'),
('/234623d5318541e098cf2f33abc9a01e0e1269{,.tmp}', f'/{ylw}234623d5318541e098cf2f33abc9a01e0e1269{rst}{{,.tmp}}'),
('/home/user/', f'/home/{ylw}user{rst}/'),
('@/home/user/', f'@/home/{ylw}user{rst}/'),
# Mixed
('/secret/secret.txt', f'/{red}secret{rst}/{red}secret{rst}.txt'),
('/root/pass.key1', f'/{red}root{rst}/{red}pass{rst}.{red}key{rst}1'),
('/private/593f03b6-656f-4c28-9be8-2153364750ca/123-AbcXy9' , f'/{red}priv{rst}ate/{ylw}593f03b6-656f-4c28-9be8-2153364750ca{rst}/123-{ylw}AbcXy9{rst}'),
('/creds/593f03b6-656f-4c28-9be8-2153364750ca/123-errors' , f'/{red}cred{rst}s/{ylw}593f03b6-656f-4c28-9be8-2153364750ca{rst}/123-errors'),
('wd8e8fca2dc0f896fd7cb4cb0031ba249x-52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec', f'w{ylw}d8e8fca2dc0f896fd7cb4cb0031ba249{rst}x-{ylw}52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec{rst}'),
('/d8e8fca2dc0f896fd7cb4cb0031ba249/52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec/', f'/{ylw}d8e8fca2dc0f896fd7cb4cb0031ba249{rst}/{ylw}52f1bf093f4b7588726035c176c0cdb4376cfea53819f1395ac9e6ec{rst}/'),
('/chroot/root/site.key-AbcXyz', f'/chroot/{red}root{rst}/site.{red}key{rst}-{ylw}AbcXyz{rst}'),
('/gvfs-metadata/root-6478f559.log', f'/gvfs-metadata/{red}root{rst}-{ylw}6478f559{rst}.log'),
# Multiple
('/keys/creds/cred.key', f'/{red}key{rst}s/{red}cred{rst}s/{red}cred{rst}.{red}key{rst}'),
('@a0d3d01e32484f6b92ad0327b593962b-a0d3d01e32484f6b92ad0327b593962b', f'@{ylw}a0d3d01e32484f6b92ad0327b593962b{rst}-{ylw}a0d3d01e32484f6b92ad0327b593962b{rst}'),  # two of the same
('/0852a2ae-4809-4ea5-8d48-7e666d21a5f5/0852a2ae-4809-4ea5-8d48-7e666d21a5f5', f'/{ylw}0852a2ae-4809-4ea5-8d48-7e666d21a5f5{rst}/{ylw}0852a2ae-4809-4ea5-8d48-7e666d21a5f5{rst}'),
('/e561af98c3584a29a4eab8a761aceaf9/a0d3d01e32484f6b92ad0327b593962b/' , f'/{ylw}e561af98c3584a29a4eab8a761aceaf9{rst}/{ylw}a0d3d01e32484f6b92ad0327b593962b{rst}/'),  # same regex, different values (overlapping)
('/df935541-42fe-44ef-b37a-59af947d2f8b3956e4f515ab190c84e8', f'/df935541-42fe-44ef-b37a-{ylw}59af947d2f8b3956e4f515ab190c84e8{rst}'),  # consuming overlap
('-0327a5b9f676b500327a5b9f676b50542f4d2a58f766a19542f', '-0327a5b9f676b500327a5b9f676b50542f4d2a58f766a19542f'),  # incorrect
('screen/ccdda718_5099_4509_a984_05540a913901', f'screen/{ylw}ccdda718_5099_4509_a984_05540a913901{rst}'),
('/var/log/journal/e561af98c3584a29a4eab8a761aceaf9/a0d3d01e32484f6b92ad0327b593962b-000000000000d3fc-0005f87685c0290f.journal' , f'/var/log/journal/{ylw}e561af98c3584a29a4eab8a761aceaf9{rst}/{ylw}a0d3d01e32484f6b92ad0327b593962b{rst}-000000000000d3fc-0005f87685c0290f.journal'),
('/python3/dist-packages/dateutil/__pycache__/',    f'/python3/dist-packages/{ylw}dateutil{rst}/__pycache__/'),
('/python3.10/dist-packages/dateutil/__pycache__/', f'/python3.10/dist-packages/{ylw}dateutil{rst}/__pycache__/'),
(f'/python3.{num_}/dist-packages/dateutil/__pycache__/', f'/python3.{num_}/dist-packages/{ylw}dateutil{rst}/__pycache__/'),
(f'/python3.{int_}/dist-packages/dateutil/__pycache__/', f'/python3.{int_}/dist-packages/{ylw}dateutil{rst}/__pycache__/'),
        )
        for p,r in pathsAndResults:
            self.assertEqual(highlightWords(p), r)

        # Param to NOT highlight volatile
        self.assertEqual(highlightWords('/root/123.aBcXy9',     False), f'/{red}root{rst}/123.aBcXy9')
        self.assertEqual(highlightWords('/secrets/123-abcxy9/', False), f'/{red}secret{rst}s/123-abcxy9/')
        self.assertEqual(highlightWords('/123.AbcdWxyz',        False), f'/123.AbcdWxyz')

class regexTests(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_adaptFilePath(self):
        '''Full-cycle substitutions, for single lines'''
        filePaths_default = (
(   {'path': '/usr/bin/',                               'operation': {'open'}},
    {'path': '/{,usr/}bin/',                            'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/']]}),
(   {'path': '/usr/sbin/ldconfig.real',                 'operation': {'open'}},
    {'path': '/{,usr/}{,s}bin/ldconfig{,.real}',        'operation': {'open'}, 'path_diffs': [[(1, 12), 'usr/s'], [(24, 32), '.real']]}),
(   {'path': '/usr/local/bin/',                         'operation': {'open'}},
    {'path': '/{,usr/}{,local/}bin/',                   'operation': {'open'}, 'path_diffs': [[(1, 17), 'usr/local/']]}),
(   {'path': '/etc/gdm/',                               'operation': {'open'}},
    {'path': '/etc/gdm{,3}/',                           'operation': {'open'}, 'path_diffs': [[(8, 12), '']]}),
(   {'path': '/etc/gdm3/',                              'operation': {'open'}},
    {'path': '/etc/gdm{,3}/',                           'operation': {'open'}, 'path_diffs': [[(8, 12), '3']]}),
(   {'path': '/bin/grep',                               'operation': {'open'}},
    {'path': '/{,usr/}bin/{,e,f}grep',                  'operation': {'open'}, 'path_diffs': [[(1, 8), ''],     [(12, 18), '']]}),
(   {'path': '/usr/bin/grep',                           'operation': {'open'}},
    {'path': '/{,usr/}bin/{,e,f}grep',                  'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/'], [(12, 18), '']]}),
(   {'path': '/bin/awk',                                'operation': {'open'}},
    {'path': '/{,usr/}bin/{,g,m}awk',                   'operation': {'open'}, 'path_diffs': [[(1, 8), ''],     [(12, 18), '']]}),
(   {'path': '/usr/bin/mawk',                           'operation': {'open'}},
    {'path': '/{,usr/}bin/{,g,m}awk',                   'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/'], [(12, 18), 'm']]}),
(   {'path': '/bin/python3.10',                         'operation': {'open'}},
    {'path': '/{,usr/}bin/python3.[0-9]{,[0-9]}',       'operation': {'open'}, 'path_diffs': [[(1, 8), ''],     [(20, 33), '10']]}),
(   {'path': '/bin/python3.12-config',                  'operation': {'open'}},
    {'path': '/{,usr/}bin/python3.[0-9]{,[0-9]}-config','operation': {'open'}, 'path_diffs': [[(1, 8), ''],     [(20, 33), '12']]}),
(   {'path': '/lib/python3.10/',                        'operation': {'open'}},
    {'path': '/{,usr/}lib/python3.[0-9]{,[0-9]}/',      'operation': {'open'}, 'path_diffs': [[(1, 8), ''],     [(20, 33), '10']]}),
(   {'path': '/usr/lib/python3.10/',                    'operation': {'open'}},
    {'path': '/{,usr/}lib/python3.[0-9]{,[0-9]}/',      'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/'], [(20, 33), '10']]}),
(   {'path': '/usr/local/lib/python3.10/',              'operation': {'open'}},
    {'path': '/usr/local/lib/python3.[0-9]{,[0-9]}/',   'operation': {'open'}, 'path_diffs': [[(23, 36), '10']]}),
(   {'path': '/home/user/.config/ibus/bus/e561af98c3584a29a4eab8a761aceaf8-', 'operation': {'open'}},
    {'path': '@{HOME}/.config/ibus/bus/[0-9a-f]*[0-9a-f]-', 'operation': {'open'}, 'path_diffs': [[(0, 7), '/home/user'], [(25, 42), 'e561af98c3584a29a4eab8a761aceaf8']], 'path_prefix': 'owner'}),
(   {'path': '/var/lib/apt/lists/ie.archive.ubuntu.com_ubuntu_dists_jammy_main_dep11_Components-amd64.yml.gz', 'operation': {'open'}},
    {'path': '/var/lib/apt/lists/*.yml.gz',             'operation': {'open'}, 'path_diffs': [[(19, 20), 'ie.archive.ubuntu.com_ubuntu_dists_jammy_main_dep11_Components-amd64']]}),
(   {'path': '/home/user/.local/share/kcookiejar/cookies.aBcXy9', 'operation': {'open'}},
    {'path': '@{user_share_dirs}/kcookiejar/cookies.??????',    'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.local/share'], [(38, 44), 'aBcXy9']], 'path_prefix': 'owner'}),
(   {'path': '/run/log/journal/e561af98c3584a29a4eab8a761aceaf8/system@84dc5cc7a30f49d19b1412b97218d200-00000000001e258e-0006093052d8dbd6.journal', 'operation': {'open'}},
    {'path': '@{run}/log/journal/[0-9a-f]*[0-9a-f]/system@[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f].journal', 'operation': {'open'}, 'path_diffs': [[(0, 6), '/run'], [(19, 36), 'e561af98c3584a29a4eab8a761aceaf8'], [(44, 61), '84dc5cc7a30f49d19b1412b97218d200'], [(62, 79), '00000000001e258e'], [(80, 97), '0006093052d8dbd6']]}),
(   {'path': '/var/log/journal/e561af98c3584a29a4eab8a761aceaf8/system@84dc5cc7a30f49d19b1412b97218d200-00000000001e258e-0006093052d8dbd6.journal', 'operation': {'open'}},
    {'path': '/var/log/journal/[0-9a-f]*[0-9a-f]/system@[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f].journal', 'operation': {'open'}, 'path_diffs': [[(17, 34), 'e561af98c3584a29a4eab8a761aceaf8'], [(42, 59), '84dc5cc7a30f49d19b1412b97218d200'], [(60, 77), '00000000001e258e'], [(78, 95), '0006093052d8dbd6']]}),
(   {'path': '/var/log/journal/e561af98c3584a29a4eab8a761aceaf8/user-1000@0006176e316484b4-20556a3ac0d10361.journal', 'operation': {'open'}},
    {'path': '/var/log/journal/[0-9a-f]*[0-9a-f]/user-@{uid}@[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f].journal', 'operation': {'open'}, 'path_diffs': [[(17, 34), 'e561af98c3584a29a4eab8a761aceaf8'], [(40, 46), '1000'], [(47, 64), '0006176e316484b4'], [(65, 82), '20556a3ac0d10361']]}),
(   {'path': '/var/log/journal/e561af98c3584a29a4eab8a761aceaf8/system@84dc5cc7a30f49d19b1412b97218d200-00000000001e258e-0006093052d8dbd6.[te*st].t"e??st', 'operation': {'open'}},
    {'path': r'/var/log/journal/[0-9a-f]*[0-9a-f]/system@[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f].\[te\*st\].t\"e\?\?st', 'operation': {'open'}, 'path_diffs': [[(17, 34), 'e561af98c3584a29a4eab8a761aceaf8'], [(42, 59), '84dc5cc7a30f49d19b1412b97218d200'], [(60, 77), '00000000001e258e'], [(78, 95), '0006093052d8dbd6'], [(96, 97), ''], [(100, 101), ''], [(104, 105), ''], [(108, 109), ''], [(111, 112), ''], [(113, 114), '']]}),
(   {'path': '/var/log/journal/e561af98c3584a29a4eab8a761aceaf8/system@00000000001e258e-0006093052d8dbd6.journal', 'operation': {'open'}},
    {'path': '/var/log/journal/[0-9a-f]*[0-9a-f]/system@[0-9a-f]*[0-9a-f]-[0-9a-f]*[0-9a-f].journal', 'operation': {'open'}, 'path_diffs': [[(17, 34), 'e561af98c3584a29a4eab8a761aceaf8'], [(42, 59), '00000000001e258e'], [(60, 77), '0006093052d8dbd6']]}),
(   {'path': '/tmp/systemd-private-779146be998c4b178253781e20277618-systemd-logind.service-h5Ctde/', 'operation': {'open'}},
    {'path': '/tmp/systemd-private-[0-9a-f]*[0-9a-f]-systemd-logind.service-??????/', 'operation': {'open'}, 'path_diffs': [[(21, 38), '779146be998c4b178253781e20277618'], [(62, 68), 'h5Ctde']], 'path_prefix': 'owner'}),
(   {'path': '/home/user/.cache/fontconfig/807752c9e168308eb5108dacded5237a-le64.cache-7', 'operation': {'open'}},
    {'path': '@{HOME}/.cache/fontconfig/[0-9a-f]*[0-9a-f]-le64.cache-7', 'operation': {'open'}, 'path_diffs': [[(0, 7), '/home/user'], [(26, 43), '807752c9e168308eb5108dacded5237a']], 'path_prefix': 'owner'}),
(   {'path': '/var/cache/fontconfig/807752c9e168308eb5108dacded5237a-le64.cache-7', 'operation': {'open'}},
    {'path': '/var/cache/fontconfig/[0-9a-f]*[0-9a-f]-le64.cache-7', 'operation': {'open'}, 'path_diffs': [[(22, 39), '807752c9e168308eb5108dacded5237a']], 'path_prefix': 'owner'}),
(   {'path': '/home/user/.cache/fontconfig/807752c9e168308eb5108dacded5237a-le64.cache-7.TMP-Ke7L9W', 'operation': {'open'}},
    {'path': '@{HOME}/.cache/fontconfig/[0-9a-f]*[0-9a-f]-le64.cache-7.TMP-??????', 'operation': {'open'}, 'path_diffs': [[(0, 7), '/home/user'], [(26, 43), '807752c9e168308eb5108dacded5237a'], [(61, 67), 'Ke7L9W']], 'path_prefix': 'owner'}),
(   {'path': '/proc/3003/fdinfo/8',                     'operation': {'open'}},
    {'path': '@{PROC}/@{pid}/fdinfo/[0-9]*',            'operation': {'open'}, 'path_diffs': [[(0, 7), '/proc'], [(8, 14), '3003'], [(22, 28), '8']], 'path_prefix': 'owner'}),
(   {'path': '/run/user/1000/wayland-0',                'operation': {'open'}},
    {'path': '@{run}/user/@{uid}/wayland-[0-9]*',       'operation': {'open'}, 'path_diffs': [[(0, 6), '/run'], [(12, 18), '1000'], [(27, 33), '0']], 'path_prefix': 'owner'}),
(   {'path': '/lib/',                                   'operation': {'open'}},
    {'path': '/{,usr/}lib/',                            'operation': {'open'}, 'path_diffs': [[(1, 8), '']]}),
(   {'path': '/usr/lib/',                               'operation': {'open'}},
    {'path': '/{,usr/}lib/',                            'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/']]}),
(   {'path': '/tmp/tmpOe4yP6mW/',                       'operation': {'open'}},
    {'path': '/tmp/tmp????????/',                       'operation': {'open'}, 'path_diffs': [[(8, 16), 'Oe4yP6mW']], 'path_prefix': 'owner'}),
(   {'path': '/tmp/tmp.Oe4yP6mWT4/',                    'operation': {'open'}},
    {'path': '/tmp/tmp.??????????/',                    'operation': {'open'}, 'path_diffs': [[(9, 19), 'Oe4yP6mWT4']], 'path_prefix': 'owner'}),
(   {'path': '/run/netns/cni-e4b9714f-cbf5-45a8-9fbf-3ac3b47fd809', 'operation': {'open'}},
    {'path': '@{run}/netns/cni-[0-9a-f]*[0-9a-f]',      'operation': {'open'}, 'path_diffs': [[(0, 6), '/run'], [(17, 34), 'e4b9714f-cbf5-45a8-9fbf-3ac3b47fd809']]}),
(   {'path': '/home/user/.cache/thumbnails/fail/gnome-thumbnail-factory/d7d9f01923147d3126f4d8dc459a958f.png', 'operation': {'open'}},
    {'path': '@{HOME}/.cache/thumbnails/fail/gnome-thumbnail-factory/*.png', 'operation': {'open'}, 'path_diffs': [[(0, 7), '/home/user'], [(55, 56), 'd7d9f01923147d3126f4d8dc459a958f']], 'path_prefix': 'owner'}),
(   {'path': '/home/user/xauth_aBcXy9',                 'operation': {'open'}},
    {'path': '@{HOME}/xauth_??????',                    'operation': {'open'}, 'path_diffs': [[(0, 7), '/home/user'], [(14, 20), 'aBcXy9']], 'path_prefix': 'owner'}),
(   {'path': '/tmp/Mozillac843286e-fb29-4915-aa17-db3a6df86497-',            'operation': {'open'}},
    {'path': '/tmp/Mozilla[0-9a-f]*[0-9a-f]-',          'operation': {'open'}, 'path_diffs': [[(12, 29), 'c843286e-fb29-4915-aa17-db3a6df86497']], 'path_prefix': 'owner'}),
(   {'path': '/tmp/Mozilla{c843286e-fb29-4915-aa17-db3a6df86497}-',            'operation': {'open'}},
    {'path': r'/tmp/Mozilla\{[0-9a-f]*[0-9a-f]\}-',      'operation': {'open'}, 'path_diffs': [[(12, 13), ''], [(14, 31), 'c843286e-fb29-4915-aa17-db3a6df86497'], [(31, 32), '']], 'path_prefix': 'owner'}),
(   {'path': r'/][*{}?^[[]]{}*? ?\*/mHwu2E.tmp',           'operation': {'open'}},
    {'path': r'/\]\[\*\{\}\?\^\[\[\]\]\{\}\*\? \?\\*/??????.tmp', 'operation': {'open'}, 'path_diffs': [[(1, 2), ''], [(3, 4), ''], [(5, 6), ''], [(7, 8), ''], [(9, 10), ''], [(11, 12), ''], [(13, 14), ''], [(15, 16), ''], [(17, 18), ''], [(19, 20), ''], [(21, 22), ''], [(23, 24), ''], [(25, 26), ''], [(27, 28), ''], [(29, 30), ''], [(32, 33), ''], [(34, 35), ''], [(38, 44), 'mHwu2E']], 'path_prefix': 'owner'}),
(   {'path': r'/\\\\\a.txt',                            'operation': {'open'}},
    {'path': r'/\\\\\\\\\\a.txt',                       'operation': {'open'}, 'path_diffs': [[(1, 2), ''], [(2, 3), ''], [(3, 4), ''], [(4, 5), ''], [(5, 6), '']]}),
(   {'path': '/var/lib/gdm3/.cache/mesa_shader_cache/5b/630568b4dc7a281bca68647783eb1b338fd9ce.tmp', 'operation': {'open'}},
    {'path': '/var/lib/gdm{,3}/.cache/mesa_shader_cache/[0-9a-f][0-9a-f]/[0-9a-f]*[0-9a-f].tmp', 'operation': {'open'}, 'path_diffs': [[(12, 16), '3'], [(42, 58), '5b'], [(59, 76), '630568b4dc7a281bca68647783eb1b338fd9ce']]}),
(   {'path': '/usr/lib/kde/',                           'operation': {'open'}},
    {'path': '/{,usr/}lib/kde{,3,4}/',                  'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/'], [(15, 21), '']]}),
(   {'path': '/lib/kde4/',                              'operation': {'open'}},
    {'path': '/{,usr/}lib/kde{,3,4}/',                  'operation': {'open'}, 'path_diffs': [[(1, 8), ''], [(15, 21), '4']]}),
(   {'path': '/lib/aarch64-linux-musl/',                'operation': {'open'}},
    {'path': '/{,usr/}lib/@{multiarch}/',               'operation': {'open'}, 'path_diffs': [[(1, 8), ''], [(12, 24), 'aarch64-linux-musl']]}),
(   {'path': '/usr/lib/x86_64-linux-gnu/',              'operation': {'open'}},
    {'path': '/{,usr/}lib/@{multiarch}/',               'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/'], [(12, 24), 'x86_64-linux-gnu']]}),
(   {'path': '/usr/lib/arm-linux-gnueabihf/',           'operation': {'open'}},
    {'path': '/{,usr/}lib/@{multiarch}/',               'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/'], [(12, 24), 'arm-linux-gnueabihf']]}),
(   {'path': '/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.', 'operation': {'open'}},
    {'path': '@{sys}/fs/cgroup/user.slice/user-@{uid}.slice/user@@{uid}.', 'operation': {'open'}, 'path_diffs': [[(0, 6), '/sys'], [(33, 39), '1000'], [(51, 57), '1000']]}),
(   {'path': '/sys/devices/pci0000:00/0000:00:1f.3/drm/card1/metrics/e12693c1-5c3d-4fe4-8fc2-6c3ae26b04d3/',           'operation': {'open'}},
    {'path': '@{sys}/devices/pci????:??/????:??:??.?/drm/card[0-9]*/metrics/[0-9a-f]*[0-9a-f]/', 'operation': {'open'}, 'path_diffs': [[(0, 6), '/sys'], [(18, 25), '0000:00'], [(26, 38), '0000:00:1f.3'], [(47, 53), '1'], [(62, 79), 'e12693c1-5c3d-4fe4-8fc2-6c3ae26b04d3']]}),
(   {'path': '/sys/devices/pci0000:00/0000:00:1f.3/0000:00:00.2/', 'operation': {'open'}},
    {'path': '@{sys}/devices/pci????:??/????:??:??.?/????:??:??.?/', 'operation': {'open'}, 'path_diffs': [[(0, 6), '/sys'], [(18, 25), '0000:00'], [(26, 38), '0000:00:1f.3'], [(39, 51), '0000:00:00.2']]}),
(   {'path': '/tmp/calibre_5.37.0_tmp_trrspk_e/zr_8mcrzlog.txt', 'operation': {'open'}},
    {'path': '/tmp/calibre_5.[0-9]{,[0-9]}.[0-9]{,[0-9]}_tmp_????????/????????log.txt', 'operation': {'open'}, 'path_diffs': [[(15, 28), '37'], [(29, 42), '0'], [(47, 55), 'trrspk_e'], [(56, 64), 'zr_8mcrz']], 'path_prefix': 'owner'}),
(   {'path': '/etc/polkit-1/rules.d/01-local',          'operation': {'open'}},
    {'path': '/etc/polkit-1/rules.d/[0-9][0-9]-local',  'operation': {'open'}, 'path_diffs': [[(22, 32), '01']]}),
(   {'path': '/etc/dir/subdir/conf.d/00-local',         'operation': {'open'}},
    {'path': '/etc/dir/subdir/conf.d/[0-9][0-9]-local', 'operation': {'open'}, 'path_diffs': [[(23, 33), '00']]}),
(   {'path': '/etc/fonts/conf.avail/10-local',           'operation': {'open'}},
    {'path': '/etc/fonts/conf.avail/[0-9][0-9]-local',   'operation': {'open'}, 'path_diffs': [[(22, 32), '10']]}),
(   {'path': '/home/user/.cache/kcrash-metadata/plasmashell.d5856b1aeb3505a99ebc25cc92607f81.1234.ini', 'operation': {'open'}},
    {'path': '@{HOME}/.cache/kcrash-metadata/plasmashell.[0-9a-f]*[0-9a-f].[0-9]*.ini', 'operation': {'open'}, 'path_diffs': [[(0, 7), '/home/user'], [(43, 60), 'd5856b1aeb3505a99ebc25cc92607f81'], [(61, 67), '1234']], 'path_prefix': 'owner'}),
(   {'path': '/var/lib/gdm3/.cache/ibus/dbus-KeTdY3dU',    'operation': {'open'}},
    {'path': '/var/lib/gdm{,3}/.cache/ibus/dbus-????????', 'operation': {'open'}, 'path_diffs': [[(12, 16), '3'], [(34, 42), 'KeTdY3dU']]}),
(   {'path': '/var/lib/gdm/.config/ibus/bus/d5856b1aeb3505a99ebc25cc92607f81-unix-1',    'operation': {'open'}},
    {'path': '/var/lib/gdm{,3}/.config/ibus/bus/[0-9a-f]*[0-9a-f]-unix-[0-9]*', 'operation': {'open'}, 'path_diffs': [[(12, 16), ''], [(34, 51), 'd5856b1aeb3505a99ebc25cc92607f81'], [(57, 63), '1']]}),
(   {'path': '/var/lib/gdm/.local/share/xorg/Xorg.1.log',          'operation': {'open'}},
    {'path': '/var/lib/gdm{,3}/.local/share/xorg/Xorg.[0-9]*.log', 'operation': {'open'}, 'path_diffs': [[(12, 16), ''], [(40, 46), '1']]}),
(   {'path': '/var/lib/gdm/.local/file',                'operation': {'open'}},
    {'path': '/var/lib/gdm{,3}/.local/file',            'operation': {'open'}, 'path_diffs': [[(12, 16), '']]}),
    # UNIX sockets
(   {'path': '@/home/user/.cache/ibus/dbus-qGivRGmK',   'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@/home/*/.cache/ibus/dbus-????????',      'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(7, 8), 'user'], [(26, 34), 'qGivRGmK']], 'path_prefix': 'owner'}),  # not actually 'path', but 'addr'
(   {'path': '@/tmp/dbus-IgfNnTvp',                     'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@/tmp/dbus-????????',                     'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(11, 19), 'IgfNnTvp']], 'path_prefix': 'owner'}),
(   {'path': '@63cf34db7fbab75f/bus/sshd/system',       'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@????????????????/bus/sshd/system',       'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(1, 17), '63cf34db7fbab75f']]}),
(   {'path': '@/var/lib/gdm3/.cache/ibus/dbus-KeTdY3dU',    'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@/var/lib/gdm{,3}/.cache/ibus/dbus-????????', 'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(13, 17), '3'], [(35, 43), 'KeTdY3dU']]}),
    # Other traps
(   {'path': '/lib/d/aarch64-linux-musl/',              'operation': {'open'}},
    {'path': '/{,usr/}lib/d/aarch64-linux-musl/',       'operation': {'open'}, 'path_diffs': [[(1, 8), '']]}),
(   {'path': '/usr/lib/d/x86_64-linux-gnu/',            'operation': {'open'}},
    {'path': '/{,usr/}lib/d/x86_64-linux-gnu/',         'operation': {'open'}, 'path_diffs': [[(1, 8), 'usr/']]}),
    # Nothing to adapt
(   {'path': '/tmp/abc',                                'operation': {'open'}},
    {'path': '/tmp/abc',                                'operation': {'open'}}),
(   {'path': '/usr/libexec/',                           'operation': {'open'}},
    {'path': '/usr/libexec/',                           'operation': {'open'}}),
        )
        for i,r in filePaths_default:
            self.assertEqual(adaptFilePath(i, 'path', 'default'), r)

        filePaths_apparmor_d = (
(   {'path': '/usr/bin/',                               'operation': {'open'}},
    {'path': '@{bin}/',                                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/bin']]}),
(   {'path': '/usr/sbin/ldconfig.real',                 'operation': {'open'}},
    {'path': '@{bin}/ldconfig{,.real}',                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/sbin'], [(15, 23), '.real']]}),
(   {'path': '/usr/sbin/',                              'operation': {'open'}},
    {'path': '@{bin}/',                                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/sbin']]}),
(   {'path': '/usr/local/bin/',                         'operation': {'open'}},
    {'path': '/{,usr/}{,local/}bin/',                   'operation': {'open'}, 'path_diffs': [[(1, 17), 'usr/local/']]}),
(   {'path': '/bin/grep',                               'operation': {'open'}},
    {'path': '@{bin}/{,e,f}grep',                       'operation': {'open'}, 'path_diffs': [[(0, 6), '/bin'],     [(7, 13), '']]}),
(   {'path': '/usr/bin/grep',                           'operation': {'open'}},
    {'path': '@{bin}/{,e,f}grep',                       'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/bin'], [(7, 13), '']]}),
(   {'path': '/bin/awk',                                'operation': {'open'}},
    {'path': '@{bin}/{,g,m}awk',                        'operation': {'open'}, 'path_diffs': [[(0, 6), '/bin'],     [(7, 13), '']]}),
(   {'path': '/usr/bin/mawk',                           'operation': {'open'}},
    {'path': '@{bin}/{,g,m}awk',                        'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/bin'], [(7, 13), 'm']]}),
(   {'path': '/bin/python3.10',                         'operation': {'open'}},
    {'path': '@{bin}/python3.@{int}',                   'operation': {'open'}, 'path_diffs': [[(0, 6), '/bin'],     [(15, 21), '10']]}),
(   {'path': '/lib/python3.10/',                        'operation': {'open'}},
    {'path': '@{lib}/python3.@{int}/',                  'operation': {'open'}, 'path_diffs': [[(0, 6), '/lib'],     [(15, 21), '10']]}),
(   {'path': '/usr/lib/python3.10/',                    'operation': {'open'}},
    {'path': '@{lib}/python3.@{int}/',                  'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib'], [(15, 21), '10']]}),
(   {'path': '/usr/local/lib/python3.10/',              'operation': {'open'}},
    {'path': '/usr/local/lib/python3.@{int}/',          'operation': {'open'}, 'path_diffs': [[(23, 29), '10']]}),
(   {'path': '/home/user/.config/ibus/bus/e561af98c3584a29a4eab8a761aceaf8-', 'operation': {'open'}},
    {'path': '@{user_config_dirs}/ibus/bus/@{hex32}-',    'operation': {'open'}, 'path_diffs': [[(0, 19), '/home/user/.config'], [(29, 37), 'e561af98c3584a29a4eab8a761aceaf8']], 'path_prefix': 'owner'}),
(   {'path': '/var/lib/apt/lists/ie.archive.ubuntu.com_ubuntu_dists_jammy_main_dep11_Components-amd64.yml.gz', 'operation': {'open'}},
    {'path': '/var/lib/apt/lists/*.yml.gz',             'operation': {'open'}, 'path_diffs': [[(19, 20), 'ie.archive.ubuntu.com_ubuntu_dists_jammy_main_dep11_Components-amd64']]}),
(   {'path': '/home/user/.local/share/gvfs-metadata/root', 'operation': {'open'}},
    {'path': '@{user_share_dirs}/gvfs-metadata/{,*}',   'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.local/share'], [(33, 37), 'root']], 'path_prefix': 'deny'}),
(   {'path': '/home/user/.local/share/gvfs-metadata/',  'operation': {'open'}},
    {'path': '@{user_share_dirs}/gvfs-metadata/{,*}',   'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.local/share'], [(33, 37), '']], 'path_prefix': 'deny'}),
(   {'path': '/home/user/.local/share/kcookiejar/cookies.aBcXy9', 'operation': {'open'}},
    {'path': '@{user_share_dirs}/kcookiejar/cookies.@{rand6}',    'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.local/share'], [(38, 46), 'aBcXy9']], 'path_prefix': 'owner'}),
(   {'path': '/var/log/journal/e561af98c3584a29a4eab8a761aceaf8/system@84dc5cc7a30f49d19b1412b97218d200-00000000001e258e-0006093052d8dbd6.journal', 'operation': {'open'}},
    {'path': '/var/log/journal/@{hex32}/system@@{hex32}-@{hex16}-@{hex16}.journal',   'operation': {'open'}, 'path_diffs': [[(17, 25), 'e561af98c3584a29a4eab8a761aceaf8'], [(33, 41), '84dc5cc7a30f49d19b1412b97218d200'], [(42, 50), '00000000001e258e'], [(51, 59), '0006093052d8dbd6']]}),
(   {'path': '/var/log/journal/e561af98c3584a29a4eab8a761aceaf8/system@00000000001e258e-0006093052d8dbd6.journal', 'operation': {'open'}},
    {'path': '/var/log/journal/@{hex32}/system@@{hex16}-@{hex16}.journal', 'operation': {'open'}, 'path_diffs': [[(17, 25), 'e561af98c3584a29a4eab8a761aceaf8'], [(33, 41), '00000000001e258e'], [(42, 50), '0006093052d8dbd6']]}),
(   {'path': '/tmp/systemd-private-779146be998c4b178253781e20277618-systemd-logind.service-h5Ctde/', 'operation': {'open'}},
    {'path': '/tmp/systemd-private-@{hex32}-systemd-logind.service-@{rand6}/', 'operation': {'open'}, 'path_diffs': [[(21, 29), '779146be998c4b178253781e20277618'], [(53, 61), 'h5Ctde']], 'path_prefix': 'owner'}),
(   {'path': '/home/user/.cache/fontconfig/807752c9e168308eb5108dacded5237a-le64.cache-7', 'operation': {'open'}},
    {'path': '@{user_cache_dirs}/fontconfig/@{hex32}-le64.cache-7', 'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.cache'], [(30, 38), '807752c9e168308eb5108dacded5237a']], 'path_prefix': 'owner'}),
(   {'path': '/var/cache/fontconfig/807752c9e168308eb5108dacded5237a-le64.cache-7', 'operation': {'open'}},
    {'path': '/var/cache/fontconfig/@{hex32}-le64.cache-7', 'operation': {'open'}, 'path_diffs': [[(22, 30), '807752c9e168308eb5108dacded5237a']], 'path_prefix': 'owner'}),
(   {'path': '/home/user/.cache/fontconfig/807752c9e168308eb5108dacded5237a-le64.cache-7.TMP-Ke7L9W', 'operation': {'open'}},
    {'path': '@{user_cache_dirs}/fontconfig/@{hex32}-le64.cache-7.TMP-@{rand6}', 'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.cache'], [(30, 38), '807752c9e168308eb5108dacded5237a'], [(56, 64), 'Ke7L9W']], 'path_prefix': 'owner'}),
(   {'path': '/proc/3003/fdinfo/8',                     'operation': {'open'}},
    {'path': '@{PROC}/@{pid}/fdinfo/@{int}',            'operation': {'open'}, 'path_diffs': [[(0, 7), '/proc'], [(8, 14), '3003'], [(22, 28), '8']], 'path_prefix': 'owner'}),
(   {'path': '/run/user/1000/wayland-0',                'operation': {'open'}},
    {'path': '@{run}/user/@{uid}/wayland-@{int}',       'operation': {'open'}, 'path_diffs': [[(0, 6), '/run'], [(12, 18), '1000'], [(27, 33), '0']], 'path_prefix': 'owner'}),
(   {'path': '/lib/',                                   'operation': {'open'}},
    {'path': '@{lib}/',                                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/lib']]}),
(   {'path': '/usr/lib32/',                             'operation': {'open'}},
    {'path': '@{lib}/',                                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib32']]}),
(   {'path': '/usr/lib64/',                             'operation': {'open'}},
    {'path': '@{lib}/',                                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib64']]}),
(   {'path': '/usr/lib/',                               'operation': {'open'}},
    {'path': '@{lib}/',                                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib']]}),
(   {'path': '/usr/libexec/',                           'operation': {'open'}},
    {'path': '@{lib}/',                                 'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/libexec']]}),
(   {'path': '/tmp/tmpOe4yP6mW/',                       'operation': {'open'}},
    {'path': '/tmp/tmp@{rand8}/',                       'operation': {'open'}, 'path_diffs': [[(8, 16), 'Oe4yP6mW']], 'path_prefix': 'owner'}),
(   {'path': '/tmp/tmp.Oe4yP6mWT4/',                    'operation': {'open'}},
    {'path': '/tmp/tmp.@{rand10}/',                     'operation': {'open'}, 'path_diffs': [[(9, 18), 'Oe4yP6mWT4']], 'path_prefix': 'owner'}),
(   {'path': '/run/netns/cni-e4b9714f-cbf5-45a8-9fbf-3ac3b47fd809', 'operation': {'open'}},
    {'path': '@{run}/netns/cni-@{uuid}',                'operation': {'open'}, 'path_diffs': [[(0, 6), '/run'], [(17, 24), 'e4b9714f-cbf5-45a8-9fbf-3ac3b47fd809']]}),
(   {'path': '/home/user/.cache/thumbnails/fail/gnome-thumbnail-factory/d7d9f01923147d3126f4d8dc459a958f.png', 'operation': {'open'}},
    {'path': '@{user_cache_dirs}/thumbnails/fail/gnome-thumbnail-factory/@{hex32}.png', 'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.cache'], [(59, 67), 'd7d9f01923147d3126f4d8dc459a958f']], 'path_prefix': 'owner'}),
(   {'path': '/home/user/xauth_aBcXy9',                 'operation': {'open'}},
    {'path': '@{HOME}/xauth_@{rand6}',                  'operation': {'open'}, 'path_diffs': [[(0, 7), '/home/user'], [(14, 22), 'aBcXy9']], 'path_prefix': 'owner'}),
(   {'path': '/tmp/Mozillac843286e-fb29-4915-aa17-db3a6df86497-',            'operation': {'open'}},
    {'path': '/tmp/Mozilla@{uuid}-',                    'operation': {'open'}, 'path_diffs': [[(12, 19), 'c843286e-fb29-4915-aa17-db3a6df86497']], 'path_prefix': 'owner'}),
(   {'path': '/tmp/Mozilla{c843286e-fb29-4915-aa17-db3a6df86497}-',            'operation': {'open'}},
    {'path': r'/tmp/Mozilla\{@{uuid}\}-',                  'operation': {'open'}, 'path_diffs': [[(12, 13), ''], [(14, 21), 'c843286e-fb29-4915-aa17-db3a6df86497'], [(21, 22), '']], 'path_prefix': 'owner'}),
(   {'path': '/var/lib/gdm/.cache/mesa_shader_cache/5b/630568b4dc7a281bca68647783eb1b338fd9ce', 'operation': {'open'}},
    {'path': '@{gdm_cache_dirs}/mesa_shader_cache/@{hex2}/@{hex38}', 'operation': {'open'}, 'path_diffs': [[(0, 17), '/var/lib/gdm/.cache'], [(36, 43), '5b'],[(44, 52), '630568b4dc7a281bca68647783eb1b338fd9ce']]}),
(   {'path': '/usr/lib/kde/',                           'operation': {'open'}},
    {'path': '@{lib}/kde{,3,4}/',                       'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib'], [(10, 16), '']]}),
(   {'path': '/lib/kde4/',                              'operation': {'open'}},
    {'path': '@{lib}/kde{,3,4}/',                       'operation': {'open'}, 'path_diffs': [[(0, 6), '/lib'], [(10, 16), '4']]}),
(   {'path': '/lib/aarch64-linux-musl/',                'operation': {'open'}},
    {'path': '@{lib}/@{multiarch}/',                    'operation': {'open'}, 'path_diffs': [[(0, 6), '/lib'], [(7, 19), 'aarch64-linux-musl']]}),
(   {'path': '/usr/lib/x86_64-linux-gnu/',              'operation': {'open'}},
    {'path': '@{lib}/@{multiarch}/',                    'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib'], [(7, 19), 'x86_64-linux-gnu']]}),
(   {'path': '/usr/lib/arm-linux-gnueabihf/',           'operation': {'open'}},
    {'path': '@{lib}/@{multiarch}/',                    'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib'], [(7, 19), 'arm-linux-gnueabihf']]}),
(   {'path': '/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.', 'operation': {'open'}},
    {'path': '@{sys}/fs/cgroup/user.slice/user-@{uid}.slice/user@@{uid}.', 'operation': {'open'}, 'path_diffs': [[(0, 6), '/sys'], [(33, 39), '1000'], [(51, 57), '1000']]}),

(   {'path': '/sys/devices/pci0000:00/0000:00:1f.3/drm/card1/metrics/e12693c1-5c3d-4fe4-8fc2-6c3ae26b04d3/',           'operation': {'open'}},
    {'path': '@{sys}/devices/@{pci_bus}/@{pci_id}/drm/card@{int}/metrics/@{uuid}/', 'operation': {'open'}, 'path_diffs': [[(0, 6), '/sys'], [(15, 25), 'pci0000:00'], [(26, 35), '0000:00:1f.3'], [(44, 50), '1'], [(59, 66), 'e12693c1-5c3d-4fe4-8fc2-6c3ae26b04d3']]}),
(   {'path': '/sys/devices/pci0000:00/0000:00:1f.3/0000:00:00.2/', 'operation': {'open'}},
    {'path': '@{sys}/devices/@{pci_bus}/@{pci_id}/@{pci_id}/', 'operation': {'open'}, 'path_diffs': [[(0, 6), '/sys'], [(15, 25), 'pci0000:00'], [(26, 35), '0000:00:1f.3'], [(36, 45), '0000:00:00.2']]}),
(   {'path': '/etc/polkit-1/rules.d/01-local',          'operation': {'open'}},
    {'path': '/etc/polkit-1/rules.d/@{int2}-local',  'operation': {'open'}, 'path_diffs': [[(22, 29), '01']]}),
(   {'path': '/etc/dir/subdir/conf.d/00-local',         'operation': {'open'}},
    {'path': '/etc/dir/subdir/conf.d/@{int2}-local', 'operation': {'open'}, 'path_diffs': [[(23, 30), '00']]}),
(   {'path': '/home/user/.cache/kcrash-metadata/plasmashell.d5856b1aeb3505a99ebc25cc92607f81.1234.ini', 'operation': {'open'}},
    {'path': '@{user_cache_dirs}/kcrash-metadata/plasmashell.@{hex32}.@{int4}.ini', 'operation': {'open'}, 'path_diffs': [[(0, 18), '/home/user/.cache'], [(47, 55), 'd5856b1aeb3505a99ebc25cc92607f81'], [(56, 63), '1234']], 'path_prefix': 'owner'}),
(   {'path': '/var/lib/gdm3/.cache/ibus/dbus-KeTdY3dU',    'operation': {'open'}},
    {'path': '@{gdm_cache_dirs}/ibus/dbus-@{rand8}', 'operation': {'open'}, 'path_diffs': [[(0, 17), '/var/lib/gdm3/.cache'], [(28, 36), 'KeTdY3dU']]}),
(   {'path': '/var/lib/gdm3/.config/ibus/bus/d5856b1aeb3505a99ebc25cc92607f81-unix-1',    'operation': {'open'}},
    {'path': '@{gdm_config_dirs}/ibus/bus/@{hex32}-unix-@{int}', 'operation': {'open'}, 'path_diffs': [[(0, 18), '/var/lib/gdm3/.config'], [(28, 36), 'd5856b1aeb3505a99ebc25cc92607f81'], [(42, 48), '1']]}),
(   {'path': '/var/lib/gdm/.local/share/xorg/Xorg.1.log',      'operation': {'open'}},
    {'path': '@{gdm_share_dirs}/xorg/Xorg.@{int}.log',  'operation': {'open'}, 'path_diffs': [[(0, 17), '/var/lib/gdm/.local/share'], [(28, 34), '1']]}),
(   {'path': '/var/lib/gdm/.local/file',                'operation': {'open'}},
    {'path': '@{gdm_local_dirs}/file',                  'operation': {'open'}, 'path_diffs': [[(0, 17), '/var/lib/gdm/.local']]}),
(   {'path': '/var/lib/sddm/.local/share/',              'operation': {'open'}},
    {'path': '@{sddm_share_dirs}/',  'operation': {'open'}, 'path_diffs': [[(0, 18), '/var/lib/sddm/.local/share']]}),
(   {'path': '/var/lib/lightdm/.local/share/',          'operation': {'open'}},
    {'path': '@{lightdm_share_dirs}/',                  'operation': {'open'}, 'path_diffs': [[(0, 21), '/var/lib/lightdm/.local/share']]}),
    # UNIX sockets
(   {'path': '@/home/user/.cache/ibus/dbus-qGivRGmK',   'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@/home/*/.cache/ibus/dbus-????????',      'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(7, 8), 'user'], [(26, 34), 'qGivRGmK']], 'path_prefix': 'owner'}),
(   {'path': '@/tmp/dbus-IgfNnTvp',                     'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@/tmp/dbus-????????',                     'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(11, 19), 'IgfNnTvp']], 'path_prefix': 'owner'}),
(   {'path': '@63cf34db7fbab75f/bus/sshd/system',       'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@????????????????/bus/sshd/system',       'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(1, 17), '63cf34db7fbab75f']]}),
(   {'path': '@/var/lib/gdm3/.cache/ibus/dbus-KeTdY3dU',    'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream'},
    {'path': '@/var/lib/gdm{,3}/.cache/ibus/dbus-????????', 'operation': {'connect'}, 'family': 'unix', 'sock_type': 'stream', 'path_diffs': [[(13, 17), '3'], [(35, 43), 'KeTdY3dU']]}),
    # Other traps
(   {'path': '/lib/d/aarch64-linux-musl/',              'operation': {'open'}},
    {'path': '@{lib}/d/aarch64-linux-musl/',            'operation': {'open'}, 'path_diffs': [[(0, 6), '/lib']]}),
(   {'path': '/usr/lib/d/x86_64-linux-gnu/',            'operation': {'open'}},
    {'path': '@{lib}/d/x86_64-linux-gnu/',              'operation': {'open'}, 'path_diffs': [[(0, 6), '/usr/lib']]}),
        )
        for i,r in filePaths_apparmor_d:
            self.assertEqual(adaptFilePath(i, 'path', 'AppArmor.d'), r)

    def test_adaptDbusPaths(self):
        '''Full-cycle substitutions, for multiple lines'''
        dbusPaths_default = (
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/2782',          'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/[0-9]*',        'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782']]}]} ),
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/2782/2',        'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/[0-9]*/[0-9]*', 'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782'], [(55, 61), '2']]}]} ),
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/SourceManager/Source_16',       'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/SourceManager/Source_[0-9]*',   'operation': {'dbus_method_call'}, 'path_diffs': [[(53, 59), '16']]}]} ),
(   {'synth': [{'path': '/org/freedesktop/Accounts/User1000',                            'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/freedesktop/Accounts/User@{uid}',                          'operation': {'dbus_method_call'}, 'path_diffs': [[(30, 36), '1000']]}]} ),
(   {'synth': [{'path': '/org/gnome/SessionManager/Client18',                            'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/SessionManager/Client[0-9]*',                        'operation': {'dbus_method_call'}, 'path_diffs': [[(32, 38), '18']]}]} ),
(   {'synth': [{'path': '/org/freedesktop/login1/seat/seat0',                            'operation': {'dbus_signal'}}]},
    {'synth': [{'path': '/org/freedesktop/login1/seat/seat[0-9]*',                       'operation': {'dbus_signal'},      'path_diffs': [[(33, 39), '0']]}]} ),
(   {'synth': [{'path': '/com/canonical/unity/launcherentry/1520791323',                 'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/com/canonical/unity/launcherentry/[0-9]*',                     'operation': {'dbus_method_call'}, 'path_diffs': [[(35, 41), '1520791323']]}]} ),
(   {'synth': [{'path': '/org/freedesktop/login1/session/_31',                           'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/freedesktop/login1/session/*',                             'operation': {'dbus_method_call'}, 'path_diffs': [[(32, 33), '_31']]}]} ),
(   {'synth': [{'path': '/org/freedesktop/UDisks2/block_devices/vda7',                   'operation': {'dbus_signal'}}]},
    {'synth': [{'path': '/org/freedesktop/UDisks2/block_devices/*',                      'operation': {'dbus_signal'},      'path_diffs': [[(39, 40), 'vda7']]}]} ),
(   {'synth': [{'path': '/Client12/ServiceBrowser2',                                     'operation': {'dbus_signal'}}]},
    {'synth': [{'path': '/Client[0-9]*/ServiceBrowser[0-9]*',                            'operation': {'dbus_signal'},      'path_diffs': [[(7, 13), '12'], [(28, 34), '2']]}]} ),
    # Already substituted (traps)
(   {'synth': [{'path': '/org/freedesktop/UDisks2/block_devices/*',                      'operation': {'dbus_signal'}}]},
    {'synth': [{'path': '/org/freedesktop/UDisks2/block_devices/*',                      'operation': {'dbus_signal'}}]} ),
(   {'synth': [{'path': '/org/freedesktop/Accounts/User@{uid}',                          'operation': {'dbus_method_call'}, 'path_diffs': [[(30, 36), '1000']]}]},
    {'synth': [{'path': '/org/freedesktop/Accounts/User@{uid}',                          'operation': {'dbus_method_call'}, 'path_diffs': [[(30, 36), '1000']]}]} ),
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/[0-9]*',        'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782']]}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/[0-9]*',        'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782']]}]} ),
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/[0-9]*/[0-9]*', 'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782'], [(55, 61), '2']]}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/[0-9]*/[0-9]*', 'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782'], [(55, 61), '2']]}]} ),
(   {'synth': [{'path': '/org/freedesktop/Accounts/User@{uid}',                          'operation': {'dbus_method_call'}, 'path_diffs': [[(30, 36), '1000']]}]},
    {'synth': [{'path': '/org/freedesktop/Accounts/User@{uid}',                          'operation': {'dbus_method_call'}, 'path_diffs': [[(30, 36), '1000']]}]} ),
    # Nothing to adapt
(   {'synth': [{'path': '/org/Synth/abc',                                                'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/Synth/abc',                                                'operation': {'dbus_method_call'}}]} ),
(   {'synth': [{'nonmatching': '/org/keepme',                                            'operation': {'dbus_method_call'}}]},
    {'synth': [{'nonmatching': '/org/keepme',                                            'operation': {'dbus_method_call'}}]} ),
        )
        for i,r in dbusPaths_default:
            self.assertEqual(adaptDbusPaths(i, 'default'), r)

        assertion1 = {'synth': [{'path': '/tmp/f', 'operation': {'open'}}]}
        self.assertRaises(ValueError, adaptDbusPaths, assertion1, 'default')

        dbusPaths_apparmor_d = (
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/2782',          'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/@{int}',        'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782']]}]} ),
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/2782/2',        'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/AddressBookView/@{int}/@{int}', 'operation': {'dbus_method_call'}, 'path_diffs': [[(48, 54), '2782'], [(55, 61), '2']]}]} ),
(   {'synth': [{'path': '/org/gnome/evolution/dataserver/SourceManager/Source_16',       'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/evolution/dataserver/SourceManager/Source_@{int}',   'operation': {'dbus_method_call'}, 'path_diffs': [[(53, 59), '16']]}]} ),
(   {'synth': [{'path': '/org/gnome/SessionManager/Client18',                            'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/org/gnome/SessionManager/Client@{int}',                        'operation': {'dbus_method_call'}, 'path_diffs': [[(32, 38), '18']]}]} ),
(   {'synth': [{'path': '/org/freedesktop/login1/seat/seat0',                            'operation': {'dbus_signal'}}]},
    {'synth': [{'path': '/org/freedesktop/login1/seat/seat@{int}',                       'operation': {'dbus_signal'},      'path_diffs': [[(33, 39), '0']]}]} ),
(   {'synth': [{'path': '/com/canonical/unity/launcherentry/1520791323',                 'operation': {'dbus_method_call'}}]},
    {'synth': [{'path': '/com/canonical/unity/launcherentry/@{int}',                     'operation': {'dbus_method_call'}, 'path_diffs': [[(35, 41), '1520791323']]}]} ),
(   {'synth': [{'path': '/Client12/ServiceBrowser2',                                     'operation': {'dbus_signal'}}]},
    {'synth': [{'path': '/Client@{int}/ServiceBrowser@{int}',                            'operation': {'dbus_signal'},      'path_diffs': [[(7, 13), '12'], [(28, 34), '2']]}]} ),
        )
        for i,r in dbusPaths_apparmor_d:
            self.assertEqual(adaptDbusPaths(i, 'AppArmor.d'), r)

    def test_substituteGroup(self):
        self.assertEqual(substituteGroup('one_two_three', '2',      '_(two)_'),
                                        ('one_2_three',   (4, 5),   'two'))
        self.assertEqual(substituteGroup('one_two_three', '3',      '_(three)'),
                                        ('one_two_3',     (8, 9),   'three'))
        self.assertEqual(substituteGroup('/etc/gdm/',    '{,3}',    '^/etc/gdm(|3)/'),
                                        ('/etc/gdm{,3}/', (8, 12),  ''))
        self.assertEqual(substituteGroup('/etc/gdm3/',   '{,3}',    '^/etc/gdm(|3)/'),
                                        ('/etc/gdm{,3}/', (8, 12),  '3'))
        self.assertRaises(ValueError,          substituteGroup, 'one_two_three', '10', '_t.._')
        self.assertRaises(NotImplementedError, substituteGroup, 'one_two_three', '10', '(one)_(two)_')
        self.assertRaises(ValueError,          substituteGroup, 'one_two_three', 'owner', '_t.._')

class t_findLineType(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

#{'comm': 'dumpcap', 'path': '/run/dbus/system_bus_socket', 'timestamp': 223, 'operation': {'connect', 'file_perm'}, 'mask': {'r', 'w'}}  TODO

class t_normalizeProfileName(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_normalizeProfileName(self):
        line_pairs = (
   (
{'operation': 'dbus_method_call', 'bus': 'session', 'path': '/org/synth', 'interface': 'org.synth', 'member': 'ListMounts2', 'mask': 'send', 'name': ':[0-9]*', 'label':   'firefox', 'peer_label': 'unconfined'},
{'operation': 'dbus_method_call', 'bus': 'session', 'path': '/org/synth', 'interface': 'org.synth', 'member': 'ListMounts2', 'mask': 'send', 'name': ':[0-9]*', 'profile': 'firefox', 'peer': 'unconfined'},
), (
{'operation': 'dbus_bind',        'bus': 'session', 'name': 'org.mpris.MediaPlayer2.vlc', 'mask': 'bind', 'label':   'vlc'},
{'operation': 'dbus_bind',        'bus': 'session', 'name': 'org.mpris.MediaPlayer2.vlc', 'mask': 'bind', 'profile': 'vlc'},
), (
{'operation': 'dbus_eavesdrop',   'bus': 'session', 'mask': 'eavesdrop', 'label':   'dumpcap'},
{'operation': 'dbus_eavesdrop',   'bus': 'session', 'mask': 'eavesdrop', 'profile': 'dumpcap'},
), (
{'operation': 'ptrace',    'profile': 'systemd-tty-ask-password-agent', 'comm': 'systemd-tty-ask', 'requested_mask': 'read', 'peer': 'unconfined'},
{'operation': 'ptrace',    'profile': 'systemd-tty-ask-password-agent', 'comm': 'systemd-tty-ask', 'requested_mask': 'read', 'peer': 'unconfined'},
), (
{'operation': 'signal',    'profile': 'dumpcap', 'comm': 'wireshark', 'requested_mask': 'receive', 'signal': 'term', 'peer': 'wireshark'},
{'operation': 'signal',    'profile': 'dumpcap', 'comm': 'wireshark', 'requested_mask': 'receive', 'signal': 'term', 'peer': 'wireshark'},
), (
{'operation': 'file_perm', 'profile': 'xorg', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'requested_mask': 'send receive', 'addr': '@/synth', 'peer_addr': 'none', 'peer': 'wireshark'},
{'operation': 'file_perm', 'profile': 'xorg', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'requested_mask': 'send receive', 'addr': '@/synth', 'peer_addr': 'none', 'peer': 'wireshark'},
), (
{'operation': 'unlink',    'profile': 'vlc', 'comm': 'vlc', 'requested_mask': 'd', 'name': '/dev/char/195:0'},
{'operation': 'unlink',    'profile': 'vlc', 'comm': 'vlc', 'requested_mask': 'd', 'name': '/dev/char/195:0'},
), (
{'operation': 'create',    'profile': 'dumpcap', 'comm': 'dumpcap', 'family': 'netlink', 'sock_type': 'raw', 'protocol': '0', 'requested_mask': 'create'},
{'operation': 'create',    'profile': 'dumpcap', 'comm': 'dumpcap', 'family': 'netlink', 'sock_type': 'raw', 'protocol': '0', 'requested_mask': 'create'},
), 
        )
        for inpt,result in line_pairs:
            self.assertEqual(normalizeProfileName(inpt), result)

class t_adaptTempPaths_pairs(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_adaptTempPaths_default(self):
        fileLines_pairs = (
    ({'synth': [  # single tail
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 110},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 111},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 110, 'path_diffs': [[(10, 20), '']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 111, 'path_diffs': [[(10, 20), '.V6RK41']]},
 ]}),
    ({'synth': [  # two tails
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 120},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.K4TK9Q',    'timestamp': 121},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 122},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 120, 'path_diffs': [[(10, 20), '']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 121, 'path_diffs': [[(10, 20), '.K4TK9Q']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 122, 'path_diffs': [[(10, 20), '.V6RK41']]},
 ]}),
    ({'synth': [  # readonly tail
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 130},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 131},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 130},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 131},
 ]}),
    ({'synth': [  # readonly tail with writable neighbors
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 140},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 141},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 142},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 140, 'path_diffs': [[(10, 20), '']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 141, 'path_diffs': [[(10, 20), '.V6RK41']]},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 142},
 ]}),
    ({'synth': [  # unaffected neighbor
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 150},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 151},
 ],   'firefox': [
{'operation': {'unlink'},      'comm': 'firefox-bin', 'mask': {'d'},       'path': '/dev/char/195:255',    'timestamp': 152},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 150, 'path_diffs': [[(10, 20), '']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 151, 'path_diffs': [[(10, 20), '.V6RK41']]},
 ],  'firefox': [
{'operation': {'unlink'},      'comm': 'firefox-bin', 'mask': {'d'},       'path': '/dev/char/195:255',    'timestamp': 152},
 ]}),
    ({'synth': [  # standalone writable tail
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 161},
 ]}, {'synth': [
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 161},
 ]}),
    ({'synth': [  # different single tail
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 170},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.tmp1234',   'timestamp': 171},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.tmp????}', 'timestamp': 170, 'path_diffs': [[(10, 21), '']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.tmp????}', 'timestamp': 171, 'path_diffs': [[(10, 21), '.tmp1234']]},
 ]}),
    ({'dconf': [  # real data, with diffs already present
{'timestamp': 18, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/etc/gdm{,3}/greeter.dconf-defaults',                 'mask': {'r'},           'path_diffs': [[(8, 12), '3']]},
{'timestamp': 19, 'comm': {'dconf'}, 'operation': {'mknod'},       'path': '/var/lib/gdm{,3}/greeter-dconf-defaults.SJYVD2',      'mask': {'c'},           'path_diffs': [[(12, 16), '3']]},
{'timestamp': 21, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/var/lib/gdm{,3}/greeter-dconf-defaults.SJYVD2',      'mask': {'w', 'r', 'c'}, 'path_diffs': [[(12, 16), '3']]},
{'timestamp': 25, 'comm': {'dconf'}, 'operation': {'rename_src'},  'path': '/var/lib/gdm{,3}/greeter-dconf-defaults.SJYVD2',      'mask': {'w', 'r', 'd'}, 'path_diffs': [[(12, 16), '3']]},
{'timestamp': 26, 'comm': {'dconf'}, 'operation': {'rename_dest'}, 'path': '/var/lib/gdm{,3}/greeter-dconf-defaults',             'mask': {'w', 'c'},      'path_diffs': [[(12, 16), '3']]},
 ]}, {'dconf': [
{'timestamp': 18, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/etc/gdm{,3}/greeter.dconf-defaults',                 'mask': {'r'},           'path_diffs': [[(8, 12), '3']]},
{'timestamp': 19, 'comm': {'dconf'}, 'operation': {'mknod'},       'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.??????}',   'mask': {'c'},           'path_diffs': [[(12, 16), '3'], [(39, 49), '.SJYVD2']]},
{'timestamp': 21, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.??????}',   'mask': {'w', 'r', 'c'}, 'path_diffs': [[(12, 16), '3'], [(39, 49), '.SJYVD2']]},
{'timestamp': 25, 'comm': {'dconf'}, 'operation': {'rename_src'},  'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.??????}',   'mask': {'w', 'r', 'd'}, 'path_diffs': [[(12, 16), '3'], [(39, 49), '.SJYVD2']]},
{'timestamp': 26, 'comm': {'dconf'}, 'operation': {'rename_dest'}, 'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.??????}',   'mask': {'w', 'c'},      'path_diffs': [[(12, 16), '3'], [(39, 49), '']]}
 ]}),
        )
        for inpt,result in fileLines_pairs:
            self.assertEqual(adaptTempPaths(inpt, 'default'), result)

    def test_adaptTempPaths_styled(self):
        fileLines_pairs = (
    ({'synth': [  # readonly tail
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 130},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 131},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 130},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 131},
 ]}),
    ({'synth': [  # readonly tail with writable neighbors
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 140},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 141},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 142},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.@{rand6}}', 'timestamp': 140, 'path_diffs': [[(10, 22), '']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.@{rand6}}', 'timestamp': 141, 'path_diffs': [[(10, 22), '.V6RK41']]},
{'operation': {'open'},        'comm': {'synth'}, 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 142},
 ]}),
    ({'synth': [  # standalone writable tail
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 161},
 ]}, {'synth': [
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41',    'timestamp': 161},
 ]}),
    ({'synth': [  # different single tail
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt',           'timestamp': 170},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.tmp1234',   'timestamp': 171},
 ]}, {'synth': [
{'operation': {'rename_dest'}, 'comm': {'synth'}, 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.tmp@{int}}', 'timestamp': 170, 'path_diffs': [[(10, 23), '']]},
{'operation': {'rename_src'},  'comm': {'synth'}, 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.tmp@{int}}', 'timestamp': 171, 'path_diffs': [[(10, 23), '.tmp1234']]},
 ]}),
    ({'dconf': [  # real data, with diffs already present; styled
{'timestamp': 18, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/etc/gdm{,3}/greeter.dconf-defaults',                 'mask': {'r'},           'path_diffs': [[(8, 12), '3']]},
{'timestamp': 19, 'comm': {'dconf'}, 'operation': {'mknod'},       'path': '/var/lib/gdm{,3}/greeter-dconf-defaults.SJYVD2',      'mask': {'c'},           'path_diffs': [[(12, 16), '3']]},
{'timestamp': 21, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/var/lib/gdm{,3}/greeter-dconf-defaults.SJYVD2',      'mask': {'w', 'r', 'c'}, 'path_diffs': [[(12, 16), '3']]},
{'timestamp': 25, 'comm': {'dconf'}, 'operation': {'rename_src'},  'path': '/var/lib/gdm{,3}/greeter-dconf-defaults.SJYVD2',      'mask': {'w', 'r', 'd'}, 'path_diffs': [[(12, 16), '3']]},
{'timestamp': 26, 'comm': {'dconf'}, 'operation': {'rename_dest'}, 'path': '/var/lib/gdm{,3}/greeter-dconf-defaults',             'mask': {'w', 'c'},      'path_diffs': [[(12, 16), '3']]},
 ]}, {'dconf': [
{'timestamp': 18, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/etc/gdm{,3}/greeter.dconf-defaults',                 'mask': {'r'},           'path_diffs': [[(8, 12), '3']]},
{'timestamp': 19, 'comm': {'dconf'}, 'operation': {'mknod'},       'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.@{rand6}}', 'mask': {'c'},           'path_diffs': [[(12, 16), '3'], [(39, 51), '.SJYVD2']]},
{'timestamp': 21, 'comm': {'dconf'}, 'operation': {'open'},        'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.@{rand6}}', 'mask': {'w', 'r', 'c'}, 'path_diffs': [[(12, 16), '3'], [(39, 51), '.SJYVD2']]},
{'timestamp': 25, 'comm': {'dconf'}, 'operation': {'rename_src'},  'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.@{rand6}}', 'mask': {'w', 'r', 'd'}, 'path_diffs': [[(12, 16), '3'], [(39, 51), '.SJYVD2']]},
{'timestamp': 26, 'comm': {'dconf'}, 'operation': {'rename_dest'}, 'path': '/var/lib/gdm{,3}/greeter-dconf-defaults{,.@{rand6}}', 'mask': {'w', 'c'},      'path_diffs': [[(12, 16), '3'], [(39, 51), '']]}
 ]}),
        )
        for inpt,result in fileLines_pairs:
            self.assertEqual(adaptTempPaths(inpt, 'AppArmor.d'), result)

class primaryFlow(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.logLines_duplicated_unnormalized_ungrouped = [
{'operation': 'rename_dest',  'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'wc',  'path': '/tmp/f.txt',        'timestamp': 139},  # write base
{'operation': 'rename_dest',  'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'wc',  'path': '/tmp/f.txt',        'timestamp': 140},  # exact duplicate
{'operation': 'open',         'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'r',   'path': '/tmp/f.txt',        'timestamp': 141},  # readonly base
{'operation': 'open',         'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'r',   'path': '/tmp/f.txt',        'timestamp': 142},  # exact duplicate
{'operation': 'mknod',        'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'c',   'path': '/tmp/f.txt.V6RK41', 'timestamp': 143},
{'operation': 'open',         'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'wrc', 'path': '/tmp/f.txt.V6RK41', 'timestamp': 144},
{'operation': 'rename_src',   'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'wrd', 'path': '/tmp/f.txt.V6RK41', 'timestamp': 145},  # write tails
{'operation': 'open',         'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'wrc', 'path': '/tmp/f.txt.K4TK9Q', 'timestamp': 146},  # second pair
{'operation': 'open',         'profile': 'tracker-miner', 'comm': 'tracker-miner-f', 'requested_mask': 'r',   'path': '/tmp/f.txt.ROTAIL', 'timestamp': 147},  # readonly pair
{'operation': 'unlink',       'profile': 'firefox',       'comm': 'firefox-bin',     'requested_mask': 'd',   'path': '/dev/char/195:255', 'timestamp': 170},
{'operation': 'dbus_signal',      'profile': 'tracker-miner',   'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'VolumeAdded',   'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 250},
{'operation': 'dbus_signal',      'profile': 'tracker-miner',   'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'VolumeChanged', 'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 251},
{'operation': 'dbus_signal',      'profile': 'tracker-miner',   'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'VolumeRemoved', 'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 252},
{'operation': 'dbus_method_call', 'profile': 'tracker-extract', 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'IsSupported',   'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 260},
{'operation': 'dbus_method_call', 'profile': 'tracker-extract', 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'List',          'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 261},
{'operation': 'dbus_method_call', 'profile': 'tracker-extract', 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'List',          'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 262},  # exact duplicate
{'operation': 'file_receive', 'profile': 'firefox', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 350},
{'operation': 'file_receive', 'profile': 'vlc',     'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 360},
{'operation': 'file_receive', 'profile': 'vlc',     'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 361},  # exact duplicate
        ]

        self.allLines_duplicated_unnormalized_profiled = {
    'tracker-miner': [
{'operation': 'rename_dest', 'comm': 'tracker-miner-f', 'requested_mask': 'wc',  'path': '/tmp/f.txt',        'timestamp': 139},  # write base
{'operation': 'rename_dest', 'comm': 'tracker-miner-f', 'requested_mask': 'wc',  'path': '/tmp/f.txt',        'timestamp': 140},  # exact duplicate
{'operation': 'open',        'comm': 'tracker-miner-f', 'requested_mask': 'r',   'path': '/tmp/f.txt',        'timestamp': 141},  # readonly base
{'operation': 'open',        'comm': 'tracker-miner-f', 'requested_mask': 'r',   'path': '/tmp/f.txt',        'timestamp': 142},  # exact duplicate
{'operation': 'mknod',       'comm': 'tracker-miner-f', 'requested_mask': 'c',   'path': '/tmp/f.txt.V6RK41', 'timestamp': 143},
{'operation': 'open',        'comm': 'tracker-miner-f', 'requested_mask': 'wrc', 'path': '/tmp/f.txt.V6RK41', 'timestamp': 144},
{'operation': 'rename_src',  'comm': 'tracker-miner-f', 'requested_mask': 'wrd', 'path': '/tmp/f.txt.V6RK41', 'timestamp': 145},  # write tails
{'operation': 'open',        'comm': 'tracker-miner-f', 'requested_mask': 'wrc', 'path': '/tmp/f.txt.K4TK9Q', 'timestamp': 146},  # second pair
{'operation': 'open',        'comm': 'tracker-miner-f', 'requested_mask': 'r',   'path': '/tmp/f.txt.ROTAIL', 'timestamp': 147},  # readonly pair
{'operation': 'dbus_signal',      'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'VolumeAdded',   'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 250},
{'operation': 'dbus_signal',      'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'VolumeChanged', 'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 251},
{'operation': 'dbus_signal',      'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'VolumeRemoved', 'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 252},
        ],
    'tracker-extract': [
{'operation': 'dbus_method_call', 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'IsSupported',   'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 260},
{'operation': 'dbus_method_call', 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'List',          'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 261},
{'operation': 'dbus_method_call', 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'List',          'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 262},  # exact duplicate
        ],
    'firefox': [
{'operation': 'unlink', 'path': '/dev/char/195:255', 'comm': 'firefox-bin', 'requested_mask': 'd', 'timestamp': 170},
{'operation': 'file_receive', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 350},
        ],
    'vlc': [
{'operation': 'file_receive', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 360},
{'operation': 'file_receive', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 361},  # exact duplicate
        ]}

        self.fileLines_duplicated_halfnormalized = {
    'tracker-miner': [
{'operation': {'rename_dest'}, 'comm': 'tracker-miner-f', 'mask': {'w', 'c'},      'path': '/tmp/f.txt',        'timestamp': 139},  # write base
{'operation': {'rename_dest'}, 'comm': 'tracker-miner-f', 'mask': {'w', 'c'},      'path': '/tmp/f.txt',        'timestamp': 140},  # exact duplicate
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'r'},           'path': '/tmp/f.txt',        'timestamp': 141},  # readonly base
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'r'},           'path': '/tmp/f.txt',        'timestamp': 142},  # exact duplicate
{'operation': {'mknod'},       'comm': 'tracker-miner-f', 'mask': {'c'},           'path': '/tmp/f.txt.V6RK41', 'timestamp': 143},
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'w', 'r', 'c'}, 'path': '/tmp/f.txt.V6RK41', 'timestamp': 144},
{'operation': {'rename_src'},  'comm': 'tracker-miner-f', 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt.V6RK41', 'timestamp': 145},  # write tails
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'w', 'r', 'c'}, 'path': '/tmp/f.txt.K4TK9Q', 'timestamp': 146},  # second pair
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL', 'timestamp': 147},  # readonly pair
        ],
    'firefox': [
{'operation': {'unlink'},      'comm': 'firefox-bin',     'mask': {'d'},           'path': '/dev/char/195:255', 'timestamp': 170}  # kept
        ]}

        self.fileLines_duplicated_tempnormalized = {
    'tracker-miner': [
{'operation': {'rename_dest'}, 'comm': 'tracker-miner-f', 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 139, 'path_diffs': [[(10, 20), '']]},  # write base
{'operation': {'rename_dest'}, 'comm': 'tracker-miner-f', 'mask': {'w', 'c'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 140, 'path_diffs': [[(10, 20), '']]},  # exact duplicate
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'c', 'r', 'w'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 141, 'path_diffs': [[(10, 20), '']]},  # normalized mask
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'c', 'r', 'w'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 142, 'path_diffs': [[(10, 20), '']]},  # normalized mask
{'operation': {'mknod'},       'comm': 'tracker-miner-f', 'mask': {'c'},           'path': '/tmp/f.txt{,.??????}', 'timestamp': 143, 'path_diffs': [[(10, 20), '.V6RK41']]},
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'w', 'r', 'c'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 144, 'path_diffs': [[(10, 20), '.V6RK41']]},
{'operation': {'rename_src'},  'comm': 'tracker-miner-f', 'mask': {'w', 'r', 'd'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 145, 'path_diffs': [[(10, 20), '.V6RK41']]},  # write tails
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'w', 'r', 'c'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 146, 'path_diffs': [[(10, 20), '.K4TK9Q']]},  # second pair
{'operation': {'open'},        'comm': 'tracker-miner-f', 'mask': {'r'},           'path': '/tmp/f.txt.ROTAIL',    'timestamp': 147},  # readonly pair
        ],
    'firefox': [
{'operation': {'unlink'},      'comm': 'firefox-bin',     'mask': {'d'},           'path': '/dev/char/195:255', 'timestamp': 170}  # kept
        ]}

        self.fileLines_masksAndOpers_merged = {
    'tracker-miner': [
{'operation': {'open', 'rename_dest'},         'comm': 'tracker-miner-f', 'mask': {'w', 'c', 'r'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 142, 'path_diffs': [[(10, 20), '']]},  # merged empty diffs
{'operation': {'open', 'mknod', 'rename_src'}, 'comm': 'tracker-miner-f', 'mask': {'w', 'c', 'r', 'd'}, 'path': '/tmp/f.txt{,.??????}', 'timestamp': 145, 'path_diffs': [[(10, 20), '.V6RK41']]},  # merged first diff
{'operation': {'open'},                        'comm': 'tracker-miner-f', 'mask': {'w', 'c', 'r'},      'path': '/tmp/f.txt{,.??????}', 'timestamp': 146, 'path_diffs': [[(10, 20), '.K4TK9Q']]},  # merged second diff
{'operation': {'open'},                        'comm': 'tracker-miner-f', 'mask': {'r'},                'path': '/tmp/f.txt.ROTAIL',    'timestamp': 147},  # readonly pair - NOT a temp tail
        ],
    'firefox': [
{'operation': {'unlink'},      'comm': 'firefox-bin',     'mask': {'d'},           'path': '/dev/char/195:255', 'timestamp': 170},  # kept
        ]}

#        self.otherLines_duplicated_halfnormalized = {
#    'firefox': [
#{'operation': 'file_receive', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 350},],
#    'vlc': [
#{'operation': 'file_receive', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 360},
#{'operation': 'file_receive', 'comm': 'Xorg', 'family': 'unix', 'sock_type': 'stream', 'protocol': '0', 'requested_mask': 'send receive', 'addr': 'none', 'peer_addr': 'none', 'peer': 'xorg', 'timestamp': 361},
#    ]}  # exact duplicate

    def test_groupLinesByProfile(self):
        self.assertEqual(groupLinesByProfile(self.logLines_duplicated_unnormalized_ungrouped), self.allLines_duplicated_unnormalized_profiled)

#    def test_normalizeAndGroup(self):
#        self.assertEqual(normalizeAndGroup(self.allLines_duplicated_unnormalized_profiled),
#                                          (self.fileLines_duplicated_halfnormalized,
#                                           self.dbusLines_duplicated_halfnormalized,
#                                           self.otherLines_duplicated_halfnormalized))

    def test_adaptTempPaths(self):
        self.assertEqual(adaptTempPaths(self.fileLines_duplicated_halfnormalized, 'default'), self.fileLines_duplicated_tempnormalized)

    def test_mergeDictsByKeyPair_tempTails(self):
        self.assertEqual(mergeDictsByKeyPair(self.fileLines_duplicated_tempnormalized, 'mask', 'operation'), self.fileLines_masksAndOpers_merged)
        non_normalizedPair = {
    'firefox': [
{'operation': 'unlink', 'comm': 'firefox-bin', 'mask': 'd', 'path': '/dev/char/195:255', 'timestamp': 170}
    ]}
        self.assertRaises(NotImplementedError, mergeDictsByKeyPair, non_normalizedPair, 'mask', 'operation')

class mergeTests(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_mergeDictsBySingleKey(self):
        dbusLines_duplicated = {
    'tracker-miner': [
{'operation': {'dbus_signal'},      'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'VolumeAdded'},   'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 250},
{'operation': {'dbus_signal'},      'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'VolumeChanged'}, 'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 251},
{'operation': {'dbus_signal'},      'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'VolumeRemoved'}, 'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 252},
{'bus': 'session', 'name': 'org.gnome.ArchiveManager1', 'mask': 'bind', 'timestamp': 350, 'operation': {'dbus_bind'}},
    ],
    'tracker-extract': [
{'operation': {'dbus_method_call'}, 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'IsSupported'},   'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 260},
{'operation': {'dbus_method_call'}, 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'List'},          'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 261},
{'operation': {'dbus_method_call'}, 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'List'},          'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 262},  # exact duplicate
    ]}
        dbusLines_merged = {
    'tracker-miner': [
{'bus': 'session', 'name': 'org.gnome.ArchiveManager1', 'mask': 'bind', 'timestamp': 350, 'operation': {'dbus_bind'}},  # preserve unaffected
{'operation': {'dbus_signal'},      'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'VolumeAdded', 'VolumeChanged', 'VolumeRemoved'}, 'name': ':[0-9]*', 'mask': 'receive', 'peer': 'unconfined', 'timestamp': 252},
    ],
    'tracker-extract': [
{'operation': {'dbus_method_call'}, 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': {'IsSupported', 'List'},                           'name': ':[0-9]*', 'mask': 'send',    'peer': 'unconfined', 'timestamp': 262},
    ]}
        self.assertEqual(mergeDictsBySingleKey(dbusLines_duplicated, 'member'), dbusLines_merged)

        non_normalizedSingle = {
    'tracker-extract': [
{'operation': {'dbus_method_call'}, 'bus': 'session', 'path': '/org/gtk/Private/RemoteVolumeMonitor', 'interface': 'org.gtk.Private.RemoteVolumeMonitor', 'member': 'IsSupported', 'name': ':[0-9]*', 'mask': 'send', 'peer': 'unconfined', 'timestamp': 262},
    ]}
        self.assertRaises(NotImplementedError, mergeDictsBySingleKey, non_normalizedSingle, 'member')

        signals_input1   = {'update-manager': [
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'}, 'signal': {'int'},         'peer': 'apt-methods-http', 'timestamp': 101},
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'}, 'signal': {'term'},        'peer': 'apt-methods-http', 'timestamp': 102},
{'requested_mask': 'receive', 'comm': {'update-manager'}, 'operation': {'signal'}, 'signal': {'hup'},         'peer': 'apt-methods-http', 'timestamp': 103},
{'requested_mask': 'send',    'comm': {'synth'},          'operation': {'signal'}, 'signal': {'int'},         'peer': 'synth',            'timestamp': 104},
{'requested_mask': 'send',    'comm': {'synth'},          'operation': {'signal'}, 'signal': {'term'},        'peer': 'synth',            'timestamp': 105},
{'requested_mask': 'send',    'comm': {'synth'},          'operation': {'signal'}, 'signal': {'hup'},         'peer': 'synth',            'timestamp': 106},
  ],              'synth': [
{'requested_mask': 'send',    'comm': {'keep-me'},        'operation': {'signal'}, 'signal': {'int'},         'peer': 'synth-peer',       'timestamp': 107},
  ]}
        signals_result1 = {'update-manager': [
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'}, 'signal': {'int', 'term'}, 'peer': 'apt-methods-http', 'timestamp': 102},
{'requested_mask': 'receive', 'comm': {'update-manager'}, 'operation': {'signal'}, 'signal': {'hup'},         'peer': 'apt-methods-http', 'timestamp': 103},  # preserve unaffected
{'requested_mask': 'send',    'comm': {'synth'},          'operation': {'signal'}, 'signal': {'int', 'term', 'hup'}, 'peer': 'synth',     'timestamp': 106},
  ],              'synth': [
{'requested_mask': 'send',    'comm': {'keep-me'},        'operation': {'signal'}, 'signal': {'int'},         'peer': 'synth-peer',       'timestamp': 107},  # preserve unaffected
  ]}
        self.assertEqual(mergeDictsBySingleKey(signals_input1, 'signal'), signals_result1)

        signals_input2   = {'update-manager': [
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'}, 'signal': {'int'},         'peer': 'apt-methods-http', 'timestamp': 101},
  ]}
        signals_result2 = {'update-manager': [
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'}, 'signal': {'int'},         'peer': 'apt-methods-http', 'timestamp': 101},
  ]}
        self.assertEqual(mergeDictsBySingleKey(signals_input2, 'signal'), signals_result2)  # not affected

        file_inherit_input1   = {'update-manager': [
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'},       'signal': {'int'},         'peer': 'apt-methods-http', 'timestamp': 101},
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'file_inherit'}, 'signal': {'term'},        'peer': 'apt-methods-http', 'timestamp': 102},
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'},       'signal': {'hup'},         'peer': 'apt-methods-http', 'timestamp': 103},
  ],              'synth': [
{'requested_mask': 'send',    'comm': {'keep-me'},        'operation': {'signal'},       'signal': {'int'},         'peer': 'synth-peer',       'timestamp': 107},
  ]}
        file_inherit_result1 = {'update-manager': [
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'file_inherit'}, 'signal': {'term'},        'peer': 'apt-methods-http', 'timestamp': 102},
{'requested_mask': 'send',    'comm': {'update-manager'}, 'operation': {'signal'},       'signal': {'int', 'hup'},  'peer': 'apt-methods-http', 'timestamp': 103},
  ],              'synth': [
{'requested_mask': 'send',    'comm': {'keep-me'},        'operation': {'signal'},       'signal': {'int'},         'peer': 'synth-peer',       'timestamp': 107},  # preserve unaffected
  ]}
        self.assertEqual(mergeDictsBySingleKey(file_inherit_input1, 'signal'), file_inherit_result1)


    def test_mergeDictsByKeyPair(self):
        linePairs = (
    ({'gnome-shell': [
{'family': 'netlink', 'sock_type': 'raw', 'timestamp': 141, 'comm': {'gnome-shell'}, 'operation': {'create'},      'mask': {'create'}},
{'family': 'netlink', 'sock_type': 'raw', 'timestamp': 142, 'comm': {'gnome-shell'}, 'operation': {'setsockopt'},  'mask': {'setopt'}},
{'family': 'netlink', 'sock_type': 'raw', 'timestamp': 143, 'comm': {'gnome-shell'}, 'operation': {'bind'},        'mask': {'bind'}},
{'family': 'netlink', 'sock_type': 'raw', 'timestamp': 144, 'comm': {'gnome-shell'}, 'operation': {'getsockname'}, 'mask': {'getattr'}},
{'family': 'netlink', 'sock_type': 'raw', 'timestamp': 968, 'comm': {'gnome-shell'}, 'operation': {'recvmsg'},     'mask': {'receive'}},
 ]}, {'gnome-shell': [
{'family': 'netlink', 'sock_type': 'raw', 'comm': {'gnome-shell'}, 'timestamp': 968, 'mask': {'create', 'setopt', 'bind', 'receive', 'getattr'}, 'operation': {'create', 'bind', 'setsockopt', 'getsockname', 'recvmsg'}},
 ]}),
    ({'NetworkManager': [
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 0,  'comm': {'NetworkManager'}, 'operation': {'create'},      'mask': {'create'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 1,  'comm': {'NetworkManager'}, 'operation': {'getsockopt'},  'mask': {'getopt'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 2,  'comm': {'NetworkManager'}, 'operation': {'setsockopt'},  'mask': {'setopt'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 3,  'comm': {'NetworkManager'}, 'operation': {'bind'},        'mask': {'bind'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 4,  'comm': {'NetworkManager'}, 'operation': {'getsockname'}, 'mask': {'getattr'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 5,  'comm': {'NetworkManager'}, 'operation': {'create'},      'mask': {'create'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 6,  'comm': {'NetworkManager'}, 'operation': {'setsockopt'},  'mask': {'setopt'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 7,  'comm': {'NetworkManager'}, 'operation': {'bind'},        'mask': {'bind'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 8,  'comm': {'NetworkManager'}, 'operation': {'getsockname'}, 'mask': {'getattr'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 9,  'comm': {'NetworkManager'}, 'operation': {'create'},      'mask': {'create'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 10, 'comm': {'NetworkManager'}, 'operation': {'setsockopt'},  'mask': {'setopt'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 11, 'comm': {'NetworkManager'}, 'operation': {'bind'},        'mask': {'bind'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 12, 'comm': {'NetworkManager'}, 'operation': {'getsockname'}, 'mask': {'getattr'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 13, 'comm': {'NetworkManager'}, 'operation': {'recvmsg'},     'mask': {'receive'}}, 
{'family': 'netlink', 'sock_type': 'raw',   'timestamp': 14, 'comm': {'NetworkManager'}, 'operation': {'sendmsg'},     'mask': {'send'}}, 
{'family': 'inet',    'sock_type': 'dgram', 'timestamp': 15, 'comm': {'NetworkManager'}, 'operation': {'create'},      'mask': {'create'}},
 ]}, {'NetworkManager': [
{'family': 'netlink', 'sock_type': 'raw',   'comm': {'NetworkManager'}, 'timestamp': 14, 'mask': {'send', 'bind', 'getattr', 'receive', 'getopt', 'setopt', 'create'}, 'operation': {'bind', 'sendmsg', 'recvmsg', 'getsockopt', 'getsockname', 'setsockopt', 'create'}}, 
{'family': 'inet',    'sock_type': 'dgram', 'comm': {'NetworkManager'}, 'timestamp': 15, 'mask': {'create'}, 'operation': {'create'}},  # kept
 ]}),
    ({'update-desktop-database': [
{'timestamp': 1274, 'comm': {'update-desktop-'}, 'operation': {'rename_dest'}, 'path': '/usr/share/applications/mimeinfo.cache',         'mask': {'w', 'c'}},
{'timestamp': 1275, 'comm': {'update-desktop-'}, 'operation': {'mknod'},       'path': '/usr/share/applications/.mimeinfo.cache.WQKRE2', 'mask': {'c'}},
{'timestamp': 1276, 'comm': {'update-desktop-'}, 'operation': {'open'},        'path': '/usr/share/applications/.mimeinfo.cache.WQKRE2', 'mask': {'c', 'w', 'r'}},
{'timestamp': 1277, 'comm': {'update-desktop-'}, 'operation': {'chmod'},       'path': '/usr/share/applications/.mimeinfo.cache.WQKRE2', 'mask': {'w'}},
{'timestamp': 1278, 'comm': {'update-desktop-'}, 'operation': {'rename_src'},  'path': '/usr/share/applications/.mimeinfo.cache.WQKRE2', 'mask': {'w', 'd', 'r'}},
{'timestamp': 1280, 'comm': {'update-desktop-'}, 'operation': {'mknod'},       'path': '/usr/share/applications/.mimeinfo.cache.UKFKE2', 'mask': {'c'}},
{'timestamp': 1281, 'comm': {'update-desktop-'}, 'operation': {'open'},        'path': '/usr/share/applications/.mimeinfo.cache.UKFKE2', 'mask': {'c', 'w', 'r'}},
{'timestamp': 1282, 'comm': {'update-desktop-'}, 'operation': {'chmod'},       'path': '/usr/share/applications/.mimeinfo.cache.UKFKE2', 'mask': {'w'}},
{'timestamp': 1283, 'comm': {'update-desktop-'}, 'operation': {'rename_src'},  'path': '/usr/share/applications/.mimeinfo.cache.UKFKE2', 'mask': {'w', 'd', 'r'}},
 ]}, {'update-desktop-database': [
{'comm': {'update-desktop-'}, 'path': '/usr/share/applications/mimeinfo.cache',         'timestamp': 1274, 'mask': {'w', 'c'},           'operation': {'rename_dest'}},  # kept
{'comm': {'update-desktop-'}, 'path': '/usr/share/applications/.mimeinfo.cache.WQKRE2', 'timestamp': 1278, 'mask': {'w', 'c', 'r', 'd'}, 'operation': {'chmod', 'rename_src', 'open', 'mknod'}},
{'comm': {'update-desktop-'}, 'path': '/usr/share/applications/.mimeinfo.cache.UKFKE2', 'timestamp': 1283, 'mask': {'w', 'c', 'r', 'd'}, 'operation': {'chmod', 'rename_src', 'open', 'mknod'}},
 ]}),
        )
        for inpt,result in linePairs:
            self.assertEqual(mergeDictsByKeyPair(inpt, 'mask', 'operation'), result)

        fileDifferentComms_normalized = {'aa_suggest': [
{'comm': 'python2', 'mask': {'c'}, 'path': '/tmp/synthetic0', 'timestamp': 1, 'operation': {'mknod'}},
{'comm': 'python3', 'mask': {'c'}, 'path': '/tmp/synthetic0', 'timestamp': 2, 'operation': {'mknod'}},
        ]}
        beforePossibleChangeComms = copy.deepcopy(fileDifferentComms_normalized)
        self.assertEqual(mergeDictsByKeyPair(fileDifferentComms_normalized, 'mask', 'operation'), beforePossibleChangeComms)

        file_inherit_input1   = {'tracker-miner': [
{'operation': {'rename_dest'},         'comm': 'tracker-miner-f', 'mask': {'w', 'c'},      'path': '/tmp/f.txt', 'timestamp': 1},
{'operation': {'file_inherit'},        'comm': 'tracker-miner-f', 'mask': {'w', 'd'},      'path': '/tmp/f.txt', 'timestamp': 2},
{'operation': {'open'},                'comm': 'tracker-miner-f', 'mask': {'r'},           'path': '/tmp/f.txt', 'timestamp': 3},
  ],              'synth': [
{'requested_mask': 'send',    'comm': {'keep-me'},        'operation': {'signal'}, 'signal': {'int'},         'peer': 'synth-peer',       'timestamp': 107},
  ]}
        file_inherit_result1 = {'tracker-miner': [
{'operation': {'file_inherit'},        'comm': 'tracker-miner-f', 'mask': {'w', 'd'},      'path': '/tmp/f.txt', 'timestamp': 2},
{'operation': {'open', 'rename_dest'}, 'comm': 'tracker-miner-f', 'mask': {'r', 'w', 'c'}, 'path': '/tmp/f.txt', 'timestamp': 3},
  ],              'synth': [
{'requested_mask': 'send',    'comm': {'keep-me'},        'operation': {'signal'}, 'signal': {'int'},         'peer': 'synth-peer',       'timestamp': 107},  # preserve unaffected
  ]}
        self.assertEqual(mergeDictsByKeyPair(file_inherit_input1, 'mask', 'operation'), file_inherit_result1)

    def test_mergeCommMasks(self):
        blu = '\x1b[0;34m'
        rst = '\x1b[0m'
        inpt   = {'apt': [
{'comm': {'sh'},                         'path': '@{bin}/touch', 'path_diffs': [[(0, 6), '/usr/bin']], 'timestamp': 10, 'mask': {'x'},      'operation': {'exec'}},
{'comm': {f'{blu}touch{rst}'}, 'path': '@{bin}/touch', 'path_diffs': [[(0, 6), '/usr/bin']], 'timestamp': 11, 'mask': {'r', 'i'}, 'operation': {'file_mmap'}},  # previously hinted ix
  ],              'xrdb': [
{'path': '/etc/X11/Xresources/x11-common', 'timestamp': 13, 'mask': {'r'}, 'operation': {'open'}, 'comm': {'xrdb', 'cc1'}},
  ]}
        result = {'apt': [
{'path': '@{bin}/touch', 'path_diffs': [[(0, 6), '/usr/bin']], 'timestamp': 11, 'operation': {'file_mmap', 'exec'}, 'comm': {'sh', f'{blu}touch{rst}'}, 'mask': {'x', 'r', 'i'}, 'transition_mask': {'r', 'i'}},
  ],              'xrdb': [
{'path': '/etc/X11/Xresources/x11-common', 'timestamp': 13, 'mask': {'r'}, 'operation': {'open'}, 'comm': {'xrdb', 'cc1'}},
  ]}
        self.assertEqual(mergeCommMasks(inpt), result)

        inpt2   = {'apt': [
{'comm': {f'{blu}touch{rst}'}, 'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 20, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}},
{'comm': {f'{blu}test{rst}'},  'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 21, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}},
{'comm': {f'{blu}echo{rst}'},  'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 22, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}},
{'comm': {'synth'},            'path': '/var/lib/command-not-found/', 'timestamp': 23, 'mask': {'r'}, 'operation': {'getattr'}},
  ],
                   'run-parts//motd': [
{'trust': 10, 'comm': {f'{blu}wc{rst}'},   'path': '/var/lib/unattended-upgrades/kept-back', 'timestamp': 40, 'mask': {'r'}, 'operation': {'file_inherit'}},
{'trust': 10, 'comm': {'update-motd-una'}, 'path': '/var/lib/unattended-upgrades/kept-back', 'timestamp': 41, 'mask': {'r'}, 'operation': {'open'}},
{'trust': 10, 'comm': {'update-motd-una'}, 'path': '/{,usr/}bin/wc',                         'timestamp': 42, 'mask': {'x'}, 'operation': {'exec'}, 'path_diffs': [[(1, 8), 'usr/']]},
{'trust': 10,                              'path': '/tmp/synth',                             'timestamp': 43, 'mask': {'r'}, 'operation': {'open'}},
{'trust': 10, 'comm': {'im-launch'},       'path': '/{,usr/}bin/dash', 'path_diffs': [[(1, 8), 'usr/']], 'timestamp': 44, 'mask': {'r'}, 'operation': {'file_mmap'}},
{'trust': 10, 'comm': {f'{blu}env{rst}'},  'path': '/{,usr/}bin/dash', 'path_diffs': [[(1, 8), 'usr/']], 'timestamp': 45, 'mask': {'x'}, 'operation': {'exec'}},
  ]}
        result2 = {'apt': [
{'comm': {f'{blu}touch{rst}'}, 'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 20, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}, 'transition_mask': {'r', 'w'}},
{'comm': {f'{blu}test{rst}'},  'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 21, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}, 'transition_mask': {'r', 'w'}},
{'comm': {f'{blu}echo{rst}'},  'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 22, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}, 'transition_mask': {'r', 'w'}},
{'comm': {'synth'},            'path': '/var/lib/command-not-found/', 'timestamp': 23, 'mask': {'r'}, 'operation': {'getattr'}},  # preserve unaffected
  ],
                   'run-parts//motd': [
{'trust': 10, 'comm': {f'{blu}wc{rst}'},   'path': '/var/lib/unattended-upgrades/kept-back', 'timestamp': 40, 'mask': {'r'}, 'operation': {'file_inherit'}, 'transition_mask': {'r'}},  # skipped because of 'file_inherit', but postcolorization was still assigned
{'trust': 10,                              'path': '/tmp/synth',                             'timestamp': 43, 'mask': {'r'}, 'operation': {'open'}},  # keep non-mergable
{'trust': 10, 'comm': {'update-motd-una'}, 'path': '/var/lib/unattended-upgrades/kept-back', 'timestamp': 41, 'mask': {'r'}, 'operation': {'open'}},
{'trust': 10, 'comm': {'update-motd-una'}, 'path': '/{,usr/}bin/wc',                         'timestamp': 42, 'mask': {'x'}, 'operation': {'exec'}, 'path_diffs': [[(1, 8), 'usr/']]},
{'trust': 10, 'comm': {'im-launch', f'{blu}env{rst}'}, 'path': '/{,usr/}bin/dash', 'path_diffs': [[(1, 8), 'usr/']], 'timestamp': 45, 'mask': {'r', 'x'}, 'operation': {'exec', 'file_mmap'}, 'transition_mask': {'x'}},
  ]}
        self.assertEqual(mergeCommMasks(inpt2), result2)

         # Merge file_inherit with itself; TODO
#        inpt2   = {'apt': [
#{'comm': {f'{blu}touch{rst}'}, 'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 20, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}},
#{'comm': {f'{blu}test{rst}'},  'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 21, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}},
#{'comm': {f'{blu}echo{rst}'},  'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 22, 'mask': {'w', 'r'}, 'operation': {'file_inherit'}},
#{'comm': {'synth'}, 'path': '/var/lib/command-not-found/', 'timestamp': 23, 'mask': {'r'}, 'operation': {'getattr'}},
#  ]}
#        result2 = {'apt': [
#{'path': '/dev/pts/@{int}', 'path_diffs': [[(9, 15), '0']], 'path_prefix': 'owner', 'timestamp': 22, 'operation': {'file_inherit'}, 'comm': {f'{blu}touch{rst}', f'{blu}test{rst}', f'{blu}echo{rst}'}, 'mask': {'w', 'r'}, 'transition_mask': {'w', 'r'}},
#{'comm': {'synth'}, 'path': '/var/lib/command-not-found/', 'timestamp': 23, 'mask': {'r'}, 'operation': {'getattr'}},  # preserve unaffected
#  ]}
#        self.assertEqual(mergeCommMasks(inpt2), result2)

    def test_mergeLinkMasks(self):
        inpt   = {'vlc': [
{'path': '@{user_config_dirs}/vlc/#@{int}',                        'path_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']],   'path_prefix': 'owner', 'mask': {'w', 'r'},                'operation': {'open', 'chmod'}, 'timestamp': 0},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.lock',     'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w', 'd', 'k'}, 'operation': {'open', 'file_lock', 'unlink', 'mknod'}, 'timestamp': 1},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf',          'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w'},           'operation': {'open', 'rename_dest'}, 'timestamp': 2},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(46, 54), 'QowpDu']],   'path_prefix': 'owner', 'mask': {'l'},                     'operation': {'link'}, 'target': '@{user_config_dirs}/vlc/#@{int}', 'target_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']], 'target_prefix': 'owner', 'timestamp': 3},  # merge subject 1
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(46, 54), 'QowpDu']],   'path_prefix': 'owner', 'mask': {'r', 'd', 'w'},           'operation': {'rename_src'}, 'timestamp': 4},  # merge subject 1
{'path': '/tmp/f', 'mask': {'l'},           'operation': {'link'},       'comm': {'synth'}, 'target': '/tmp/1234', 'timestamp': 5},  # merge subject 2
{'path': '/tmp/f', 'mask': {'r', 'd', 'w'}, 'operation': {'rename_src'}, 'comm': {'synth'}, 'timestamp': 6},  # merge subject 2
{'path': '/dev/shm/f', 'mask': {'r'}, 'operation': {'open'}, 'comm': {'synth'}, 'timestamp': 7},  # preserve unaffected
  ],              'qbittorrent': [
{'path': '@{user_config_dirs}/qBittorrent/qBittorrent-data.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(54, 62), 'BcLDls']], 'path_prefix': 'owner', 'mask': {'l'},               'operation': {'link'}, 'target': '@{user_config_dirs}/qBittorrent/#@{int}', 'comm': {'qbittorrent'}, 'target_diffs': [[(0, 19), '/home/user/.config'], [(33, 39), '667638']], 'target_prefix': 'owner', 'timestamp': 7},  # merge subject 3
{'path': '@{user_config_dirs}/qBittorrent/qBittorrent-data.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(54, 62), 'BcLDls']], 'path_prefix': 'owner', 'mask': {'r', 'd', 'w'},     'operation': {'rename_src'}, 'comm': {'qbittorrent'}, 'timestamp': 8},  # merge subject 3
  ],              'xrdb': [
{'path': '/etc/X11/Xresources/x11-common', 'timestamp': 11, 'mask': {'r'}, 'operation': {'open'}, 'comm': {'xrdb', 'cc1'}},
  ]}
        result = {'vlc': [
{'path': '@{user_config_dirs}/vlc/#@{int}',                        'path_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']],   'path_prefix': 'owner', 'mask': {'w', 'r'},                'operation': {'open', 'chmod'}, 'timestamp': 0},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.lock',     'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w', 'd', 'k'}, 'operation': {'open', 'file_lock', 'unlink', 'mknod'}, 'timestamp': 1},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf',          'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w'},           'operation': {'open', 'rename_dest'}, 'timestamp': 2},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(46, 54), 'QowpDu']],   'path_prefix': 'owner', 'mask': {'l', 'w', 'd', 'r'},      'operation': {'link', 'rename_src'}, 'target': '@{user_config_dirs}/vlc/#@{int}', 'target_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']], 'target_prefix': 'owner', 'timestamp': 4},  # merged 1
{'path': '/tmp/f', 'mask': {'l', 'r', 'd', 'w'}, 'operation': {'link', 'rename_src'}, 'comm': {'synth'}, 'target': '/tmp/1234', 'timestamp': 6},  # merged 2
{'path': '/dev/shm/f', 'mask': {'r'}, 'operation': {'open'}, 'comm': {'synth'}, 'timestamp': 7},  # preserve unaffected
  ],              'qbittorrent': [
{'path': '@{user_config_dirs}/qBittorrent/qBittorrent-data.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(54, 62), 'BcLDls']], 'path_prefix': 'owner', 'mask': {'l', 'r', 'd', 'w'},'operation': {'link', 'rename_src'}, 'target': '@{user_config_dirs}/qBittorrent/#@{int}', 'target_diffs': [[(0, 19), '/home/user/.config'], [(33, 39), '667638']], 'target_prefix': 'owner', 'comm': {'qbittorrent'}, 'timestamp': 8},  # merged 3
  ],              'xrdb': [
{'path': '/etc/X11/Xresources/x11-common', 'timestamp': 11, 'mask': {'r'}, 'operation': {'open'}, 'comm': {'xrdb', 'cc1'}},
  ]}
        self.assertEqual(mergeLinkMasks(inpt), result)

        file_inherit_inpt   = {'vlc': [
{'path': '@{user_config_dirs}/vlc/#@{int}',                        'path_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']],   'path_prefix': 'owner', 'mask': {'w', 'r'},                'operation': {'open', 'chmod'}, 'timestamp': 0},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.lock',     'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w', 'd', 'k'}, 'operation': {'open', 'file_lock', 'unlink', 'mknod'}, 'timestamp': 1},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf',          'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w'},           'operation': {'open', 'rename_dest'}, 'timestamp': 2},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(46, 54), 'QowpDu']],   'path_prefix': 'owner', 'mask': {'l'},                     'operation': {'link'}, 'target': '@{user_config_dirs}/vlc/#@{int}', 'target_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']], 'target_prefix': 'owner', 'timestamp': 3},  # merge subject 1
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(46, 54), 'QowpDu']],   'path_prefix': 'owner', 'mask': {'r', 'd', 'w'},           'operation': {'rename_src'}, 'timestamp': 4},  # merge subject 1
{'path': '/tmp/f', 'mask': {'l'},           'operation': {'link'},         'comm': {'synth'}, 'target': '/tmp/1234', 'timestamp': 5},  # invalid merge subject 2
{'path': '/tmp/f', 'mask': {'r', 'd', 'w'}, 'operation': {'file_inherit'}, 'comm': {'synth'}, 'timestamp': 6},  # invalid merge subject 2
{'path': '/dev/shm/f', 'mask': {'r'}, 'operation': {'open'}, 'comm': {'synth'}, 'timestamp': 7},  # preserve unaffected
  ],              'xrdb': [
{'path': '/etc/X11/Xresources/x11-common', 'timestamp': 11, 'mask': {'r'}, 'operation': {'open'}, 'comm': {'xrdb', 'cc1'}},
  ]}
        file_inherit_result = {'vlc': [
{'path': '@{user_config_dirs}/vlc/#@{int}',                        'path_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']],   'path_prefix': 'owner', 'mask': {'w', 'r'},                'operation': {'open', 'chmod'}, 'timestamp': 0},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.lock',     'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w', 'd', 'k'}, 'operation': {'open', 'file_lock', 'unlink', 'mknod'}, 'timestamp': 1},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf',          'path_diffs': [[(0, 19), '/home/user/.config']],                         'path_prefix': 'owner', 'mask': {'c', 'r', 'w'},           'operation': {'open', 'rename_dest'}, 'timestamp': 2},
{'path': '@{user_config_dirs}/vlc/vlc-qt-interface.conf.@{rand6}', 'path_diffs': [[(0, 19), '/home/user/.config'], [(46, 54), 'QowpDu']],   'path_prefix': 'owner', 'mask': {'l', 'w', 'd', 'r'},      'operation': {'link', 'rename_src'}, 'target': '@{user_config_dirs}/vlc/#@{int}', 'target_diffs': [[(0, 19), '/home/user/.config'], [(25, 31), '667142']], 'target_prefix': 'owner', 'timestamp': 4},  # merged 1
{'path': '/tmp/f', 'mask': {'l'},           'operation': {'link'},         'comm': {'synth'}, 'target': '/tmp/1234', 'timestamp': 5},  # invalid merge subject 2
{'path': '/tmp/f', 'mask': {'r', 'd', 'w'}, 'operation': {'file_inherit'}, 'comm': {'synth'}, 'timestamp': 6},  # invalid merge subject 2
{'path': '/dev/shm/f', 'mask': {'r'}, 'operation': {'open'}, 'comm': {'synth'}, 'timestamp': 7},  # preserve unaffected
  ],              'xrdb': [
{'path': '/etc/X11/Xresources/x11-common', 'timestamp': 11, 'mask': {'r'}, 'operation': {'open'}, 'comm': {'xrdb', 'cc1'}},
  ]}
        self.assertEqual(mergeLinkMasks(file_inherit_inpt), file_inherit_result)

    def test_mergeExactDuplicates(self):
        inpt = {'gnome-calculator-search-provider': [
{'bus': 'session', 'name': 'org.gnome.Calculator.SearchProvider', 'mask': 'bind', 'operation': {'dbus_bind'}, 'timestamp': 1},
{'bus': 'session', 'name': 'org.gnome.Calculator.SearchProvider', 'mask': 'bind', 'operation': {'dbus_bind'}, 'timestamp': 2},
{'bus': 'session', 'name': 'org.gnome.Calculator.SearchProvider', 'mask': 'bind', 'operation': {'dbus_bind'}, 'timestamp': 3},
{'capname': 'sys_admin',    'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 4},
{'capname': 'sys_admin',    'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 5},
{'capname': 'sys_resource', 'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 6},
{'bus': 'session', 'path': '/org/gtk/Settings', 'interface': 'org.freedesktop.DBus.Properties', 'mask': 'send', 'name': ':1.[0-9]*', 'peer': 'gsd-xsettings', 'operation': {'dbus_method_call'}, 'timestamp': 7, 'member': 'GetAll'},
],              'xdg-document-portal': [
{'capname': 'sys_admin',    'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 11},
{'capname': 'sys_resource', 'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 12},
{'capname': 'sys_resource', 'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 13},
]}
        result = {'gnome-calculator-search-provider': [
{'bus': 'session', 'name': 'org.gnome.Calculator.SearchProvider', 'mask': 'bind', 'operation': {'dbus_bind'}, 'timestamp': 3},
{'capname': 'sys_admin',    'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 5},
{'capname': 'sys_resource', 'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 6},
{'bus': 'session', 'path': '/org/gtk/Settings', 'interface': 'org.freedesktop.DBus.Properties', 'mask': 'send', 'name': ':1.[0-9]*', 'peer': 'gsd-xsettings', 'operation': {'dbus_method_call'}, 'timestamp': 7, 'member': 'GetAll'},
],              'xdg-document-portal': [
{'capname': 'sys_admin',    'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 11},
{'capname': 'sys_resource', 'comm': {'fuse mainloop'}, 'operation': {'capable'}, 'timestamp': 13},
]}
        self.assertEqual(mergeExactDuplicates(inpt), result)

class abstractionsTests(unittest.TestCase):
    '''Match = hide'''
    def setUp(self):
        self.blu = '\x1b[0;34m'
        self.rst = '\x1b[0m'
        self.baseAbs = (
{'path': '/dev/log', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/dev/random', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/dev/urandom', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/run/uuidd/request', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/locale/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/locale/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/locale.alias', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/localtime', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/writable/localtime', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/locale-bundle/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/locale-bundle/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/locale-langpack/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/locale-langpack/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/locale/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/locale/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/d/locale/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/d/locale/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/d/d/locale/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/zoneinfo/', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/zoneinfo/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/zoneinfo/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/X11/locale/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/X11/locale/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/run/systemd/journal/dev-log', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/run/systemd/journal/socket', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/run/systemd/journal/stdout', 'mask': {'r', 'w'}, 'comm': {'syn'}},
{'path': '/usr/lib/locale/f', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/locale/f', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/locale/d/f', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/gconv/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/gconv/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/gconv/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/gconv/gconv-modules', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/gconv/gconv-modules.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/gconv/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/gconv/gconv-modules', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/etc/bindresvport.blacklist', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.cache', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf.d/', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf.d/f.conf', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.preload', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/lib/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/d/d/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/ld32-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/ld64-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/ld64-f.so.2', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/arm-linux-gnueabihf/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/aarch64-linux-gnu/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/d/d/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/d/d/ld-f.so.2', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/x86_64-linux-gnu/ld32-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/x86_64-linux-gnu/ld64-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/tls/i686/cmov/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/tls/i686/nosegneg/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/tls/i686/nosegneg/ld-f.so.2', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/i386-linux-gnu/tls/i686/cmov/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/i386-linux-gnu/tls/i686/nosegneg/ld-f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/i386-linux-gnu/tls/i686/nosegneg/ld-f.so.2', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/opt/f-linux-uclibc/lib/ld-uClibcso', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/opt/f-linux-uclibc/lib/ld-uClibcF.soF', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/lib/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/d/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/d/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/lib/x86_64-linux-gnu/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/x86_64-linux-gnu/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/x86_64-linux-gnu/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/d/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/x86_64-linux-gnu/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/x86_64-linux-gnu/d/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/tls/i686/cmov/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/tls/i686/nosegneg/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/tls/i686/nosegneg/f.so.1', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/i386-linux-gnu/tls/i686/cmov/f.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/i386-linux-gnu/tls/i686/nosegneg/.so', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/i386-linux-gnu/tls/i686/nosegneg/.so.2', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/lib/.lib.so.hmac', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/.lib.so.hmac', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib32/.libF.soF.hmac', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib64/.libF.soF.hmac', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/.lib.so.hmac', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/.libF.soF.hmac', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/dev/null', 'mask': {'r', 'w'}, 'comm': {'syn'}},
{'path': '/dev/zero', 'mask': {'r', 'w'}, 'comm': {'syn'}},
{'path': '/dev/full', 'mask': {'r', 'w'}, 'comm': {'syn'}},
{'path': '/proc/sys/kernel/version', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/sys/kernel/ngroups_max', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/meminfo', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/stat', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/cpuinfo', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/sys/devices/system/cpu/', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/sys/devices/system/cpu/online', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/2/maps', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/123/auxv', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/1234/status', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/sys/crypto/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/common-licenses/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/common-licenses/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/filesystems', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/sys/vm/overcommit_memory', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/sys/kernel/cap_last_cap', 'mask': {'r'}, 'comm': {'syn'}},
# crypto include (oldest)
{'path': '/etc/gcrypt/random.conf', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/sys/crypto/fips_enabled', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/crypto-policies/d/f.txt', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/crypto-policies/d/f.txt', 'mask': {'r'}, 'comm': {'syn'}},
        )
        self.alwaysFalse = (
{'path': '/etc/openvpn/f.conf', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/wireguard/wg0.conf', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/f', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/locale/f', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/locale/d/f', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/locale.alias', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/localtime', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/writable/localtime', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/bindresvport.blacklist', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.cache', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf.d/', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf.d/f.conf', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.preload', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/gcrypt/random.conf', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/crypto-policies/d/f.txt', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/usr/share/crypto-policies/d/f.txt', 'mask': {'w'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_dsa_key', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_dsa_key.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_ecdsa_key', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_ecdsa_key.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_ed25519_key', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_ed25519_key.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_rsa_key', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ssh/ssh_host_rsa_key.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_dsa', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_dsa.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_ecdsa', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_ecdsa.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_ed25519', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_ed25519.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_rsa', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/root/.ssh/id_rsa.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/home/user/.ssh/id_rsa', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/home/user/.ssh/id_rsa.pub', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/usr/share/false/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/lib/f', 'mask': {'m'}, 'comm': {'syn'}},
{'path': '/usr/lib/d/f', 'mask': {'m', 'r'}, 'comm': {'syn'}},
{'path': '/lib/gconv/d/f', 'mask': {'m'}, 'comm': {'syn'}},
{'path': '/usr/lib64/gconv/f', 'mask': {'m'}, 'comm': {'syn'}},
{'path': '/usr/lib64/gconv/gconv-modules/f', 'mask': {'m'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/gconv/d/f', 'mask': {'m'}, 'comm': {'syn'}},
{'path': '/usr/lib/x86_64-linux-gnu/gconv/gconv-modules/f', 'mask': {'m'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/etc/ld.so.conf.d/d/f', 'mask': {'r'}, 'comm': {'syn'}},
{'path': '/proc/sys/crypto/d/f', 'mask': {'r'}, 'comm': {'syn'}},
        )

        self.regularProfile         = 'parent'
        self.childProfile           = 'parent//child'
        self.transitionProfile      = 'parent▶transition'
        self.childTransitionProfile = 'parent//child▶transition'
        self.allProfileTypes        = [self.regularProfile    + self.childProfile + \
                                       self.transitionProfile + self.childTransitionProfile]

    def test_isBaseAbstractionTransition(self):

        # Regular profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.regularProfile))

        # Child profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.childProfile))

        # Transition profile lines will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.transitionProfile))

        # Child transition profile lines will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.childTransitionProfile))

        # Convert comm to merged down transition
        for l in self.baseAbs:
            l['comm'] = {f'{self.blu}syn{self.rst}'}

        # Regular profile lines with merged down comm will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.regularProfile))

        # Transition profile lines with merged down comm will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.transitionProfile))

        # Always false
        for t in self.allProfileTypes:
            [self.assertFalse(isBaseAbstractionTransition(l, t)) for l in self.alwaysFalse]

    def test_isBaseAbstractionTransition_append(self):

        ## Change input from write to append
        for l in self.baseAbs:
            masks = l.get('mask')
            if 'w' in masks:
                masks.remove('w')
                masks.add('a')
                l['mask'] = masks

        # Regular profile lines must NOT match, even with 'a'
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.regularProfile))

        # Child profile lines must NOT match, even with 'a'
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.childProfile))

        # Transition profile lines will match, with 'a'
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.transitionProfile))

        # Child transition profile lines will match, with 'a'
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.childTransitionProfile))

        # Convert comm to merged down transition
        for l in self.baseAbs:
            l['comm'] = {f'{self.blu}syn{self.rst}'}

        # Regular profile lines with merged down comm will match, with 'a'
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.regularProfile))

        # Transition profile lines with merged down comm will match, with 'a'
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.transitionProfile))

        # Always false
        for t in self.allProfileTypes:
            [self.assertFalse(isBaseAbstractionTransition(l, t)) for l in self.alwaysFalse]

    def test_isBaseAbstractionTransition_overpermissive(self):

        ## Change input to more permissive
        for l in self.baseAbs:
            masks = l.get('mask')
            if 'w' in masks:
                masks.remove('w')
                masks.add('m')
            else:
                masks.add('w')
            l['mask'] = masks

        # More permissive regular profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.regularProfile))

        # More permissive child profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.childProfile))

        # More permissive transition profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.transitionProfile))

        # More permissive child transition profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.childTransitionProfile))

        # Convert comm to merged down transition
        for l in self.baseAbs:
            l['comm'] = {f'{self.blu}syn{self.rst}'}

        # More permissive regular profile lines with merged down comm must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.regularProfile))

        # More permissive transition profile lines with merged down comm must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.transitionProfile))

        # Always false
        for t in self.allProfileTypes:
            [self.assertFalse(isBaseAbstractionTransition(l, t)) for l in self.alwaysFalse]

    def test_isBaseAbstractionTransition_lesspermissive(self):

        ## Change input to less permissive
        for l in self.baseAbs:
            masks = l.get('mask')
            if   'm' in masks:
                masks.remove('m')
            elif 'w' in masks and len(masks) >= 2:
                masks.remove('w')
            l['mask'] = masks

        # Less permissive regular profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.regularProfile))

        # Less permissive child profile lines must NOT match
        for l in self.baseAbs:
            self.assertFalse(isBaseAbstractionTransition(l, self.childProfile))

        # Less permissive transition profile lines will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.transitionProfile))

        # Less permissive child transition profile lines will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.childTransitionProfile))

        # Convert comm to merged down transition
        for l in self.baseAbs:
            l['comm'] = {f'{self.blu}syn{self.rst}'}

        # Less permissive regular profile lines with merged down comm will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.regularProfile))

        # Less permissive transition profile lines with merged down comm will match
        for l in self.baseAbs:
            self.assertTrue(isBaseAbstractionTransition(l, self.transitionProfile))

        # Always false
        for t in self.allProfileTypes:
            [self.assertFalse(isBaseAbstractionTransition(l, t)) for l in self.alwaysFalse]

class otherTests(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_composeSuffix(self):
        bblu = '\x1b[0;94m'
        blu  = '\x1b[0;34m'
        rst  = '\x1b[0m'
        inputResultPair = (
({'path_diffs': [[(0, 7), '/proc'], [(8, 14), '2126']], 'operation': {'open'}, 'comm': {'tracker-miner-f'}},
    f'comm=tracker-miner-f operation=open path_diffs=/proc{bblu},{rst}2126'),
({'operation': {'mknod'}, 'path_diffs': [[(41, 49), '7TU24T']], 'comm': {'[pango] FcInit'}},
    f"comm='[pango] FcInit' operation=mknod path_diffs=7TU24T"),
({'path_diffs': [[(0, 6), '/run'], [(12, 18), '1000'], [(27, 33), '0']], 'operation': {'connect'}, 'comm': {'xdg-desktop-por'}},
    f'comm=xdg-desktop-por operation=connect path_diffs=/run{bblu},{rst}1000{bblu},{rst}0'),
({'operation': {'file_perm'}, 'comm': {'Xwayland'}, 'addr_diffs': [[(17, 23), '1']], 'addr_prefix': 'owner'},
    f'comm=Xwayland operation=file_perm addr_diffs=1'),
        )
        for i,r in inputResultPair:
            hideKeys = []
            self.assertEqual(composeSuffix(i, hideKeys), r)

        inputResultPair_hide = (
({'path_diffs': [[(0, 7), '/proc'], [(8, 14), '2126']], 'operation': {'open'}, 'comm': {'tracker-miner-f'}},
    f'operation=open'),
({'operation': {'mknod'}, 'path_diffs': [[(41, 49), '7TU24T']], 'comm': {'[pango] FcInit'}},
    f"operation=mknod"),
({'path_diffs': [[(0, 6), '/run'], [(12, 18), '1000'], [(27, 33), '0']], 'operation': {'connect'}, 'comm': {'xdg-desktop-por'}},
    f'operation=connect'),
({'operation': {'file_perm'}, 'comm': {'Xwayland'}, 'addr_diffs': [[(17, 23), '1']], 'addr_prefix': 'owner'},
    f'operation=file_perm'),
        )
        for i,r in inputResultPair_hide:
            hideKeys = ['*_diffs', 'comm']
            self.assertEqual(composeSuffix(i, hideKeys), r)

        inputResultPair_hideAll = (
({'path_diffs': [[(0, 7), '/proc'], [(8, 14), '2126']], 'operation': {'open'}, 'comm': {'tracker-miner-f'}},
    None),
({'operation': {'mknod'}, 'path_diffs': [[(41, 49), '7TU24T']], 'comm': {'[pango] FcInit'}},
    None),
({'path_diffs': [[(0, 6), '/run'], [(12, 18), '1000'], [(27, 33), '0']], 'operation': {'connect'}, 'comm': {'xdg-desktop-por'}},
    None),
({'operation': {'file_perm'}, 'comm': {'Xwayland'}, 'addr_diffs': [[(17, 23), '1']], 'addr_prefix': 'owner'},
    None),
        )
        for i,r in inputResultPair_hideAll:
            hideKeys = ['ALL']
            self.assertEqual(composeSuffix(i, hideKeys), r)

    def test_findLogLines(self):
        '''All inputs are made up'''
        args = handleArgs()
        eventsAndLines = (
([
{'_TRANSPORT': 'audit', 'SYSLOG_FACILITY': '4', 'SYSLOG_IDENTIFIER': 'audit', '_AUDIT_TYPE': '1107', '_AUDIT_TYPE_NAME': 'USER_AVC', '_UID': '102', 'MESSAGE': 'USER_AVC pid=1676 apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/NetworkManager" interface="org.freedesktop.DBus.Properties" member="GetAll" name=":1.149" mask="receive" pid=1677 label="NetworkManager" peer_pid=19096 peer_label="cups-browsed"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?', '__REALTIME_TIMESTAMP': 111111},  # USER_AVC; synth

{'_TRANSPORT': 'audit', 'SYSLOG_FACILITY': '4', 'SYSLOG_IDENTIFIER': 'audit', '_AUDIT_TYPE': '1107', '_AUDIT_TYPE_NAME': 'USER_AVC', '_UID': '102', 'MESSAGE': 'USER_AVC pid=1676 auid=4294967295 ses=4294967295 subj=dbus-daemon msg=\'apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/NetworkManager" interface="org.freedesktop.DBus.Properties" member="GetAll" name=":1.149" mask="receive" pid=1677 label="NetworkManager" peer_pid=19096 peer_label="cups-browsed"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?\'', '__REALTIME_TIMESTAMP': 111112},  # nested USER_AVC

{'_UID': '1000', '_GID': '1000', '_TRANSPORT': 'syslog', 'PRIORITY': '5', 'SYSLOG_IDENTIFIER': 'dbus-daemon', 'MESSAGE': 'apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/NetworkManager" interface="org.freedesktop.DBus.Properties" member="GetAll" name=":1.149" mask="receive" pid=1677 label="NetworkManager" peer_pid=19096 peer_label="cups-browsed"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?', '__REALTIME_TIMESTAMP': 999998},  # plain MESSAGE; synth

{'_UID': '1000', '_GID': '1000', '_TRANSPORT': 'syslog', 'PRIORITY': '5', 'SYSLOG_IDENTIFIER': 'audit', 'MESSAGE': 'msg=\'AVC apparmor="ALLOWED" operation="file_inherit" profile="touch" name="/tmp/f" pid=19156 comm="touch" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=1000\'', '__REALTIME_TIMESTAMP': 111114},  # non-consumed nested MESSAGE; synth

{'_UID': '1000', '_GID': '1000', '_TRANSPORT': 'syslog', 'PRIORITY': '5', 'SYSLOG_IDENTIFIER': 'audit', 'MESSAGE': 'msg=\'AVC apparmor="ALLOWED" operation="open"         profile="echo" name="/tmp/echo" pid=19156 comm="echo" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=1000\'', '__REALTIME_TIMESTAMP': 111115},  # consumed nested MESSAGE; synth

{'_AUDIT_TYPE_NAME': 'AVC',      '_TRANSPORT': 'syslog', 'PRIORITY': '5', 'SYSLOG_IDENTIFIER': 'audit', 'MESSAGE':       'AVC apparmor="ALLOWED" operation="open"         profile="echo" name="/tmp/echo" pid=19156 comm="echo" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=1000', '__REALTIME_TIMESTAMP': 111116},  # takes priority; synth

{'_UID': '1000', '_GID': '1000', '_TRANSPORT': 'syslog', 'PRIORITY': '5', 'SYSLOG_IDENTIFIER': 'dbus-daemon', 'MESSAGE': 'AVC apparmor="ALLOWED" operation="file_inherit" profile="systemd-cat" name="/etc/secret.key" pid=19156 comm="systemd-cat" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=1000', '__REALTIME_TIMESTAMP': 111117},  # potential log poisoning; not consumed; synth

{'_AUDIT_TYPE_NAME': 'AVC',      '_TRANSPORT': 'syslog', 'PRIORITY': '5', 'SYSLOG_IDENTIFIER': 'audit', 'MESSAGE':       'AVC apparmor="ALLOWED" operation="file_inherit" profile="systemd-cat" name="/etc/secret.key" pid=19156 comm="systemd-cat" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=1000', '__REALTIME_TIMESTAMP': 111118},  # not a log poisoning; synth

{'_AUDIT_TYPE': '1107', '_AUDIT_TYPE_NAME': 'USER_AVC', '_UID': 102, '_SELINUX_CONTEXT': 'dbus-daemon', 'AUDIT_FIELD_APPARMOR': '"ALLOWED"', 'AUDIT_FIELD_BUS': '"system"', 'AUDIT_FIELD_INTERFACE': '"org.freedesktop.DBus.Properties"', 'AUDIT_FIELD_MASK': '"send"', 'AUDIT_FIELD_EXE': '/usr/bin/dbus-daemon', 'AUDIT_FIELD_SAUID': '102', 'AUDIT_FIELD_HOSTNAME': '?', 'AUDIT_FIELD_ADDR': '?', 'AUDIT_FIELD_TERMINAL': '?', 'AUDIT_FIELD_OPERATION': '"dbus_method_call"', 'AUDIT_FIELD_MEMBER': '"GetAll"', 'AUDIT_FIELD_PEER_LABEL': '"systemd-logind"\n', 'AUDIT_FIELD_PATH': '"/org/freedesktop/login1/session/_41"', 'AUDIT_FIELD_LABEL': '"gnome-shell"', '_AUDIT_ID': '1992', '_PID': 1695, 'AUDIT_FIELD_PEER_PID': '1711', 'MESSAGE': 'USER_AVC pid=1695 uid=102 auid=4294967295 ses=4294967295 subj=dbus-daemon msg=\'apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/login1/session/_41" interface="org.freedesktop.DBus.Properties" member="GetAll" mask="send" name=":1.1" pid=2166 label="gnome-shell" peer_pid=1711 peer_label="systemd-logind"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?\'', 'AUDIT_FIELD_PID': '2166', '__REALTIME_TIMESTAMP': 111119},

{'_TRANSPORT': 'syslog', 'PRIORITY': 5, 'SYSLOG_FACILITY': 1, 'SYSLOG_IDENTIFIER': 'dbus-daemon', 'SYSLOG_PID': 1989, '_PID': 1989, '_UID': 1000, '_GID': 1000, '_COMM': 'dbus-daemon', '_EXE': '/usr/bin/dbus-daemon', '_CMDLINE': '/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only', '_CAP_EFFECTIVE': '0', '_SELINUX_CONTEXT': 'dbus-daemon (complain)\n', '_AUDIT_SESSION': 2, '_AUDIT_LOGINUID': 1000, '_SYSTEMD_CGROUP': '/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service', '_SYSTEMD_OWNER_UID': 1000, '_SYSTEMD_UNIT': 'user@1000.service', '_SYSTEMD_USER_UNIT': 'dbus.service', '_SYSTEMD_SLICE': 'user-1000.slice', '_SYSTEMD_USER_SLICE': 'app.slice', 'MESSAGE': 'apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/login1/session/_41" interface="org.freedesktop.DBus.Properties" member="GetAll" mask="send" name=":1.1" pid=2166 label="gnome-shell" peer_pid=1711 peer_label="systemd-logind"', '__REALTIME_TIMESTAMP': 111120},

{'_TRANSPORT': 'syslog', 'PRIORITY': 5, 'SYSLOG_FACILITY': 1, 'SYSLOG_IDENTIFIER': 'dbus-daemon', 'SYSLOG_PID': 1989, '_PID': 1989, '_UID': 1000, '_GID': 1000, '_COMM': 'dbus-daemon', '_EXE': '/usr/bin/dbus-daemon', '_CMDLINE': '/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only', '_CAP_EFFECTIVE': '0', '_SELINUX_CONTEXT': 'dbus-daemon (complain)\n', '_AUDIT_SESSION': 2, '_AUDIT_LOGINUID': 1000, '_SYSTEMD_CGROUP': '/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service', '_SYSTEMD_OWNER_UID': 1000, '_SYSTEMD_UNIT': 'user@1000.service', '_SYSTEMD_USER_UNIT': 'dbus.service', '_SYSTEMD_SLICE': 'user-1000.slice', '_SYSTEMD_USER_SLICE': 'app.slice', 'MESSAGE': 'apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/login1/seat/seat25" interface="org.freedesktop.DBus.Properties" member="GetAll" mask="send" name=":1.1" pid=2166 label="gnome-shell" peer_pid=1711 peer_label="systemd-logind"', '__REALTIME_TIMESTAMP': 111121},

{'_AUDIT_TYPE': '1107', '_AUDIT_TYPE_NAME': 'USER_AVC', '_UID': 102, '_SELINUX_CONTEXT': 'dbus-daemon', 'AUDIT_FIELD_APPARMOR': '"ALLOWED"', 'AUDIT_FIELD_BUS': '"system"', 'AUDIT_FIELD_INTERFACE': '"org.freedesktop.DBus.Properties"', 'AUDIT_FIELD_MASK': '"send"', 'AUDIT_FIELD_EXE': '/usr/bin/dbus-daemon', 'AUDIT_FIELD_SAUID': '102', 'AUDIT_FIELD_HOSTNAME': '?', 'AUDIT_FIELD_ADDR': '?', 'AUDIT_FIELD_TERMINAL': '?', 'AUDIT_FIELD_OPERATION': '"dbus_method_call"', 'AUDIT_FIELD_MEMBER': '"GetAll"', 'AUDIT_FIELD_PEER_LABEL': '"systemd-logind"\n', 'AUDIT_FIELD_PATH': '"/org/freedesktop/login1/seat/seat25"', 'AUDIT_FIELD_LABEL': '"gnome-shell"', '_AUDIT_ID': '1992', '_PID': 1695, 'AUDIT_FIELD_PEER_PID': '1711', 'MESSAGE': 'USER_AVC pid=1695 uid=102 auid=4294967295 ses=4294967295 subj=dbus-daemon msg=\'apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/login1/seat/seat25" interface="org.freedesktop.DBus.Properties" member="GetAll" mask="send" name=":1.1" pid=2166 label="gnome-shell" peer_pid=1711 peer_label="systemd-logind"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?\'', 'AUDIT_FIELD_PID': '2166', '__REALTIME_TIMESTAMP': 999999},

{'_SELINUX_CONTEXT': 'dbus-daemon', 'MESSAGE': 'pid=1695 uid=102 auid=4294967295 ses=4294967295 subj=dbus-daemon msg=\'apparmor="ALLOWED" operation="dbus_method_call"  bus="session" path="/MenuBar" interface="com.canonical.dbusmenu" member="GetLayout" mask="send" name=":1.141" pid=2166 label="gnome-shell" peer_pid=4317 peer_label="vlc"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?\'', '__REALTIME_TIMESTAMP': 111123},

{'_TRANSPORT': 'syslog', 'PRIORITY': 5, 'SYSLOG_FACILITY': 1, 'SYSLOG_IDENTIFIER': 'dbus-daemon', 'SYSLOG_PID': 1989, '_PID': 1989, '_UID': 1000, '_GID': 1000, '_COMM': 'dbus-daemon', '_EXE': '/usr/bin/dbus-daemon', '_CMDLINE': '/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only', '_CAP_EFFECTIVE': '0', '_SELINUX_CONTEXT': 'dbus-daemon (complain)\n', '_AUDIT_SESSION': 2, '_AUDIT_LOGINUID': 1000, '_SYSTEMD_CGROUP': '/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service', '_SYSTEMD_OWNER_UID': 1000, '_SYSTEMD_UNIT': 'user@1000.service', '_SYSTEMD_USER_UNIT': 'dbus.service', '_SYSTEMD_SLICE': 'user-1000.slice', '_SYSTEMD_USER_SLICE': 'app.slice', 'MESSAGE': 'apparmor="ALLOWED" operation="dbus_method_call"  bus="session" path="/MenuBar" interface="com.canonical.dbusmenu" member="GetLayout" mask="send" name=":1.141" pid=2166 label="gnome-shell" peer_pid=4317 peer_label="vlc"', '__REALTIME_TIMESTAMP': 111124},

{'_SELINUX_CONTEXT': 'dbus-daemon', 'MESSAGE': 'pid=1695 uid=102 auid=4294967295 ses=4294967295 subj=dbus-daemon msg=\'apparmor="ALLOWED" operation="dbus_method_call"  bus="session" path="/MenuBar" interface="com.canonical.dbusmenu" member="GetLayout" mask="send" name=":1.141" pid=2166 label="gnome-shell" peer_pid=4317 peer_label="vlc"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?\'', '__REALTIME_TIMESTAMP': 111125},

{'_AUDIT_TYPE': '1107', '_AUDIT_TYPE_NAME': 'AVC', '_UID': 102, '_SELINUX_CONTEXT': 'dbus-daemon', 'AUDIT_FIELD_APPARMOR': '"ALLOWED"', 'AUDIT_FIELD_BUS': '"session"', 'AUDIT_FIELD_INTERFACE': '"org.freedesktop.DBus.Properties"', 'AUDIT_FIELD_MASK': '"send"', 'AUDIT_FIELD_EXE': '/usr/bin/dbus-daemon', 'AUDIT_FIELD_SAUID': '102', 'AUDIT_FIELD_HOSTNAME': '?', 'AUDIT_FIELD_ADDR': '?', 'AUDIT_FIELD_TERMINAL': '?', 'AUDIT_FIELD_OPERATION': '"dbus_method_call"', 'AUDIT_FIELD_MEMBER': '"GetAll"', 'AUDIT_FIELD_PEER_LABEL': '"systemd-logind"\n', 'AUDIT_FIELD_PATH': '"/org/freedesktop/login1/session/_41"', 'AUDIT_FIELD_LABEL': '"gnome-shell"', '_AUDIT_ID': '1992', '_PID': 1695, 'AUDIT_FIELD_PEER_PID': '1711', 'MESSAGE': 'AVC pid=1695 uid=102 auid=4294967295 ses=4294967295 subj=dbus-daemon msg=\'apparmor="ALLOWED" operation="dbus_method_call"  bus="system" path="/org/freedesktop/login1/session/_41" interface="org.freedesktop.DBus.Properties" member="GetAll" mask="send" name=":1.1" pid=2166 label="gnome-shell" peer_pid=1711 peer_label="systemd-logind"\n exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?\'', 'AUDIT_FIELD_PID': '2166', '__REALTIME_TIMESTAMP': 111126},

{'_AUDIT_TYPE_NAME': 'USER_AVC',      '_TRANSPORT': 'syslog', 'PRIORITY': '5', 'SYSLOG_IDENTIFIER': 'audit', 'MESSAGE':       'USER_AVC apparmor="ALLOWED" operation="open"         profile="grep" name="/tmp/secret.key" pid=19156 comm="grep" requested_mask="wr" denied_mask="wr" fsuid=1000 ouid=1000', '__REALTIME_TIMESTAMP': 111127},

{'MESSAGE': 'minimal', '__REALTIME_TIMESTAMP': 111128},
], ([
{'timestamp': 999998, 'bus': 'system', 'interface': 'org.freedesktop.DBus.Properties', 'label': 'NetworkManager', 'mask': 'receive', 'member': 'GetAll', 'name': ':1.[0-9]*', 'operation': 'dbus_method_call', 'path': '/org/freedesktop/NetworkManager', 'peer_label': 'cups-browsed', 'trust': 8},  # consumed lower trusts for identical lines
{'timestamp': 111114, 'comm': 'touch',       'name': '/tmp/f',          'operation': 'file_inherit', 'profile': 'touch',       'requested_mask': 'wr', 'trust': 4},  # was nested, but haven't fell under other conditions
{'timestamp': 111116, 'comm': 'echo',        'name': '/tmp/echo',       'operation': 'open',         'profile': 'echo',        'requested_mask': 'wr', 'trust': 10},
{'timestamp': 111117,'comm': 'systemd-cat', 'name': '/etc/secret.key', 'operation': 'file_inherit', 'profile': 'systemd-cat', 'requested_mask': 'wr', 'trust': 1},  # lower trust not merged
{'timestamp': 111118, 'comm': 'systemd-cat', 'name': '/etc/secret.key', 'operation': 'file_inherit', 'profile': 'systemd-cat', 'requested_mask': 'wr', 'trust': 10}, # legitimate source
{'timestamp': 111120, 'bus': 'system', 'interface': 'org.freedesktop.DBus.Properties', 'label': 'gnome-shell', 'mask': 'send', 'member': 'GetAll', 'name': ':1.[0-9]*', 'operation': 'dbus_method_call', 'path': '/org/freedesktop/login1/session/_41', 'peer_label': 'systemd-logind', 'trust': 8},
{'timestamp': 999999, 'bus': 'system', 'interface': 'org.freedesktop.DBus.Properties', 'label': 'gnome-shell', 'mask': 'send', 'member': 'GetAll', 'name': ':1.[0-9]*', 'operation': 'dbus_method_call', 'path': '/org/freedesktop/login1/seat/seat25', 'peer_label': 'systemd-logind', 'trust': 8},
{'timestamp': 111125, 'bus': 'session', 'interface': 'com.canonical.dbusmenu', 'label': 'gnome-shell', 'mask': 'send', 'member': 'GetLayout', 'name': ':1.[0-9]*', 'operation': 'dbus_method_call', 'path': '/MenuBar', 'peer_label': 'vlc', 'trust': 7},
{'timestamp': 111126, 'bus': 'system', 'interface': 'org.freedesktop.DBus.Properties', 'label': 'gnome-shell', 'mask': 'send', 'member': 'GetAll', 'name': ':1.[0-9]*', 'operation': 'dbus_method_call', 'path': '/org/freedesktop/login1/session/_41', 'peer_label': 'systemd-logind', 'trust': 3},  # potential 'system' poisoning from 'session'; not merged with similar
{'timestamp': 111127, 'comm': 'grep', 'name': '/tmp/secret.key', 'operation': 'open', 'profile': 'grep', 'requested_mask': 'wr', 'trust': 3},  # potential poisoning from DBus
{'timestamp': 111128, 'trust': 4},  # minimal input still gets trust assigned
], 999999)),
        )
        for j,r in eventsAndLines:
            self.assertEqual(findLogLines(j, args), r)

if __name__ == '__main__':

    unittest.main()
