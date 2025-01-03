# apparmor-suggest
## Features
Deduplicates AppArmor log entries and suggests unequivocal rules for profiles. Provides tuning and filtering parameters to better evaluate required access.

BETA state - suitable for usage and testing (comparing raw log and suggested rules).

### `--help`
```
$ sudo aa_suggest.py --help
usage: aa_suggest.py [-h] [-v] [--legend] [-b {-14,-13,-12,-11,-10,-9,-8,-7,-6,-5,-4,-3,-2,-1,0}] [-t {file,dbus,unix,network,signal,ptrace,cap,mount,pivot,unknown}] [-p PROFILE] [-l PEER] [-o OPERATION]
                     [--hide-keys {comm,operation,mask,*_diffs,error,info,class,ALL}] [--drop-comm] [--keep-base-abs-transitions] [--keep-status] [--keep-status-audit] [-c] [-s {profile,peer,path,interface,member,timestamp}]
                     [--style {default,AppArmor.d}]

Suggest AppArmor rules

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  --legend              Display color legend
  -b {-14,-13,-12,-11,-10,-9,-8,-7,-6,-5,-4,-3,-2,-1,0}, --boot-id {-14,-13,-12,-11,-10,-9,-8,-7,-6,-5,-4,-3,-2,-1,0}
                        Specify (previous) boot id
  -t {file,dbus,unix,network,signal,ptrace,cap,mount,pivot,unknown}, --type {file,dbus,unix,network,signal,ptrace,cap,mount,pivot,unknown}
                        Handle only specified rule type
  -p PROFILE, --profile PROFILE
                        Handle only specified profile
  -l PEER, --peer PEER  Handle only specified peer profile
  -o OPERATION, --operation OPERATION
                        Show only lines containing specified operation. Does not affect merging
  --hide-keys {comm,operation,mask,*_diffs,error,info,class,ALL}
                        Hide specified keys in suffix. Does not affect merging
  --drop-comm           Drop comm key to affect further merging
  --keep-base-abs-transitions
                        Do not drop automatic transition lines '▶' which rules are present in 'base' abstraction
  --keep-status         Do not drop 'apparmor' status key. Affects merging
  --keep-status-audit   Do not drop 'AUDIT' log lines. Implies '--keep-status'
  -c, --convert-file-masks
                        Convert requested file masks to currently supported variants. Will be deprecated (changed)
  -s {profile,peer,path,interface,member,timestamp}, --sort {profile,peer,path,interface,member,timestamp}
                        Sort by. 'profile' is the default
  --style {default,AppArmor.d}
                        Style preset. Stock or 'roddhjav/apparmor.d'. Affects custom tunables
```

## Requirements
1. AppArmor supported in kernel and enabled
2. systemd journal via `python3-systemd`
3. `/dev/shm` availability

## Installation
```sh
$ sudo apt install python3-systemd                                           # install systemd module for python
$ git clone https://github.com/nobody43/apparmor-suggest.git
$ cd apparmor-suggest
$ sudo install -m 644 -o root -g root apparmor.d/aa_suggest /etc/apparmor.d/ # install AppArmor profile for executable
$ sudo apparmor_parser --add /etc/apparmor.d/aa_suggest                      # confine profile for executable
$ sudo install -m 755 -o root -g root aa_suggest.py /usr/local/bin/          # install the executable
```

## Usage advice
- Always fight against [automation bias](https://en.wikipedia.org/wiki/Automation_bias)
- If a program requests some access - it doesn't mean you should unquestionably allow it
- Ensure your system is free of malware, even better, write profiles on ephemeral systems
- Increasing number of tech abstactions also increases chances of unreliable results
- Adopt [AppArmor.d tunables](https://github.com/roddhjav/apparmor.d/tree/main/apparmor.d/tunables) (`--style` param)

## Planned features
### for BETA
- compatibility with more distros
- switching from journal to `audit` entirely

### for 1.0
- better padding
- boot ID selection
- `--no-color`

## Supported distros
- Debian 12
- Ubuntu 22.04
- Ubuntu 24.04 (`audit` fix)
- OpenSUSE Tumbleweed (`audit` fix)

## Known issues
On certain distros/configurations AppArmor logs in journal could be taken over by `audit` package when it's installed. To overcome this, `systemd-journald-audit.socket` could be TEMPORARILY enabled:
```sh
sudo systemctl enable systemd-journald-audit.socket
```
Return to default state when not needed:
```sh
sudo systemctl disable systemd-journald-audit.socket
```
Restart the system to take effect.

## Deinstallation
```sh
$ sudo rm /usr/local/bin/aa_suggest.py
$ sudo apparmor_parser --remove /etc/apparmor.d/aa_suggest
$ sudo rm /etc/apparmor.d/aa_suggest
$ sudo rm /dev/shm/apparmor_suggest/timestamp.latest
$ sudo rm -d /dev/shm/apparmor_suggest/
```

## Links
- https://github.com/roddhjav/apparmor.d - Full set of AppArmor profiles
- https://forums.grsecurity.net/viewtopic.php?t=2522 - capabilities boundaries
