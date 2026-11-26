#!/bin/bash
# Native ALT p11 package fixture. Run only in a disposable, rootful container.
set -euo pipefail
[[ $(id -u) == 0 && ( -f /run/.containerenv || -f /.dockerenv ) ]] || exit 77
driver=${1:?native driver}
role_rpm=${2:?RPM alterator-roles-common}
ldap_rpm=${3:?RPM alterator-ldap-users}
backend=/usr/lib/alterator/backend3/ldap-users
ldap=alt_ldap_users_default_groups
role=alt_role_groups
work=$(mktemp -d)
cd /etc/role.d
rpm -q shadow-utils alterator-ldap-users libnss-role alterator-roles-common
chmod 0755 /

has_group() {
    local memberships
    memberships=" $(id -Gn "$1") "
    [[ $memberships == *" $2 "* ]]
}

lacks_group() {
    if has_group "$1" "$2"; then
        echo "$1 unexpectedly inherits $2" >&2
        return 1
    fi
}

create_alterator_user() {
    printf '%s\n' _message:begin action:new _objects:user "newusername:$1" _message:end | "$backend"
    getent passwd "$1"
}

without_assignment() { sed '/^default_groups=/d' "$1"; }

stamp() { stat -c '%d:%i:%y:%z' "$@"; }

crash_apply() {
    local status=0
    "$driver" crash-apply "$@" || status=$?
    [[ $status == 86 ]]
}

reject_apply() {
    if "$driver" apply "$@"; then
        echo "Expected apply to refuse: $*" >&2
        exit 1
    fi
}

reject_release() {
    if "$driver" release "$1"; then
        echo "Expected rollback to refuse: $1" >&2
        exit 1
    fi
}

cp -p "$backend" "$work/original-ldap"
for group in ficldapone ficldaptwo ficouter ficinner ficinherited ficmaximum ficnew ficforeign; do
    groupadd "$group"
done

[[ $(/usr/sbin/system-auth status | cut -d ' ' -f 1) == local ]]
for phase in before after; do
    crash_apply "$ldap" '["ficldapone","ficldaptwo"]' "$phase"
    "$driver" apply "$ldap" '["ficldapone","ficldaptwo"]'
    grep -Fx 'default_groups="ficldapone ficldaptwo"' "$backend"
    cmp <(without_assignment "$backend") <(without_assignment "$work/original-ldap")
    [[ $(stat -c '%a:%u:%g' "$backend") == "$(stat -c '%a:%u:%g' "$work/original-ldap")" ]]
    before=$(stamp "$backend")
    "$driver" apply "$ldap" '["ficldapone","ficldaptwo"]'
    [[ $(stamp "$backend") == "$before" ]]
    "$driver" release "$ldap"
    cmp "$backend" "$work/original-ldap"
done
"$driver" apply "$ldap" '["ficldapone","ficldaptwo"]'
create_alterator_user ficldapfilled
getent -s files group ficldapone | grep -F ':ficldapfilled'
getent -s files group ficldaptwo | grep -F ':ficldapfilled'
"$driver" apply "$ldap" '[]'
grep -Fx 'default_groups=""' "$backend"
create_alterator_user ficldapempty
[[ $(id -Gn ficldapempty) == ficldapempty ]]
[[ $(getent -s files group ficldapone | cut -d: -f4) == ficldapfilled ]]
[[ $(getent -s files group ficldaptwo | cut -d: -f4) == ficldapfilled ]]
"$driver" release "$ldap"
cmp "$backend" "$work/original-ldap"
rpm -V --nomtime alterator-ldap-users

# Exercise true package publication and a fresh ownership cycle on that inode.
ldap_value='["ficldapone","ficldaptwo"]'
for phase in direct between before after; do
    # Give the old cycle a different baseline even when both RPM operations
    # use the same official build. Restoring it would resurrect stale content.
    sed -i 's/^default_groups=.*/default_groups="ficforeign"/' "$backend"
    "$driver" apply "$ldap" "$ldap_value"
    prior_inode=$(stat -c '%d:%i' "$backend")
    rpm -U --replacepkgs "$ldap_rpm"
    [[ $(stat -c '%d:%i' "$backend") != "$prior_inode" ]]
    cp -p "$backend" "$work/stock-after-rpm"
    cmp "$backend" "$work/original-ldap"
    if [[ $phase == direct ]]; then
        stock=$(stamp "$backend")
        "$driver" release "$ldap"
        [[ $(stamp "$backend") == "$stock" ]]
    else
        crash_apply "$ldap" "$ldap_value" "$phase"
        if [[ $phase == between ]]; then
            cmp "$backend" "$work/stock-after-rpm"
            "$driver" release "$ldap"
            cmp "$backend" "$work/stock-after-rpm"
        fi
        "$driver" apply "$ldap" "$ldap_value"
        grep -Fx 'default_groups="ficldapone ficldaptwo"' "$backend"
        cmp <(without_assignment "$backend") <(without_assignment "$work/stock-after-rpm")
        "$driver" release "$ldap"
        cmp "$backend" "$work/stock-after-rpm"
    fi
done
"$driver" apply "$ldap" "$ldap_value"
cp -p "$work/original-ldap" "$backend.foreign"
printf '\n# foreign bytes\n' >> "$backend.foreign"
mv -f "$backend.foreign" "$backend"
foreign=$(stamp "$backend")
reject_apply "$ldap" "$ldap_value"
reject_release "$ldap"
[[ $(stamp "$backend") == "$foreign" ]]
rpm -U --replacepkgs "$ldap_rpm"
# Exact stock bytes are insufficient when there is no installed package owner.
rpm -e --justdb alterator-ldap-users
stock=$(stamp "$backend")
reject_apply "$ldap" "$ldap_value"
reject_release "$ldap"
[[ $(stamp "$backend") == "$stock" ]]
rpm -U "$ldap_rpm"
"$driver" release "$ldap"
cmp "$backend" "$work/original-ldap"
echo 'PASS RPM ownership and digest, cycle renewal, no-write release and crash recovery'

rpm -e alterator-ldap-users
"$driver" apply "$ldap" '[]'
"$driver" release "$ldap"
[[ ! -e $backend ]]
echo 'PASS Alterator local native defaults, absent RPM, repeat, crash recovery and rollback'

cp -p /etc/role "$work/original-role"
cp -a . "$work/original-role.d"
useradd -M -g localadmins ficpkgmember
useradd -M -g ficouter ficrolemember
has_group ficpkgmember wheel

# Both the native consumer and the FIC transaction must handle NAME_MAX bytes.
name_max=$(getconf NAME_MAX .)
printf -v stem '%0*d' "$((name_max - 5))" 0
long_name="$stem.role"
long_backup="$stem.fic"
[[ ${#long_name} == "$name_max" ]]
printf 'ficouter:ficmaximum\n' > "$long_name"
cp -p "$long_name" "$work/original-long"
rolelst -V | grep -F 'ficouter:ficmaximum'
has_group ficrolemember ficmaximum

# A matching-looking third-party relative symlink and target have no provenance.
printf 'ficouter:ficforeign\n' > exterior.fic
ln -s exterior.fic exterior.role
exterior_stamp=$(stamp exterior.role exterior.fic)
printf 'ficouter:ficforeign\n' > conflict.role
printf 'foreign reservation\n' > conflict.fic
conflict=$(stamp conflict.role conflict.fic)
reject_apply "$role" '{}'
[[ $(stamp conflict.role conflict.fic) == "$conflict" ]]
[[ -f $long_name && ! -L $long_name ]]
cmp /etc/role "$work/original-role"
rm conflict.role conflict.fic

rules='{"ficouter":["ficinner"],"ficinner":["ficinherited"]}'
for phase in before after; do
    crash_apply "$role" "$rules" "$phase"
    "$driver" apply "$role" "$rules"
    [[ $(readlink "$long_name") == "$long_backup" ]]
    [[ -f $long_backup && ! -L $long_backup ]]
    lacks_group ficrolemember ficmaximum
    has_group ficrolemember ficinherited
    "$driver" release "$role"
    cmp "$long_name" "$work/original-long"
    [[ ! -e $long_backup && ! -L $long_backup ]]
    has_group ficrolemember ficmaximum
    cmp /etc/role "$work/original-role"
done

"$driver" apply "$role" "$rules"
printf 'ficinner:ficinherited\nficouter:ficinner\n' | cmp /etc/role -
[[ $(readlink "$long_name") == "$long_backup" ]]
cmp "$long_backup" "$work/original-long"
[[ $(readlink localadmins.role) == localadmins.fic ]]
rolelst -V | grep -F 'ficouter:'
has_group ficrolemember ficinner
has_group ficrolemember ficinherited
lacks_group ficpkgmember wheel
lacks_group ficrolemember ficmaximum
lacks_group ficrolemember ficforeign

# Drift is writable through exclusive apply, while rollback retains the
# initial snapshot and refuses foreign bytes or an unproven inode.
role_inode=$(stat -c '%d:%i' /etc/role)
printf 'ficouter:ficforeign\n' > /etc/role
[[ $(stat -c '%d:%i' /etc/role) == "$role_inode" ]]
has_group ficrolemember ficforeign
reject_release "$role"
"$driver" apply "$role" "$rules"
has_group ficrolemember ficinherited
lacks_group ficrolemember ficforeign

printf 'ficouter:ficforeign\n' > /etc/role.fixture
mv -f /etc/role.fixture /etc/role
has_group ficrolemember ficforeign
crash_apply "$role" "$rules" config-before
foreign=$(stamp /etc/role)
reject_release "$role"
[[ $(stamp /etc/role) == "$foreign" ]]
"$driver" apply "$role" "$rules"
has_group ficrolemember ficinherited

rm /etc/role
crash_apply "$role" "$rules" config-after
published=$(stamp /etc/role)
"$driver" apply "$role" "$rules"
[[ $(stamp /etc/role) == "$published" ]]
has_group ficrolemember ficinherited

mv /etc/role /etc/role.fixture
cp -p /etc/role.fixture /etc/role
foreign=$(stamp /etc/role)
"$driver" apply "$role" "$rules"
reject_release "$role"
[[ $(stamp /etc/role) == "$foreign" ]]
rm /etc/role
ln -s /etc/role.fixture /etc/role
reject_apply "$role" "$rules"
reject_release "$role"
[[ $(readlink /etc/role) == /etc/role.fixture ]]
mv -f /etc/role.fixture /etc/role
echo 'PASS exclusive /etc/role drift repair, NSS, recovery, strict rollback and no-op'

before=$(stamp /etc/role "$long_name" "$long_backup" localadmins.role localadmins.fic)
"$driver" apply "$role" "$rules"
[[ $(stamp /etc/role "$long_name" "$long_backup" localadmins.role localadmins.fic) == "$before" ]]
printf 'ficouter:ficnew\n' > late.role
has_group ficrolemember ficnew
"$driver" apply "$role" "$rules"
[[ $(readlink late.role) == late.fic ]]
lacks_group ficrolemember ficnew
rpm -U --replacepkgs "$role_rpm"
"$driver" apply "$role" "$rules"
[[ $(readlink localadmins.role) == localadmins.fic ]]
lacks_group ficpkgmember wheel

"$driver" apply "$role" '{}'
[[ ! -s /etc/role ]]
lacks_group ficrolemember ficinherited
lacks_group ficrolemember ficmaximum

# An inode replaced by a link with identical spelling is still foreign.
mv late.role late.held
ln -s late.fic late.role
foreign_replacement=$(stamp late.role)
if "$driver" release "$role"; then
    echo 'Rollback accepted a foreign link with a matching target' >&2
    exit 1
fi
[[ $(stamp late.role) == "$foreign_replacement" ]]
rm late.role
mv late.held late.role
"$driver" release "$role"
"$driver" release "$role"
cmp /etc/role "$work/original-role"
for original in "$work/original-role.d/"*.role; do
    name=${original##*/}
    [[ -f $name && ! -L $name ]]
    cmp "$name" "$original"
done
cmp "$long_name" "$work/original-long"
[[ -f late.role && ! -L late.role ]]
[[ $(stamp exterior.role exterior.fic) == "$exterior_stamp" ]]
has_group ficpkgmember wheel
has_group ficrolemember ficmaximum
has_group ficrolemember ficnew
lacks_group ficrolemember ficinherited
echo 'PASS libnss-role native inheritance, NAME_MAX, nested rules, reinstall, conflicts, recovery and rollback'

mv /etc/role "$work/previous-main"
"$driver" apply "$role" '{}'
[[ -f /etc/role && ! -s /etc/role ]]
printf 'ficouter:ficforeign\n' > /etc/role
"$driver" apply "$role" '{}'
[[ -f /etc/role && ! -s /etc/role ]]
"$driver" release "$role"
[[ ! -e /etc/role && ! -L /etc/role ]]
mv "$work/previous-main" /etc/role
echo 'PASS role policy restores absent /etc/role'
