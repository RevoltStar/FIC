#!/bin/bash
# Only real OS consumers in disposable Podman. Production driver refuses host.
set -euo pipefail
[[ $(id -u) == 0 && -f /run/.containerenv ]] || exit 77
driver=${1:?native driver}; row=${2:?platform row}
cat /etc/os-release
root=/var/lib/fic-user-creation-native
mkdir -p "$root/home" "$root/home-next" "$root/skel" "$root/skel-next" "$root/override-skel"
echo native-skeleton > "$root/skel/fic-template"
echo next-skeleton > "$root/skel-next/fic-template-next"
echo argument-skeleton > "$root/override-skel/fic-override"
# Cached ALT test image root metadata is repaired only inside this container.
[[ $row != alt-p11 ]] || chmod 0755 /
if command -v dpkg-query >/dev/null; then
 dpkg-query -W -f='${Package}=${Version}\n' passwd adduser
else
 rpm -q shadow-utils
fi
command -v useradd
command -v adduser || true
for group in users staff audio video; do getent group "$group" >/dev/null || groupadd "$group"; done
for file in /etc/default/useradd /etc/login.defs; do [[ -f $file && ! -L $file ]]; done
cp /etc/default/useradd "$root/useradd-original"
cp /etc/login.defs "$root/login-original"
printf '\n# native foreign compliant USER_CREATION fixture\nHOME=%s/home\nSKEL=%s/skel\nSHELL=/bin/sh\nGROUP=users\n' "$root" "$root" >> /etc/default/useradd
printf '\n# native foreign compliant USER_CREATION fixture\nCREATE_HOME yes\nUSERGROUPS_ENAB no\n' >> /etc/login.defs
case $row in
 debian12|ubuntu2404)
  provider=adduser
  [[ -f /etc/adduser.conf && ! -L /etc/adduser.conf ]]
  cp /etc/adduser.conf "$root/adduser-original"
  printf '\n# native foreign fixture\nADD_EXTRA_GROUPS=0\nEXTRA_GROUPS="audio video"\n' >> /etc/adduser.conf
  cp /etc/adduser.conf "$root/adduser-foreign";;
 debian13|ubuntu2604)
  provider=shadow
  printf 'GROUPS=audio,video\nGROUPS=\n' >> /etc/default/useradd;;
 alt-p11) provider=unsupported;;
 *) exit 2;;
esac
cp /etc/default/useradd "$root/useradd-foreign"
cp /etc/login.defs "$root/login-foreign"
checks=0
pass() { checks=$((checks+1)); echo "PASS $*"; }
apply() {
 local out
 out=$("$driver" apply "$1" "$2")
 [[ $out == *"SUCCESS writes=$3 ownership=Applied"* ]] || { echo "Unexpected apply: $out" >&2; exit 1; }
 pass "FIC $1 writes=$3"
}
release() { "$driver" release "$1"; }
policies=(user_home_base_directory user_create_home user_skeleton_directory user_default_shell user_create_private_group user_default_primary_group)
values=("$root/home" yes "$root/skel" /bin/sh no users)
next=("$root/home-next" no "$root/skel-next" /bin/bash yes staff)
if [[ $provider != unsupported ]]; then
 policies+=(user_default_supplementary_groups); values+=('[]'); next+=('["audio","video"]')
else
 before=$(sha256sum /etc/default/useradd /etc/login.defs)
 if "$driver" apply user_default_supplementary_groups '[]'; then echo 'ALT Unsupported accepted' >&2; exit 1; fi
 [[ $(sha256sum /etc/default/useradd /etc/login.defs) == "$before" ]]
 pass 'ALT supplementary Unsupported: refusal without system mutation'
fi
# Fresh compliant ownership, repeat, single refresh, release both fresh and
# refreshed, actual persistent crash recovery before/after physical install.
for i in ${!policies[@]}; do
 policy=${policies[$i]}; value=${values[$i]}
 apply "$policy" "$value" 1
 apply "$policy" "$value" 0
 release "$policy"
 release "$policy" | grep -F NothingToDo
 apply "$policy" "$value" 1
 apply "$policy" "${next[$i]}" 1
 release "$policy"
 cmp /etc/default/useradd "$root/useradd-foreign"
 cmp /etc/login.defs "$root/login-foreign"
 [[ $provider != adduser ]] || cmp /etc/adduser.conf "$root/adduser-foreign"
 pass "$policy release preserves all foreign bytes and removes last container"
 for phase in before after; do
  if "$driver" crash-apply "$policy" "$value" "$phase"; then
   echo 'Crash hook did not terminate' >&2; exit 1
  else
   [[ $? == 86 ]] || exit 1
  fi
  apply "$policy" "$value" "$([[ $phase == before ]] && echo 1 || echo 0)"
  release "$policy"
  cmp /etc/default/useradd "$root/useradd-foreign"
  cmp /etc/login.defs "$root/login-foreign"
  [[ $provider != adduser ]] || cmp /etc/adduser.conf "$root/adduser-foreign"
  pass "$policy Prepared/$phase actual process crash recovered"
 done
done
# All real peer owners coexist. Apply repeat must still be a zero-write no-op.
for i in ${!policies[@]}; do apply "${policies[$i]}" "${values[$i]}" 1; done
for i in ${!policies[@]}; do apply "${policies[$i]}" "${values[$i]}" 0; done
# Native configured GROUP can be effective while a private-group mechanism
# selects a different primary group. Both FIC policies succeed independently.
serial=0
new_user() { serial=$((serial+1)); account="ficnative$serial"; useradd "$@" "$account"; }
primary() { [[ $(id -gn "$account") == "$1" ]]; }
for group in users staff; do
 for private in no yes; do
  apply user_default_primary_group "$group" "$([[ $group == users ]] && echo 0 || { [[ $private == no ]] && echo 1 || echo 0; })"
  # First no remains no only for users; after the users/yes row change back.
  current=$(awk '$1 == "USERGROUPS_ENAB" {v=$2} END {print v}' /etc/login.defs)
  apply user_create_private_group "$private" "$([[ $current == "$private" ]] && echo 0 || echo 1)"
  native_gid=$(useradd -D | sed -n 's/^GROUP=//p')
  [[ $native_gid == "$(getent group "$group" | cut -d: -f3)" ]]
  new_user
  if [[ $private == yes ]]; then primary "$account"; else primary "$group"; fi
  entry=$(getent passwd "$account")
  [[ $(echo "$entry" | cut -d: -f6) == "$root/home/$account" && $(echo "$entry" | cut -d: -f7) == /bin/sh ]]
  [[ -f $root/home/$account/fic-template ]]
  pass "native GROUP=$group USERGROUPS_ENAB=$private home/skel/shell"
 done
done
# CLI overrides do not invalidate FIC's configured defaults.
new_user -g users; primary users; pass '-g overrides private group'
new_user -N; primary staff; pass '-N overrides private=yes'
apply user_create_private_group no 1
new_user -U; primary "$account"; pass '-U overrides private=no'
new_user -M; [[ ! -e $root/home/$account ]]; pass '-M overrides CREATE_HOME=yes'
apply user_create_home no 1
new_user; [[ ! -e $root/home/$account ]]; pass 'CREATE_HOME=no actual absence'
new_user -m; [[ -f $root/home/$account/fic-template ]]; pass '-m overrides CREATE_HOME=no'
new_user -m -d "$root/explicit-home" -k "$root/override-skel" -s /bin/bash
[[ $(getent passwd "$account" | cut -d: -f6) == "$root/explicit-home" && $(getent passwd "$account" | cut -d: -f7) == /bin/bash && -f $root/explicit-home/fic-override ]]
pass '-d/-k/-s explicit native overrides'
apply user_home_base_directory "$root/home-next" 1
apply user_skeleton_directory "$root/skel-next" 1
apply user_default_shell /bin/bash 1
apply user_create_home yes 1
new_user
[[ $(getent passwd "$account" | cut -d: -f6) == "$root/home-next/$account" && $(getent passwd "$account" | cut -d: -f7) == /bin/bash && -f $root/home-next/$account/fic-template-next ]]
pass 'refreshed HOME/SKEL/SHELL actual native account'
if [[ $provider == shadow ]]; then
 apply user_default_supplementary_groups '["audio","video"]' 1
 new_user; memberships=" $(id -Gn "$account") "
 [[ $memberships == *' audio '* && $memberships == *' video '* ]]
 pass 'GROUPS actual nonempty native membership'
 # Prove how this distribution frontend invokes useradd, separately from its
 # own EXTRA_GROUPS mechanism; do not pretend adduser consumes every default.
 printf '\nADD_EXTRA_GROUPS=0\n' >> /etc/adduser.conf
 serial=$((serial+1)); account="ficnative$serial"
 adduser --disabled-password --gecos '' "$account" </dev/null
 memberships=" $(id -Gn "$account") "
 [[ $memberships == *' audio '* && $memberships == *' video '* ]]
 pass 'native adduser inherits shadow GROUPS when its own extras disabled'
 [[ $(getent passwd "$account" | cut -d: -f6) == "/home/$account" ]]
 primary "$account"
 pass 'adduser frontend overrides HOME and primary group defaults'
 new_user -G users; memberships=" $(id -Gn "$account") "
 [[ $memberships != *' audio '* && $memberships != *' video '* && $memberships == *' users '* ]]
 pass '-G overrides GROUPS'
 apply user_default_supplementary_groups '[]' 1
 grep -Fx 'GROUPS=' /etc/default/useradd
 new_user; memberships=" $(id -Gn "$account") "
 [[ $memberships != *' audio '* && $memberships != *' video '* ]]
 pass 'GROUPS= actual empty membership despite prior nonempty foreign defaults'
elif [[ $provider == adduser ]]; then
 apply user_default_supplementary_groups '["audio","video"]' 1
 serial=$((serial+1)); account="ficnative$serial"
 adduser --disabled-password --gecos '' "$account" </dev/null
 memberships=" $(id -Gn "$account") "
 [[ $memberships == *' audio '* && $memberships == *' video '* ]]
 pass 'ADD_EXTRA_GROUPS=1 actual adduser membership'
 [[ $(getent passwd "$account" | cut -d: -f6) == "/home/$account" ]]
 primary "$account"
 pass 'adduser frontend overrides HOME and primary group defaults'
 new_user; memberships=" $(id -Gn "$account") "
 [[ $memberships != *' audio '* && $memberships != *' video '* ]]
 pass 'old useradd does not consume adduser EXTRA_GROUPS'
 apply user_default_supplementary_groups '[]' 1
 grep -Fx 'EXTRA_GROUPS="audio video"' /etc/adduser.conf
 [[ $(grep -c '^EXTRA_GROUPS=' /etc/adduser.conf) == $(grep -c '^EXTRA_GROUPS=' "$root/adduser-foreign") ]]
 serial=$((serial+1)); account="ficnative$serial"
 adduser --disabled-password --gecos '' "$account" </dev/null
 memberships=" $(id -Gn "$account") "
 [[ $memberships != *' audio '* && $memberships != *' video '* ]]
 pass 'ADD_EXTRA_GROUPS=0 disables foreign list without owning EXTRA_GROUPS'
 new_user -G audio; [[ " $(id -Gn "$account") " == *' audio '* ]]; pass '-G explicit useradd membership'
fi
# Reapply after argument overrides still succeeds; account state is outside
# the ownership domain. Release all peers, preserve existing accounts unchanged.
accounts_before=$(getent passwd | sha256sum)
groups_before=$(getent group | sha256sum)
apply user_home_base_directory "$root/home-next" 0
apply user_skeleton_directory "$root/skel-next" 0
apply user_default_shell /bin/bash 0
apply user_create_home yes 0
apply user_create_private_group no 0
apply user_default_primary_group staff 0
[[ $provider == unsupported ]] || apply user_default_supplementary_groups '[]' 0
for policy in "${policies[@]}"; do release "$policy"; done
cmp /etc/default/useradd "$root/useradd-foreign"
cmp /etc/login.defs "$root/login-foreign"
[[ $provider != adduser ]] || cmp /etc/adduser.conf "$root/adduser-foreign"
[[ $(getent passwd | sha256sum) == "$accounts_before" && $(getent group | sha256sum) == "$groups_before" ]]
pass 'final ownership release preserves foreign files and existing accounts/groups'
if [[ $provider == shadow ]]; then
 # Missing foreign key is not ownership: fresh empty still materializes GROUPS=.
 sed -i '/^GROUPS=/d' /etc/default/useradd
 cp /etc/default/useradd "$root/useradd-no-groups"
 apply user_default_supplementary_groups '[]' 1
 grep -Fx 'GROUPS=' /etc/default/useradd
 new_user -M; memberships=" $(id -Gn "$account") "
 [[ $memberships != *' audio '* && $memberships != *' video '* ]]
 release user_default_supplementary_groups
 cmp /etc/default/useradd "$root/useradd-no-groups"
 pass 'absent foreign GROUPS still acquires authoritative empty ownership'
fi
echo "RESULT row=$row PASS=$checks FAIL=0 Unsupported=$([[ $provider == unsupported ]] && echo 1 || echo 0)"
