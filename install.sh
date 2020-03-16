#!/bin/sh
apt-get update
apt-get upgrade -yq

# Setting umask on /etc/profile
echo "umask 027" >> /etc/profile

rm /etc/cron.deny 2> /dev/null
rm /etc/at.deny 2> /dev/null
echo 'root' > /etc/cron.allow
echo 'root' > /etc/at.allow
chown root:root /etc/cron*
chown root:root /etc/at*

echo 'sshd : ALL : ALLOW' > /etc/hosts.allow
echo 'ALL: LOCAL, 127.0.0.1' >> /etc/hosts.allow
echo 'ALL: PARANOID' > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

# updating fstab
echo 'proc /proc proc defaults,hidepid=2 0 0' >> /etc/fstab

cat <<-EOF > /etc/sysctl.d/01-sysctl.conf
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter= 1
net.ipv4.conf.default.secure_redirects = 1
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 1
net.ipv4.tcp_challenge_ack_limit = 1000000
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.accept_ra_rtr_pref = 0
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0
vm.swappiness = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_syncookies = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF

sysctl -p

mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

cat <<-EOF > /etc/ssh/sshd_config
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
Port 22
Protocol 2
AcceptEnv LANG LC_*
AllowGroups root sudo
Banner /etc/issue.net
ChallengeResponseAuthentication no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
ClientAliveCountMax 0
ClientAliveInterval 300
Compression no
HostbasedAuthentication no
IgnoreUserKnownHosts yes
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
LoginGraceTime 20
LogLevel VERBOSE
Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60
PermitEmptyPasswords no
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
PermitUserEnvironment no
PrintLastLog yes
PrintMotd no
StrictModes yes
Subsystem sftp internal-sftp
UseDNS no
UsePAM yes
X11Forwarding no
EOF

apt-get install -yq build-essential linux-headers-amd64 linux-headers-cloud-amd64 > /dev/null 2>&1
apt-get install -yq apt-transport-https ca-certificates curl gnupg2 software-properties-common > /dev/null 2>&1
apt-get install -yq rkhunter usbguard haveged pwgen auditd audispd-plugins unattended-upgrades debsums debsecan ntp > /dev/null 2>&1
apt-get install -yq apparmor dh-apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils apparmor-easyprof > /dev/null 2>&1
apt-get install -yq libpam-apparmor libcrack2 cracklib-runtime libpam-cracklib python3-cracklib libpam-tmpdir > /dev/null 2>&1

echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
apt update

apt-get install -yq wireguard wireguard-tools wireguard-dkms > /dev/null 2>&1
touch /etc/wireguard/wg0.conf
chmod -R 600 /etc/wireguard/

# Setting up USBGuard
usbguard generate-policy > /tmp/rules.conf
install -m 0600 -o root -g root /tmp/rules.conf /etc/usbguard/rules.conf

# Enforce apparmor profiles
echo 'session optional pam_apparmor.so order=user,group,default' > /etc/pam.d/apparmor

echo 'server 0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org' >> /etc/ntp.conf

cat <<-EOF > /etc/audit/rules.d/hardening.rules
# Remove any existing rules
-D

# Buffer Size
-b 8192

# Ignore errors
-i

# Failure Mode
-f 1
# Audit the audit logs
-w /var/log/audit/ -k auditlog

# Auditd configuration
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

# Monitor for use of audit management tools
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Monitor AppArmor configuration changes
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor

# Monitor usage of AppArmor tools
-w /sbin/apparmor_parser -p x -k apparmor_tools
-w /usr/sbin/aa-complain -p x -k apparmor_tools
-w /usr/sbin/aa-disable -p x -k apparmor_tools
-w /usr/sbin/aa-enforce -p x -k apparmor_tools

# Monitor Systemd configuration changes
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# Monitor usage of systemd tools
-w /bin/systemctl -p x -k systemd_tools
-w /bin/journalctl -p x -k systemd_tools

# Special files
-a always,exit -F arch=x86_64 -S mknod -S mknodat -k specialfiles
-a always,exit -F arch=b32 -S mknod -S mknodat -k specialfiles

# Mount operations
-a always,exit -F arch=x86_64 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export

# Changes to the time
-a always,exit -F arch=x86_64 -S settimeofday -k audit_time_rules
-a always,exit -F arch=x86_64 -S adjtimex -k audit_time_rules
-a always,exit -F arch=x86_64 -S clock_settime -k audit_time_rules
-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules
-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules

# Cron configuration & scheduled jobs
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -k cron

# User, group, password databases
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

# MAC-policy
-w /etc/selinux/ -p wa -k MAC-policy

# Monitor usage of passwd
-w /usr/bin/passwd -p x -k passwd_modification

# Monitor for use of tools to change group identifiers
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification

# Monitor module tools
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules

# Login configuration and information
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/run/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login

# Network configuration
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/network/ -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification

# System startup scripts
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init

# Library search paths
-w /etc/ld.so.conf -p wa -k libpath

# Local time zone
-w /etc/localtime -p wa -k localtime

# Time zone configuration
-w /etc/timezone -p wa -k audit_time_ruleszone

# Kernel parameters
-w /etc/sysctl.conf -p wa -k sysctl

# Modprobe configuration
-w /etc/modprobe.conf -p wa -k modprobe
-w /etc/modprobe.d/ -p wa -k modprobe
-w /etc/modules -p wa -k modprobe

# Module manipulations
-a always,exit -F arch=x86_64 -S init_module -S delete_module -F key=modules
-a always,exit -F arch=x86_64 -S init_module -F key=modules
-a always,exit -F arch=b32 -S init_module -S delete_module -F key=modules
-a always,exit -F arch=b32 -S init_module -F key=modules

# PAM configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam

# Postfix configuration
-w /etc/aliases -p wa -k mail
-w /etc/postfix/ -p wa -k mail

# SSH configuration
-w /etc/ssh/sshd_config -k sshd

# Changes to hostname
-a always,exit -F arch=x86_64 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification

# Changes to issue
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification

# Capture all unauthorized file accesses
-a always,exit -F arch=x86_64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access

# Monitor for use of process ID change (switching accounts) applications
-w /bin/su -p x -k actions
-w /usr/bin/sudo -p x -k actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d -p wa -k actions

# Monitor usage of commands to change power state
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power

# Use of privileged commands
-a always,exit -F path=/bin/fusermount -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/bin/ntfs-3g -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/sbin/pam_extrausers_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/bsd-write -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/cgclassify -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/cgexec -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/expiry -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/locate -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/mlocate -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/newgidmap -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/newuidmap -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/traceroute6.iputils -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/dbus-1.0/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/eject/dmcrypt-get-device -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/libexec/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/policykit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/snapd/snap-confine -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/lib/x86_64-linux-gnu/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/fping6 -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/fping -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/usernetct -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
# Docker
-w /etc/default/docker -k docker
-w /etc/docker -k docker
-w /etc/sysconfig/docker -k docker
-w /etc/sysconfig/docker-network -k docker
-w /etc/sysconfig/docker-registry -k docker
-w /etc/sysconfig/docker-storage -k docker
-w /etc/systemd/system/docker-registry.service -k docker
-w /etc/systemd/system/docker.service -k docker
-w /lib/systemd/system/docker-registry.service -k docker
-w /lib/systemd/system/docker.service -k docker
-w /lib/systemd/system/docker.socket -k docker
-w /usr/bin/containerd -k docker
-w /usr/bin/containerd-shim -k docker
-w /usr/bin/ctr -k docker
-w /usr/bin/docker -k docker
-w /usr/bin/docker-containerd -k docker
-w /usr/bin/docker-containerd-ctr -k docker
-w /usr/bin/docker-containerd-shim -k docker
-w /usr/bin/docker-init -k docker
-w /usr/bin/docker-proxy -k docker
-w /usr/bin/docker-runc -k docker
-w /usr/bin/dockerd -k docker
-w /usr/bin/dockerd-ce -k docker
-w /usr/lib/systemd/system/docker-registry.service -k docker
-w /usr/lib/systemd/system/docker.service -k docker
-w /usr/sbin/runc -k docker
-w /var/lib/docker -k docker
-w /var/run/docker.sock -k docker
# Make the configuration immutable
-e 2

EOF

apt-get install wget > /dev/null 2>&1
cd /tmp
wget https://dl.google.com/go/go1.14.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.14.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /etc/profile

cat <<-EOF > /etc/rsyslog.d/10-syslog.conf
$PreserveFQDN on
##Enable sending of logs over UDP add the following line:

*.* @10.128.1.1:514

##Enable sending of logs over TCP add the following line:

*.* @@10.128.1.1:514

##Set disk queue when rsyslog server will be down:

$ActionQueueFileName queue
$ActionQueueMaxDiskSpace 1g
$ActionQueueSaveOnShutdown on
$ActionQueueType LinkedList
$ActionResumeRetryCount -1
EOF

cat <<-EOF > /etc/apt/apt.conf.d/40unattended-upgrades
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-updates";
        "origin=Debian,codename=${distro_codename},label=Debian";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "o=Debian,a=stable";
        "o=Debian,a=stable-updates";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

cat <<-EOF > /etc/bash.bashrc
# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# don't put duplicate lines in the history. See bash(1) for more options
# ... or force ignoredups and ignorespace
HISTCONTROL=ignoredups:ignorespace

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
    
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
    #PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
    #PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\033[0;31m\]\342\224\214\342\224\200\$([[ \$? != 0 ]] && echo \"[\[\033[0;31m\]\342\234\227\[\033[0;37m\]]\342\224\200\")[$(if [[ ${EUID} == 0 ]]; then echo '\[\033[01;31m\]root\[\033[01;33m\]@\[\033[01;96m\]\h'; else echo '\[\033[0;39m\]\u\[\033[01;33m\]@\[\033[01;96m\]\h'; fi)\[\033[0;31m\]]\342\224\200[\[\033[0;32m\]\w\[\033[0;31m\]]\n\[\033[0;31m\]\342\224\224\342\224\200\342\224\200\342\225\274 \[\033[0m\]\[\e[01;33m\]\\$\[\e[0m\]"
    #PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

if [ -f /etc/bash_completion ] && ! shopt -oq posix; then
    . /etc/bash_completion
fi
EOF

mkdir /etc/iptables
chmod 700 /etc/iptables
cat <<-EOF > /etc/iptables/rules.v4
*filter
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N BLOCK
-I INPUT -i lo -j ACCEPT
-A INPUT -d 127.0.0.0/8 ! -i lo -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p udp -m udp --dport 51820 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -j REJECT --reject-with icmp-port-unreachable
-A FORWARD -i wg0 -o ens3 -j ACCEPT
-A FORWARD -i en3 -o wg0 -j ACCEPT
-A FORWARD -i wg0 -o wg0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m limit --limit 5/min -j LOG --log-prefix "iptables_FORWARD_denied: " --log-level 7
-A FORWARD -m conntrack --ctstate INVALID -j DROP
-A FORWARD -j REJECT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -o wg0 -j ACCEPT
-A OUTPUT -j ACCEPT
-A BLOCK -j REJECT
COMMIT
EOF

cat <<-EOF > /etc/iptables/rules.v6
*filter
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N BLOCK
-I INPUT -i lo -j ACCEPT
-A INPUT -s ::1/128 ! -i lo -j REJECT --reject-with icmp6-port-unreachable
-A INPUT -i wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p udp -m udp --dport 51820 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "ip6tables denied: " --log-level 7
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -j REJECT --reject-with icmp6-port-unreachable
-A FORWARD -i wg0 -o ens3 -j ACCEPT
-A FORWARD -i ens3 -o wg0 -j ACCEPT
-A FORWARD -i wg0 -o wg0 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m limit --limit 5/min -j LOG --log-prefix "ip6tables_FORWARD_denied: " --log-level 7
-A FORWARD -m conntrack --ctstate INVALID -j DROP
-A FORWARD -j REJECT --reject-with icmp6-port-unreachable
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -o wg0 -j ACCEPT
-A OUTPUT -j ACCEPT
-A BLOCK -j REJECT
COMMIT
EOF
