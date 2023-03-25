#!/bin/bash

# Ubuntu 20.04 CIS Benchmark Audit Script

# Print current date and time
echo "Audit started at $(date)"

# Ensure system is running a supported version of Ubuntu 20.04
echo "Ubuntu version:"
lsb_release -a

# Check SSH configuration
echo "SSH Configuration:"
grep -E "^Protocol|^LogLevel|^MaxAuthTries|^IgnoreRhosts|^HostbasedAuthentication|^PermitRootLogin|^PermitEmptyPasswords|^X11Forwarding|^MaxSessions" /etc/ssh/sshd_config

# Check password policy
echo "Password Policy:"
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE" /etc/login.defs

# Check filesystem configuration
echo "Filesystem Configuration:"
grep -E "tmpfs|/tmp|/dev/shm" /etc/fstab
grep -E "nodev|nosuid|noexec" /etc/fstab



# Check cron and at configuration
echo "Cron and At Configuration:"
grep -E "^auth.*required.*pam_wheel.so use_uid" /etc/pam.d/cron
grep -E "^auth.*required.*pam_wheel.so use_uid" /etc/pam.d/atd

# Check kernel parameters
echo "Kernel Parameters:"
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.default.send_redirects
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.default.accept_redirects
sysctl net.ipv4.conf.all.log_martians
sysctl net.ipv4.conf.default.log_martians

# Check network parameters
echo "Network Parameters:"
grep -E "^net.ipv4.conf.all.accept_source_route|^net.ipv4.conf.default.accept_source_route|^net.ipv4.tcp_syncookies|^net.ipv4.conf.all.rp_filter|^net.ipv4.conf.default.rp_filter|^net.ipv4.conf.all.send_redirects|^net.ipv4.conf.default.send_redirects" /etc/sysctl.conf

# Check mandatory access control
echo "Mandatory Access Control:"
apparmor_status

# Check for Telnet and FTP services
echo "Telnet and FTP services:"
systemctl status xinetd.service | grep -E "(telnet|ftp)"

# Check file permissions and ownership for sensitive files and directories
echo "File permissions and ownership:"
ls -l /etc/passwd
ls -l /etc/shadow
ls -l /etc/group
ls -l /etc/sudoers
ls -l /etc/cron.d

# Check for unnecessary network services and ports
echo "Unnecessary network services and ports:"
ss -ltnp

# Check firewall configuration
echo "Firewall configuration:"
ufw status verbose

# Check system software and package updates
echo "System software and package updates:"
apt update
apt list --upgradable



# Disable root login over SSH
if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
    sed -i "s/^PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
else
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi

# Ensure password authentication is disabled for SSH
if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
    sed -i "s/^PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config
else
    echo




# Check filesystem configuration
echo "Filesystem Configuration:"
grep -E "tmpfs|/tmp|/dev/shm" /etc/fstab
grep -E "nodev|nosuid|noexec" /etc/fstab

# Check cron and at configuration
echo "Cron and At Configuration:"
grep -E "^auth.*required.*pam_wheel.so use_uid" /etc/pam.d/cron
grep -E "^auth.*required.*pam_wheel.so use_uid" /etc/pam.d/atd

# Check kernel parameters
echo "Kernel Parameters:"
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.default.send_redirects
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.default.accept_redirects
sysctl net.ipv4.conf.all.log_martians
sysctl net.ipv4.conf.default.log_martians

# Check network parameters
echo "Network Parameters:"
grep -E "^net.ipv4.conf.all.accept_source_route|^net.ipv4.conf.default.accept_source_route|^net.ipv4.tcp_syncookies|^net.ipv4.conf.all.rp_filter|^net.ipv4.conf.default.rp_filter|^net.ipv4.conf.all.send_redirects|^net.ipv4.conf.default.send_redirects" /etc/sysctl.conf

# Check mandatory access control
echo "Mandatory Access Control:"
apparmor_status

# Check software updates configuration
echo "Software Updates Configuration:"
grep -E "^APT::Periodic::Update-Package-Lists|^APT::Periodic::Download-Upgradeable-Packages|^APT::Periodic::AutocleanInterval|^APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades

# Check filesystem integrity checking
echo "Filesystem Integrity Checking:"
grep -E "^FSCKFIX|^AUTOMOUNT" /etc/default/rcS

# Check Secure Boot settings
echo "Secure Boot Settings:"
mokutil --sb-state

# Check AppArmor configuration
echo "AppArmor Configuration:"
if ! dpkg -s apparmor > /dev/null 2>&1; then
  echo "AppArmor is not installed"
else
  echo "AppArmor is installed"
  if grep -q "apparmor=1" /proc/cmdline; then
    echo "AppArmor is enabled in the bootloader configuration"
  else
    echo "AppArmor is not enabled in the bootloader configuration"
  fi
  aa_status | grep -E "^([[:alnum:]_\-]+)\s+(enforce|complain)" | awk '{print $1 " profile is in " $2 " mode"}'
  aa-enforce /etc/apparmor.d/* && echo "All AppArmor profiles are enforcing"
fi

# Check command line warning banners
echo "Command Line Warning Banners:"
grep -E "^auth.*required.*pam_warn.so" /etc/pam.d/common-auth


# Ensure root owns /etc/motd
if [[ $(stat -c %U:%G /etc/motd) != "root:root" ]]; then
  echo "FAILURE: /etc/motd is not owned by root"
fi

# Ensure /etc/motd is not group or world writable
if [[ $(stat -c %a /etc/motd) != "644" ]]; then
  echo "FAILURE: /etc/motd permissions are not set to 644"
fi

# Ensure root owns /etc/issue
if [[ $(stat -c %U:%G /etc/issue) != "root:root" ]]; then
  echo "FAILURE: /etc/issue is not owned by root"
fi

# Ensure /etc/issue is not group or world writable
if [[ $(stat -c %a /etc/issue) != "644" ]]; then
  echo "FAILURE: /etc/issue permissions are not set to 644"
fi

# Ensure root owns /etc/issue.net
if [[ $(stat -c %U:%G /etc/issue.net) != "root:root" ]]; then
  echo "FAILURE: /etc/issue.net is not owned by root"
fi

# Ensure /etc/issue.net is not group or world writable
if [[ $(stat -c %a /etc/issue.net) != "644" ]]; then
  echo "FAILURE: /etc/issue.net permissions are not set to 644"
fi

# Ensure login warning banner is configured properly
if [[ $(grep -i "Authorized uses only" /etc/issue) == "" ]]; then
  echo "FAILURE: Login warning banner is not configured properly in /etc/issue"
fi

# Ensure remote login warning banner is configured properly
if [[ $(grep -i "Authorized uses only" /etc/issue.net) == "" ]]; then
  echo "FAILURE: Remote login warning banner is not configured properly in /etc/issue.net"
fi

# Ensure permissions on /etc/motd are configured properly
if [[ $(stat -c %a /etc/motd) != "644" ]]; then
  echo "FAILURE: Permissions on /etc/motd are not configured properly"
fi

# Ensure permissions on /etc/issue are configured properly
if [[ $(stat -c %a /etc/issue) != "644" ]]; then
  echo "FAILURE: Permissions on /etc/issue are not configured properly"
fi

# Ensure permissions on /etc/issue.net are configured properly
if [[ $(stat -c %a /etc/issue.net) != "644" ]]; then
  echo "FAILURE: Permissions on /etc/issue.net are not configured properly"
fi

# Ensure AppArmor is installed
if ! dpkg -s apparmor &> /dev/null; then
  echo "AppArmor is not installed."
fi

# Ensure AppArmor is enabled in the bootloader configuration
if ! grep "apparmor=1" /boot/grub/grub.cfg &> /dev/null; then
  echo "AppArmor is not enabled in the bootloader configuration."
fi

# Ensure all AppArmor Profiles are in enforce or complain mode
for profile in $(aa-status --enabled | awk '{print $1}'); do
  mode=$(aa-status $profile | awk '/^Mode:/{print $2}')
  if [[ "$mode" != "enforce" && "$mode" != "complain" ]]; then
    echo "Profile $profile is not in enforce or complain mode."
  fi
done

# Ensure all AppArmor Profiles are enforcing
if aa-status | grep -q "0 profiles are in complain mode."; then
  echo "All AppArmor profiles are not enforcing."
fi

# Ensure message of the day is configured properly
if ! grep "Authorized uses only. All activity may be monitored and reported." /etc/motd &> /dev/null; then
  echo "Message of the day is not configured properly."
fi

# Ensure local login warning banner is configured properly
if ! grep "Authorized uses only. All activity may be monitored and reported." /etc/issue &> /dev/null; then
  echo "Local login warning banner is not configured properly."
fi

# Ensure remote login warning banner is configured properly
if ! grep "Authorized uses only. All activity may be monitored and reported." /etc/issue.net &> /dev/null; then
  echo "Remote login warning banner is not configured properly."
fi

# Ensure permissions on /etc/motd are configured
if [[ "$(stat -c %a /etc/motd)" -ne "644" ]]; then
  echo "Permissions on /etc/motd are not configured properly."
fi

# Ensure permissions on /etc/issue are configured
if [[ "$(stat -c %a /etc/issue)" -ne "644" ]]; then
  echo "Permissions on /etc/issue are not configured properly."
fi

# Ensure permissions on /etc/issue.net are configured
if [[ "$(stat -c %a /etc/issue.net)" -ne "644" ]]; then
  echo "Permissions on /etc/issue.net are not configured properly."
fi

# Ensure GNOME Display Manager is removed
if dpkg -s gdm3 &> /dev/null; then
  echo "GNOME Display Manager is installed."
fi


# Ensure /tmp is configured
if [ -z "$(mount | grep 'on /tmp type')" ]; then
  echo "/tmp is not a separate partition"
fi

# Ensure nodev option set on /tmp partition
if [ -z "$(mount | grep 'on /tmp type .*nodev')" ]; then
  echo "nodev option is not set on /tmp partition"
fi

# Ensure nosuid option set on /tmp partition
if [ -z "$(mount | grep 'on /tmp type .*nosuid')" ]; then
  echo "nosuid option is not set on /tmp partition"
fi

# Ensure noexec option set on /tmp partition
if [ -z "$(mount | grep 'on /tmp type .*noexec')" ]; then
  echo "noexec option is not set on /tmp partition"
fi

# Ensure /dev/shm is configured
if [ -z "$(mount | grep 'on /dev/shm type')" ]; then
  echo "/dev/shm is not a separate partition"
fi

# Ensure nodev option set on /dev/shm partition
if [ -z "$(mount | grep 'on /dev/shm type .*nodev')" ]; then
  echo "nodev option is not set on /dev/shm partition"
fi

# Ensure nosuid option set on /dev/shm partition
if [ -z "$(mount | grep 'on /dev/shm type .*nosuid')" ]; then
  echo "nosuid option is not set on /dev/shm partition"
fi

# Ensure noexec option set on /dev/shm partition
if [ -z "$(mount | grep 'on /dev/shm type .*noexec')" ]; then
  echo "noexec option is not set on /dev/shm partition"
fi

# Ensure separate partition exists for /var
if [ -z "$(mount | grep 'on /var type')" ]; then
  echo "/var is not a separate partition"
fi

# Ensure separate partition exists for /var/tmp
if [ -z "$(mount | grep 'on /var/tmp type')" ]; then
  echo "/var/tmp is not a separate partition"
fi

# Ensure /var/tmp partition includes the nodev option
if [ -z "$(mount | grep 'on /var/tmp type .*nodev')" ]; then
  echo "nodev option is not set on /var/tmp partition"
fi

# Ensure /var/tmp partition includes the nosuid option
if [ -z "$(mount | grep 'on /var/tmp type .*nosuid')" ]; then
  echo "nosuid option is not set on /var/tmp partition"
fi

# Ensure /var/tmp partition includes the noexec option
if [ -z "$(mount | grep 'on /var/tmp type .*noexec')" ]; then
  echo "noexec option is not set on /var/tmp partition"
fi

# Ensure separate partition exists for /var/log
if [ -z "$(mount | grep 'on /var/log type')" ]; then
  echo "/var/log is not a separate partition"
fi

# Ensure separate partition exists for /var/log/audit
if [ -z "$(mount | grep 'on /var/log/audit type')" ]; then
  echo "/var/log/audit is not a separate partition"
fi


# Ensure separate partition exists for /home
if grep -q " /home " /etc/fstab; then
  echo "/home is on a separate partition"
else
  echo "/home is not on a separate partition"
fi

# Ensure /home partition includes the nodev option
if mount | grep " /home " | grep -q "nodev"; then
  echo "/home partition includes the nodev option"
else
  echo "/home partition does not include the nodev option"
fi

# Ensure nodev option set on removable media partitions
if grep -q "nodev" /etc/fstab; then
  echo "nodev option is set on removable media partitions"
else
  echo "nodev option is not set on removable media partitions"
fi

# Ensure nosuid option set on removable media partitions
if grep -q "nosuid" /etc/fstab; then
  echo "nosuid option is set on removable media partitions"
else
  echo "nosuid option is not set on removable media partitions"
fi

# Ensure noexec option set on removable media partitions
if grep -q "noexec" /etc/fstab; then
  echo "noexec option is set on removable media partitions"
else
  echo "noexec option is not set on removable media partitions"
fi

# Ensure sticky bit is set on all world-writable directories
if find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print | grep -q "/"; then
  echo "Sticky bit is set on all world-writable directories"
else
  echo "Sticky bit is not set on all world-writable directories"
fi

# Disable Automounting
if systemctl is-enabled autofs.service | grep -q "enabled"; then
  echo "Automounting is enabled and should be disabled"
else
  echo "Automounting is disabled"
fi

# Disable USB Storage
if modprobe -n -v usb-storage | grep -q "install /bin/true"; then
	echo " USB storage is disabled"
else
	echo "USB stroage is enabled"
fi



# Check if package manager repositories are configured
if [ -z "$(apt-cache policy | grep 'Packages' | awk '{print $2}' | uniq)" ]; then
  echo "Package manager repositories are not configured"
else
  echo "Package manager repositories are configured"
fi

# Check if GPG keys are configured
if [ -z "$(apt-key list | grep -v expired | grep -v pub)" ]; then
  echo "GPG keys are not configured"
else
  echo "GPG keys are configured"
fi


# Ensure AIDE is installed
if ! dpkg -s aide > /dev/null 2>&1; then
    echo "AIDE is not installed"
else
    echo "AIDE is installed"
fi

# Ensure file system integrity is regularly checked
if ! grep -q "aide" /etc/crontab; then
    echo "File system integrity check not configured"
else
    echo "File system integrity check configured"
fi


# Ensure permissions on bootloader config are not overridden
if [[ $(stat -L -c "%a" /boot/grub/grub.cfg) == *"00"* ]]; then
  echo "PASS - Permissions on bootloader config are not overridden"
else
  echo "FAIL - Permissions on bootloader config are overridden"
fi

# Ensure bootloader password is set
if [[ $(grep "^set superusers" /boot/grub/grub.cfg) && $(grep "^password" /boot/grub/grub.cfg) ]]; then
  echo "PASS - Bootloader password is set"
else
  echo "FAIL - Bootloader password is not set"
fi

# Ensure permissions on bootloader config are configured
if [[ $(stat -L -c "%a" /boot/grub/grub.cfg) == "600" ]]; then
  echo "PASS - Permissions on bootloader config are configured"
else
  echo "FAIL - Permissions on bootloader config are not configured"
fi

# Ensure authentication required for single user mode
if [[ $(grep ^SINGLE /etc/sysconfig/init) == "SINGLE=/sbin/sulogin" ]]; then
  echo "PASS - Authentication required for single user mode"
else
  echo "FAIL - Authentication not required for single user mode"
fi

# Ensure XD/NX support is enabled
if [[ $(dmesg | grep "NX (Execute Disable) protection: active") ]]; then
  echo "PASS - XD/NX support is enabled"
else
  echo "FAIL - XD/NX support is not enabled"
fi

# Ensure address space layout randomization (ASLR) is enabled
if [[ $(sysctl kernel.randomize_va_space) == "kernel.randomize_va_space = 2" ]]; then
  echo "PASS - ASLR is enabled"
else
  echo "FAIL - ASLR is not enabled"
fi

# Ensure prelink is not installed
if [[ $(rpm -q prelink) == "package prelink is not installed" ]]; then
  echo "PASS - prelink is not installed"
else
  echo "FAIL - prelink is installed"
fi	


# Ensure GNOME Display Manager is removed
if [[ $(systemctl status gdm.service &> /dev/null; echo $?) -eq 0 ]]; then
    echo "GNOME Display Manager is installed. Please remove it."
else
    echo "GNOME Display Manager is not installed."
fi

# Ensure GDM login banner is configured
if [[ $(grep "^banner-message-enable=true" /etc/gdm/custom.conf &> /dev/null; echo $?) -eq 0 ]]; then
    echo "GDM login banner is configured."
else
    echo "GDM login banner is not configured. Please configure it."
fi

# Ensure disable-user-list is enabled
if [[ $(grep "^disable-user-list=true" /etc/gdm/custom.conf &> /dev/null; echo $?) -eq 0 ]]; then
    echo "disable-user-list is enabled."
else
    echo "disable-user-list is not enabled. Please enable it."
fi

# Ensure XDCMP is not enabled
if [[ $(systemctl status xdmcp.service &> /dev/null; echo $?) -eq 0 ]]; then
    echo "XDCMP is enabled. Please disable it."
else
    echo "XDCMP is not enabled."
fi

# Ensure updates, patches, and additional security software are installed
echo "Checking for updates..."
yum check-update &> /dev/null
if [[ $? -eq 100 ]]; then
    echo "Updates are available. Please install them."
else
    echo "System is up to date."
fi


# Ensure GNOME Display Manager is removed
if [[ $(systemctl status gdm.service &> /dev/null; echo $?) -eq 0 ]]; then
    echo "GNOME Display Manager is installed. Please remove it."
else
    echo "GNOME Display Manager is not installed."
fi

# Ensure GDM login banner is configured
if [[ $(grep "^banner-message-enable=true" /etc/gdm/custom.conf &> /dev/null; echo $?) -eq 0 ]]; then
    echo "GDM login banner is configured."
else
    echo "GDM login banner is not configured. Please configure it."
fi

# Ensure disable-user-list is enabled
if [[ $(grep "^disable-user-list=true" /etc/gdm/custom.conf &> /dev/null; echo $?) -eq 0 ]]; then
    echo "disable-user-list is enabled."
else
    echo "disable-user-list is not enabled. Please enable it."
fi

# Ensure XDCMP is not enabled
if [[ $(systemctl status xdmcp.service &> /dev/null; echo $?) -eq 0 ]]; then
    echo "XDCMP is enabled. Please disable it."
else
    echo "XDCMP is not enabled."
fi

# Ensure updates, patches, and additional security software are installed
echo "Checking for updates..."
yum check-update &> /dev/null
if [[ $? -eq 100 ]]; then
    echo "Updates are available. Please install them."
else
    echo "System is up to date."
fi

# End of script
echo "Script execution completed."


# Ensure time synchronization is in use
echo "Checking if time synchronization is in use"
timedatectl status | grep "synchronized" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "Time synchronization is in use"
else
  echo "Time synchronization is not in use"
fi

# Ensure systemd-timesyncd is configured
echo "Checking if systemd-timesyncd is configured"
systemctl is-enabled systemd-timesyncd > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "systemd-timesyncd is configured"
else
  echo "systemd-timesyncd is not configured"
fi

# Ensure chrony is configured
echo "Checking if chrony is configured"
systemctl is-enabled chronyd > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "chrony is configured"
else
  echo "chrony is not configured"
fi

# Ensure ntp is configured
echo "Checking if ntp is configured"
systemctl is-enabled ntpd > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "ntp is configured"
else
  echo "ntp is not configured"
fi

# Ensure X Window System is not installed
echo "Checking if X Window System is installed"
if [ -z "$(rpm -qa xorg-x11-server-common)" ]; then
  echo "X Window System is not installed"
else
  echo "X Window System is installed"
fi

# Ensure Avahi Server is not installed
echo "Checking if Avahi Server is installed"
if [ -z "$(rpm -qa avahi)" ]; then
  echo "Avahi Server is not installed"
else
  echo "Avahi Server is installed"
fi

# Ensure CUPS is not installed
echo "Checking if CUPS is installed"
if [ -z "$(rpm -qa cups)" ]; then
  echo "CUPS is not installed"
else
  echo "CUPS is installed"
fi


# Ensure time synchronization is in use
timedatectl status > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo "Time synchronization is in use."
else
    echo "Time synchronization is not in use."
fi

# Ensure systemd-timesyncd is configured
systemctl is-enabled systemd-timesyncd > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo "systemd-timesyncd is enabled."
else
    echo "systemd-timesyncd is not enabled."
fi

# Ensure chrony is configured
systemctl is-enabled chrony > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo "chrony is enabled."
else
    echo "chrony is not enabled."
fi

# Ensure ntp is configured
systemctl is-enabled ntp > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo "ntp is enabled."
else
    echo "ntp is not enabled."
fi

# Ensure X Window System is not installed
if ! rpm -q xorg-x11-server-Xorg > /dev/null 2>&1; then
    echo "X Window System is not installed."
else
    echo "X Window System is installed."
fi

# Ensure Avahi Server is not installed
if ! rpm -q avahi > /dev/null 2>&1; then
    echo "Avahi Server is not installed."
else
    echo "Avahi Server is installed."
fi

# Ensure CUPS is not installed
if ! rpm -q cups > /dev/null 2>&1; then
    echo "CUPS is not installed."
else
    echo "CUPS is installed."
fi

# Ensure DHCP Server is not installed
if ! rpm -q dhcp-server > /dev/null 2>&1; then
    echo "DHCP Server is not installed."
else
    echo "DHCP Server is installed."
fi

# Ensure LDAP server is not installed
if ! rpm -q openldap-servers > /dev/null 2>&1; then
    echo "LDAP server is not installed."
else
    echo "LDAP server is installed."
fi

# Ensure NFS is not installed
if ! rpm -q nfs-utils > /dev/null 2>&1; then
    echo "NFS is not installed."
else
    echo "NFS is installed."
fi

# Ensure DNS Server is not installed
if ! rpm -q bind > /dev/null 2>&1; then
    echo "DNS Server is not installed."
else
    echo "DNS Server is installed."
fi

# Ensure FTP Server is not installed
if ! rpm -q vsftpd > /dev/null 2>&1; then
    echo "FTP Server is not installed."
else
    echo "FTP Server is installed."
fi

# Ensure HTTP server is not installed
if ! rpm -q httpd > /dev/null 2>&1; then
    echo "HTTP server is not installed."
else
    echo "HTTP server is installed."
fi

# Ensure IMAP and POP3 server are not installed
if ! rpm -q dovecot > /dev/null 2>&1; then
    echo "IMAP and POP3 server are not installed."
else
    echo "IMAP and POP3 server are installed."
fi


# Ensure Samba is not installed
if [[ $(dpkg-query -W -f='${Status}' samba 2>/dev/null | grep -c "ok installed") -eq 1 ]]; then
  echo "Samba is installed. Please remove it."
else
  echo "Samba is not installed."
fi

# Ensure HTTP Proxy Server is not installed
if [[ $(dpkg-query -W -f='${Status}' squid 2>/dev/null | grep -c "ok installed") -eq 1 ]]; then
  echo "Squid (HTTP Proxy Server) is installed. Please remove it."
else
  echo "Squid (HTTP Proxy Server) is not installed."
fi

# Ensure SNMP Server is not installed
if [[ $(dpkg-query -W -f='${Status}' snmpd 2>/dev/null | grep -c "ok installed") -eq 1 ]]; then
  echo "SNMP Server is installed. Please remove it."
else
  echo "SNMP Server is not installed."
fi

# Ensure mail transfer agent is configured for local-only mode
if [[ $(dpkg-query -W -f='${Status}' postfix 2>/dev/null | grep -c "ok installed") -eq 1 ]]; then
  if [[ $(grep -c "^inet_interfaces\s*=.*localhost" /etc/postfix/main.cf) -eq 1 ]]; then
    echo "Postfix is installed and configured for local-only mode."
  else
    echo "Postfix is installed but not configured for local-only mode. Please configure it."
  fi
else
  echo "Postfix is not installed."
fi

# Ensure rsync service is not installed
if [[ $(dpkg-query -W -f='${Status}' rsync 2>/dev/null | grep -c "ok installed") -eq 1 ]]; then
  echo "rsync service is installed. Please remove it."
else
  echo "rsync service is not installed."
fi

# Ensure NIS Client is not installed
if [[ $(dpkg -s nis 2>/dev/null | grep Status) != "Status: deinstall ok config-files"* ]]; then
    echo "NIS Client is installed. Please remove it."
else
    echo "NIS Client is not installed."
fi

# Ensure rsh client is not installed
if [[ $(dpkg -s rsh-client 2>/dev/null | grep Status) != "Status: deinstall ok config-files"* ]]; then
    echo "rsh client is installed. Please remove it."
else
    echo "rsh client is not installed."
fi

# Ensure talk client is not installed
if [[ $(dpkg -s talk 2>/dev/null | grep Status) != "Status: deinstall ok config-files"* ]]; then
    echo "talk client is installed. Please remove it."
else
    echo "talk client is not installed."
fi

# Ensure telnet client is not installed
if [[ $(dpkg -s telnet 2>/dev/null | grep Status) != "Status: deinstall ok config-files"* ]]; then
    echo "telnet client is installed. Please remove it."
else
    echo "telnet client is not installed."
fi

# Ensure LDAP client is not installed
if [[ $(dpkg -s ldap-utils 2>/dev/null | grep Status) != "Status: deinstall ok config-files"* ]]; then
    echo "LDAP client is installed. Please remove it."
else
    echo "LDAP client is not installed."
fi

# Ensure RPC is not installed
if [[ $(dpkg -s rpcbind 2>/dev/null | grep Status) != "Status: deinstall ok config-files"* ]]; then
    echo "RPC is installed. Please remove it."
else
    echo "RPC is not installed."
fi

# Ensure nonessential services are removed or masked
systemctl list-unit-files | grep -E "(enabled|masked)" | grep -E "(rpcbind|nis|talk|telnet|ntalk|ypbind)" && echo "Please disable or mask the above services." || echo "No nonessential services found."


# Ensure IPv6 is disabled
ipv6_enabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
if [ $ipv6_enabled -eq 0 ]; then
    echo "IPv6 is enabled. Please disable IPv6."
else
    echo "IPv6 is disabled."
fi

# Ensure wireless interfaces are disabled
wireless_enabled=$(rfkill list wifi | grep -o "Soft blocked:.*" | grep -c "no")
if [ $wireless_enabled -eq 1 ]; then
    echo "Wireless interfaces are enabled. Please disable wireless interfaces."
else
    echo "Wireless interfaces are disabled."
fi

# Ensure packet redirect sending is disabled
packet_redirects=$(cat /proc/sys/net/ipv4/conf/all/send_redirects)
if [ $packet_redirects -eq 1 ]; then
    echo "Packet redirect sending is enabled. Please disable packet redirect sending."
else
    echo "Packet redirect sending is disabled."
fi

# Ensure IP forwarding is disabled
ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)
if [ $ip_forward -eq 1 ]; then
    echo "IP forwarding is enabled. Please disable IP forwarding."
else
    echo "IP forwarding is disabled."
fi

# Ensure source routed packets are not accepted
source_routed=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route)
if [ $source_routed -eq 1 ]; then
    echo "Source routed packets are accepted. Please disable source routed packets."
else
    echo "Source routed packets are not accepted."
fi

# Ensure ICMP redirects are not accepted
icmp_redirects=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects)
if [ $icmp_redirects -eq 1 ]; then
    echo "ICMP redirects are accepted. Please disable ICMP redirects."
else
    echo "ICMP redirects are not accepted."
fi

# Ensure secure ICMP redirects are not accepted
secure_icmp_redirects=$(cat /proc/sys/net/ipv4/conf/all/secure_redirects)
if [ $secure_icmp_redirects -eq 0 ]; then
    echo "Secure ICMP redirects are not disabled. Please disable secure ICMP redirects."
else
    echo "Secure ICMP redirects are disabled."
fi

# Ensure suspicious packets are logged
suspicious_packets=$(cat /proc/sys/net/ipv4/conf/all/log_martians)
if [ $suspicious_packets -eq 0 ]; then
    echo "Suspicious packets are not logged. Please enable logging of suspicious packets."
else
    echo "Suspicious packets are logged."
fi

# Ensure broadcast ICMP requests are ignored
broadcast_icmp=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts)
if [ $broadcast_icmp -eq 0 ]; then
    echo "Broadcast ICMP requests are not ignored. Please ignore broadcast ICMP requests."
else
    echo "Broadcast ICMP requests are ignored."
fi

# Ensure bogus ICMP responses are ignored
bogus_icmp=$(cat /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses)
if [ $bogus_icmp -eq 0 ]; then
    echo "Bogus ICMP responses are not ignored. Please ignore bogus ICMP responses."
else
    echo "Bogus ICMP responses are ignored."
fi



# Ensure wireless interfaces are disabled
if [[ $(ip link | grep wlan) ]]; then
  echo "Wireless interfaces are enabled."
else
  echo "Wireless interfaces are disabled."
fi

# Ensure packet redirect sending is disabled
if [[ $(sysctl net.ipv4.conf.all.send_redirects) == "net.ipv4.conf.all.send_redirects = 0" ]]; then
  echo "Packet redirect sending is disabled."
else
  echo "Packet redirect sending is enabled."
fi

# Ensure IP forwarding is disabled
if [[ $(sysctl net.ipv4.ip_forward) == "net.ipv4.ip_forward = 0" ]]; then
  echo "IP forwarding is disabled."
else
  echo "IP forwarding is enabled."
fi

# Ensure source routed packets are not accepted
if [[ $(sysctl net.ipv4.conf.all.accept_source_route) == "net.ipv4.conf.all.accept_source_route = 0" ]]; then
  echo "Source routed packets are not accepted."
else
  echo "Source routed packets are accepted."
fi

# Ensure ICMP redirects are not accepted
if [[ $(sysctl net.ipv4.conf.all.accept_redirects) == "net.ipv4.conf.all.accept_redirects = 0" ]]; then
  echo "ICMP redirects are not accepted."
else
  echo "ICMP redirects are accepted."
fi

# Ensure secure ICMP redirects are not accepted
if [[ $(sysctl net.ipv4.conf.all.secure_redirects) == "net.ipv4.conf.all.secure_redirects = 0" ]]; then
  echo "Secure ICMP redirects are not accepted."
else
  echo "Secure ICMP redirects are accepted."
fi

# Ensure suspicious packets are logged
if [[ $(sysctl net.ipv4.conf.all.log_martians) == "net.ipv4.conf.all.log_martians = 1" ]]; then
  echo "Suspicious packets are logged."
else
  echo "Suspicious packets are not logged."
fi

# Ensure broadcast ICMP requests are ignored
if [[ $(sysctl net.ipv4.icmp_echo_ignore_broadcasts) == "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]]; then
  echo "Broadcast ICMP requests are ignored."
else
  echo "Broadcast ICMP requests are not ignored."
fi

# Ensure bogus ICMP responses are ignored
if [[ $(sysctl net.ipv4.icmp_ignore_bogus_error_responses) == "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]]; then
  echo "Bogus ICMP responses are ignored."
else
  echo "Bogus ICMP responses are not ignored."
fi

# Ensure Reverse Path Filtering is enabled
if [[ $(sysctl net.ipv4.conf.all.rp_filter) == "net.ipv4.conf.all.rp_filter = 1" ]]; then
  echo "Reverse Path Filtering is enabled."
else
  echo "Reverse Path Filtering is not enabled."
fi

# Ensure TCP SYN Cookies is enabled
if [[ $(sysctl net.ipv4.tcp_syncookies) == "net.ipv4.tcp_syncookies = 1" ]]; then
  echo "TCP SYN Cookies is enabled."
else
  echo "TCP SYN Cookies is not enabled."
fi

# Ensure IPv6 router advertisements are not accepted
if [[ $(sysctl net.ipv6.conf.all.accept_ra) == "net.ipv6.conf.all.accept_ra = 0" ]]; then
  echo "IPv6 router advertisements are not accepted."
else
  echo "IPv6 router advertisements are accepted."
fi


# Ensure SCTP is disabled
if [[ $(modprobe -n -v sctp) == *"install /bin/true "* ]] && [[ $(lsmod | grep sctp) == "" ]]; then
  echo "SCTP is disabled"
else
  echo "SCTP is enabled"
fi

# Ensure RDS is disabled
if [[ $(modprobe -n -v rds) == *"install /bin/true "* ]] && [[ $(lsmod | grep rds) == "" ]]; then
  echo "RDS is disabled"
else
  echo "RDS is enabled"
fi

# Ensure TIPC is disabled
if [[ $(modprobe -n -v tipc) == *"install /bin/true "* ]] && [[ $(lsmod | grep tipc) == "" ]]; then
  echo "TIPC is disabled"
else
  echo "TIPC is enabled"
fi

# Ensure ufw is installed
if [[ $(dpkg -s ufw 2>/dev/null | grep "Status: install ok installed") ]]; then
  echo "ufw is installed"
else
  echo "ufw is not installed"
fi

# Ensure iptables-persistent is not installed with ufw
if [[ $(dpkg -s iptables-persistent 2>/dev/null | grep "Status: install ok installed") ]] && [[ $(dpkg -s ufw 2>/dev/null | grep "Status: install ok installed") ]]; then
  echo "iptables-persistent is installed with ufw"
else
  echo "iptables-persistent is not installed with ufw"
fi

# Ensure ufw service is enabled
if [[ $(systemctl is-enabled ufw) == "enabled" ]]; then
  echo "ufw service is enabled"
else
  echo "ufw service is not enabled"
fi

# Ensure ufw loopback traffic is configured
if [[ $(ufw status | grep "Anywhere on lo") == *"ALLOW"* ]]; then
  echo "ufw loopback traffic is configured"
else
  echo "ufw loopback traffic is not configured"
fi

# Ensure ufw outbound connections are configured
if [[ $(ufw status | grep "Anywhere out") == *"ALLOW"* ]]; then
  echo "ufw outbound connections are configured"
else
  echo "ufw outbound connections are not configured"
fi

# Ensure ufw firewall rules exist for all open ports
if [[ $(ufw status | grep "Status: active") ]] && [[ $(ss -tulwn | grep "LISTEN" | awk '{print $5}' | cut -d":" -f2 | sort -u) == $(ufw status | grep "ALLOW IN" | awk '{print $1}' | cut -d"/" -f1 | sort -u) ]]; then
  echo "ufw firewall rules exist for all open ports"
else
  echo "ufw firewall rules do not exist for all open ports"
fi

# Ensure ufw default deny firewall policy
if [[ $(ufw status | grep "Default: deny (incoming), allow (outgoing), disabled (routed)") ]]; then
  echo "ufw default deny firewall policy is configured"
else
  echo "ufw default deny firewall policy is not configured"
fi

# Ensure nftables is installed
if [[ $(dpkg -s nftables 2>/dev/null | grep "Status: install ok installed") ]]; then
  echo "nftables is installed"
else
  echo "nftables is not installed"
fi


# Ensure auditd is installed
if ! command -v auditd &> /dev/null
then
    echo "auditd is not installed!"
    exit 1
fi

# Ensure auditd service is enabled
if ! systemctl is-enabled auditd &> /dev/null
then
    echo "auditd service is not enabled!"
    exit 1
fi

# Ensure auditing for processes that start prior to auditd is enabled
if [[ $(grep "^[[:space:]]*linux" /boot/grub2/grub.cfg | grep -v "audit=1") ]]
then
    echo "Auditing for processes that start prior to auditd is not enabled!"
    exit 1
fi

# Ensure audit_backlog_limit is sufficient
if [[ $(grep "^space_left_action" /etc/audit/auditd.conf | awk '{print $3}') -lt 1024 ]]
then
    echo "audit_backlog_limit is not sufficient!"
    exit 1
fi

# Ensure audit log storage size is configured
if [[ $(grep "^max_log_file" /etc/audit/auditd.conf | awk '{print $3}') -lt 1024 ]]
then
    echo "audit log storage size is not sufficient!"
    exit 1
fi

# Ensure audit logs are not automatically deleted
if [[ $(grep "^max_log_file_action" /etc/audit/auditd.conf | awk '{print $3}') != "keep_logs" ]]
then
    echo "Audit logs are set to be automatically deleted!"
    exit 1
fi

# Ensure system is disabled when audit logs are full
if [[ $(grep "^space_left_action" /etc/audit/auditd.conf | awk '{print $3}') != "email" ]]
then
    echo "System is not disabled when audit logs are full!"
    exit 1
fi

# Ensure events that modify date and time information are collected
if [[ $(grep time-change /etc/audit/rules.d/*.rules | wc -l) -eq 0 ]]
then
    echo "Events that modify date and time information are not collected!"
    exit 1
fi

# Ensure events that modify user/group information are collected
if [[ $(grep identity /etc/audit/rules.d/*.rules | wc -l) -eq 0 ]]
then
    echo "Events that modify user/group information are not collected!"
    exit 1
fi

# Ensure events that modify the system's network environment are collected
if [[ $(grep system-locale /etc/audit/rules.d/*.rules | wc -l) -eq 0 ]]
then
    echo "Events that modify the system's network environment are not collected!"
    exit 1
fi

# Ensure events that modify the system's Mandatory Access Controls are collected
if [[ $(grep MAC-policy /etc/audit/rules.d/*.rules | wc -l) -eq 0 ]]
then
    echo "Events that modify the system's Mandatory Access Controls are not collected!"
    exit 1
fi

# Ensure login and logout events are collected
if [[ $(grep logins /etc/audit/rules.d/*.rules | wc -l) -eq 0 ]]
then
    echo "Login and logout events are not collected!"
    exit 1
fi

# Ensure session initiation information is collected
if [[ $(grep session /etc/audit/rules.d/*.rules | wc -l) -eq 0 ]]
then
    echo "Session initiation information is not collected!"
    exit 1
fi


# Ensure discretionary access control permission modification events are collected
#grep "^ *-a always,exit .* perm_mod$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchown,fchownat -F auid>=1000 -F auid!=-1 -k perm_mod" >> /etc/audit/audit.rules
#grep "^ *-a always,exit .* perm_mod$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,fchown,fchownat -F auid>=1000 -F auid!=-1 -k perm_mod" >> /etc/audit/audit.rules

# Ensure unsuccessful unauthorized file access attempts are collected
#grep "^ *-a always,exit .* access$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access" >> /etc/audit/audit.rules
#grep "^ *-a always,exit .* access$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access" >> /etc/audit/audit.rules

# Ensure use of privileged commands is collected
#grep "^ *-a always,exit .* privileged$" /etc/audit/audit.rules || echo "-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=-1 -k privileged" >> /etc/audit/audit.rules
#grep "^ *-a always,exit .* privileged$" /etc/audit/audit.rules || echo "-a always,exit -F path=/usr/bin/sudoedit -F auid>=1000 -F auid!=-1 -k privileged" >> /etc/audit/audit.rules

# Ensure successful file system mounts are collected
#grep "^ *-a always,exit .* mounts$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts" >> /etc/audit/audit.rules
#grep "^ *-a always,exit .* mounts$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts" >> /etc/audit/audit.rules

# Ensure file deletion events by users are collected
#grep "^ *-a always,exit .* delete$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k delete" >> /etc/audit/audit.rules
#grep "^ *-a always,exit .* delete$" /etc/audit/audit.rules || echo "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k delete" >> /etc/audit/audit.rules


# Ensure changes to system administration scope (sudoers) is collected
if [[ $(grep "^-a always,exit -F path=/etc/sudoers -F perm=wa -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change$" /etc/audit/rules.d/*.rules) ]]; then
  echo "PASS - Changes to system administration scope (sudoers) is being collected"
else
  echo "FAIL - Changes to system administration scope (sudoers) is not being collected"
fi

# Ensure system administrator command executions (sudo) are collected
if [[ $(grep "^-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change$" /etc/audit/rules.d/*.rules) ]]; then
  echo "PASS - System administrator command executions (sudo) are being collected"
else
  echo "FAIL - System administrator command executions (sudo) are not being collected"
fi

# Ensure kernel module loading and unloading is collected
if [[ $(grep "^-w /sbin/insmod -p x -k modules$" /etc/audit/rules.d/*.rules) && $(grep "^-w /sbin/rmmod -p x -k modules$" /etc/audit/rules.d/*.rules) && $(grep "^-w /sbin/modprobe -p x -k modules$" /etc/audit/rules.d/*.rules) ]]; then
  echo "PASS - Kernel module loading and unloading is being collected"
else
  echo "FAIL - Kernel module loading and unloading is not being collected"
fi

# Ensure the audit configuration is immutable
if [[ $(grep "^-e 2$" /etc/audit/rules.d/*.rules) ]]; then
  echo "PASS - The audit configuration is immutable"
else
  echo "FAIL - The audit configuration is not immutable"
fi


# Ensure rsyslog is installed
if ! command -v rsyslog >/dev/null 2>&1; then
    echo "rsyslog is not installed"
fi

# Ensure rsyslog service is enabled
if ! systemctl is-enabled rsyslog.service >/dev/null 2>&1; then
    echo "rsyslog service is not enabled"
fi

# Ensure logging is configured
if ! grep -q "^*.*[^I][^I]*@" /etc/rsyslog.conf; then
    echo "logging is not configured"
fi

# Ensure rsyslog default file permissions configured
if ! grep -q "^\$FileCreateMode " /etc/rsyslog.conf || [[ $(grep "^\$FileCreateMode " /etc/rsyslog.conf | awk '{print $2}') -gt 640 ]]; then
    echo "rsyslog default file permissions are not configured"
fi

# Ensure rsyslog is configured to send logs to a remote log host
if ! grep -q "^*.*[^I][^I]*@@[a-zA-Z0-9\.-]+" /etc/rsyslog.conf; then
    echo "rsyslog is not configured to send logs to a remote log host"
fi

# Ensure remote rsyslog messages are only accepted on designated log hosts
if ! grep -q "^\$ModLoad imtcp.so" /etc/rsyslog.conf && grep -q "^\$InputTCPServerRun" /etc/rsyslog.conf; then
    echo "rsyslog is not configured to accept remote messages"
fi

# Ensure cron daemon is enabled and running
systemctl is-enabled cron &> /dev/null
if [ $? -eq 0 ]; then
  echo "PASS - Cron daemon is enabled"
else
  echo "FAIL - Cron daemon is not enabled"
fi

systemctl is-active cron &> /dev/null
if [ $? -eq 0 ]; then
  echo "PASS - Cron daemon is running"
else
  echo "FAIL - Cron daemon is not running"
fi

# Ensure permissions on /etc/crontab are configured
if [[ $(stat -L -c "%a" /etc/crontab) == "600" ]]; then
  echo "PASS - Permissions on /etc/crontab are configured"
else
  echo "FAIL - Permissions on /etc/crontab are not configured"
fi

# Ensure permissions on /etc/cron.hourly are configured
if [[ $(stat -L -c "%a" /etc/cron.hourly) == "700" ]]; then
  echo "PASS - Permissions on /etc/cron.hourly are configured"
else
  echo "FAIL - Permissions on /etc/cron.hourly are not configured"
fi

# Ensure permissions on /etc/cron.daily are configured
if [[ $(stat -L -c "%a" /etc/cron.daily) == "700" ]]; then
  echo "PASS - Permissions on /etc/cron.daily are configured"
else
  echo "FAIL - Permissions on /etc/cron.daily are not configured"
fi

# Ensure permissions on /etc/cron.weekly are configured
if [[ $(stat -L -c "%a" /etc/cron.weekly) == "700" ]]; then
  echo "PASS - Permissions on /etc/cron.weekly are configured"
else
  echo "FAIL - Permissions on /etc/cron.weekly are not configured"
fi

# Ensure permissions on /etc/cron.monthly are configured
if [[ $(stat -L -c "%a" /etc/cron.monthly) == "700" ]]; then
  echo "PASS - Permissions on /etc/cron.monthly are configured"
else
  echo "FAIL - Permissions on /etc/cron.monthly are not configured"
fi

# Ensure permissions on /etc/cron.d are configured
if [[ $(stat -L -c "%a" /etc/cron.d) == "700" ]]; then
  echo "PASS - Permissions on /etc/cron.d are configured"
else
  echo "FAIL - Permissions on /etc/cron.d are not configured"
fi

# Ensure cron is restricted to authorized users
if [[ $(grep ^cron /etc/cron.allow) ]] && [[ ! $(grep ^cron /etc/cron.deny) ]]; then
  echo "PASS - Cron is restricted to authorized users"
else
  echo "FAIL - Cron is not restricted to authorized users"
fi

# Ensure at is restricted to authorized users
if [[ $(grep ^at /etc/at.allow) ]] && [[ ! $(grep ^at /etc/at.deny) ]]; then
  echo "PASS - at is restricted to authorized users"
else
  echo "FAIL - at is not restricted to authorized users"
fi


# Ensure sudo is installed
if ! command -v sudo >/dev/null; then
  echo "sudo is not installed"
else
  # Ensure sudo commands use pty
  if ! grep -q "^Defaults.*requiretty" /etc/sudoers /etc/sudoers.d/*; then
    echo "sudo commands are not set to use pty"
  fi

  # Ensure sudo log file exists
  if [ ! -f /var/log/sudo.log ]; then
    echo "sudo log file does not exist"
  fi
fi


# Ensure permissions on /etc/ssh/sshd_config are configured
perms_sshd=$(stat -L -c "%a %u %g" /etc/ssh/sshd_config)
if [ "$perms_sshd" != "600 0 0" ]; then
  echo "Permissions on /etc/ssh/sshd_config are not properly configured!"
fi

# Ensure permissions on SSH private host key files are configured
for keyfile in $(find /etc/ssh -type f -name 'ssh_host_*_key'); do
  perms_keyfile=$(stat -L -c "%a %u %g" "$keyfile")
  if [ "$perms_keyfile" != "600 0 0" ]; then
    echo "Permissions on $keyfile are not properly configured!"
  fi
done

# Ensure permissions on SSH public host key files are configured
for keyfile in $(find /etc/ssh -type f -name 'ssh_host_*_key.pub'); do
  perms_keyfile=$(stat -L -c "%a %u %g" "$keyfile")
  if [ "$perms_keyfile" != "644 0 0" ]; then
    echo "Permissions on $keyfile are not properly configured!"
  fi
done

# Ensure SSH access is limited
sshd_config=$(cat /etc/ssh/sshd_config)
if [[ "$sshd_config" != *"AllowUsers"* && "$sshd_config" != *"AllowGroups"* ]]; then
  echo "SSH access is not limited!"
fi

# Ensure SSH LogLevel is appropriate
if [[ "$sshd_config" != *"LogLevel VERBOSE"* ]]; then
  echo "SSH LogLevel is not set to VERBOSE!"
fi

# Ensure SSH X11 forwarding is disabled
if [[ "$sshd_config" != *"X11Forwarding no"* ]]; then
  echo "SSH X11 forwarding is not disabled!"
fi

# Ensure SSH MaxAuthTries is set to 4 or less
maxauthtries=$(grep -i "MaxAuthTries" /etc/ssh/sshd_config | awk '{print $2}')
if [ "$maxauthtries" -gt 4 ]; then
  echo "SSH MaxAuthTries is not set to 4 or less!"
fi


# Ensure SSH IgnoreRhosts is enabled
grep -q "^IgnoreRhosts yes" /etc/ssh/sshd_config || echo "IgnoreRhosts is not enabled in /etc/ssh/sshd_config"

# Ensure SSH HostbasedAuthentication is disabled
grep -q "^HostbasedAuthentication no" /etc/ssh/sshd_config || echo "HostbasedAuthentication is not disabled in /etc/ssh/sshd_config"

# Ensure SSH root login is disabled
grep -q "^PermitRootLogin no" /etc/ssh/sshd_config || echo "Root login is not disabled in /etc/ssh/sshd_config"

# Ensure SSH PermitEmptyPasswords is disabled
grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config || echo "PermitEmptyPasswords is not disabled in /etc/ssh/sshd_config"

# Ensure SSH PermitUserEnvironment is disabled
grep -q "^PermitUserEnvironment no" /etc/ssh/sshd_config || echo "PermitUserEnvironment is not disabled in /etc/ssh/sshd_config"

# Ensure only strong Ciphers are used
grep -E "^Ciphers (aes256-ctr|aes192-ctr|aes128-ctr)" /etc/ssh/sshd_config || echo "Weak ciphers are used in /etc/ssh/sshd_config"

# Ensure only strong MAC algorithms are used
grep -E "^MACs (hmac-sha2-512|hamc-sha2-256)" /etc/ssh/sshd_config || echo "Weak MAC algorithms are used in /etc/ssh/sshd_config"

# Ensure only strong Key Exchange algorithms are used
grep -E "^KexAlgorithms (curve25519-sha256|diffie-hellman-group-exchange-sha256)" /etc/ssh/sshd_config || echo "Weak Key Exchange algorithms are used in /etc/ssh/sshd_config"

# Ensure SSH Idle Timeout Interval is configured
grep -q "^ClientAliveInterval" /etc/ssh/sshd_config && grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config || echo "SSH Idle Timeout Interval is not configured in /etc/ssh/sshd_config"

# Ensure SSH LoginGraceTime is set to one minute or less
grep -q "^LoginGraceTime 1m" /etc/ssh/sshd_config || echo "SSH LoginGraceTime is not set to one minute or less in /etc/ssh/sshd_config"

# Ensure SSH warning banner is configured
grep -q "^Banner" /etc/ssh/sshd_config || echo "SSH warning banner is not configured in /etc/ssh/sshd_config"

# Ensure SSH PAM is enabled
grep -q "^UsePAM yes" /etc/ssh/sshd_config || echo "SSH PAM is not enabled in /etc/ssh/sshd_config"

# Ensure SSH AllowTcpForwarding is disabled
grep -q "^AllowTcpForwarding no" /etc/ssh/sshd_config || echo "SSH AllowTcpForwarding is not disabled in /etc/ssh/sshd_config"

# Ensure SSH MaxStartups is configured
grep -q "^MaxStartups" /etc/ssh/sshd_config || echo "SSH MaxStartups is not configured in /etc/ssh/sshd_config"

# Ensure SSH MaxSessions is limited
grep -q "^MaxSessions" /etc/ssh/sshd_config || echo "SSH MaxSessions is not configured in /etc/ssh/sshd_config"


# Ensure password creation requirements are configured
grep "password.*requisite.*pam_pwquality.so" /etc/pam.d/system-auth >/dev/null
if [[ $? -eq 0 ]]; then
    echo "Password creation requirements are configured"
else
    echo "WARNING: Password creation requirements are not configured"
fi

# Ensure lockout for failed password attempts is configured
grep "pam_faillock.so" /etc/pam.d/password-auth >/dev/null
if [[ $? -eq 0 ]]; then
    echo "Lockout for failed password attempts is configured"
else
    echo "WARNING: Lockout for failed password attempts is not configured"
fi

# Ensure password reuse is limited
grep "remember" /etc/pam.d/system-auth >/dev/null
if [[ $? -eq 0 ]]; then
    echo "Password reuse is limited"
else
    echo "WARNING: Password reuse is not limited"
fi

# Ensure password hashing algorithm is SHA-512
grep "sha512" /etc/login.defs >/dev/null
if [[ $? -eq 0 ]]; then
    echo "Password hashing algorithm is SHA-512"
else
    echo "WARNING: Password hashing algorithm is not SHA-512"
fi

#***************************************************************************************************************



# Ensure password creation requirements are configured
grep -q '^password\s+\requisite\s+pam_pwquality.so' /etc/pam.d/system-auth || echo "password creation requirements not configured"

# Ensure lockout for failed password attempts is configured
grep -q '^auth\s+required\s+pam_faillock.so' /etc/pam.d/password-auth || echo "lockout for failed password attempts not configured"

# Ensure password reuse is limited
grep -q '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth || echo "password reuse not limited"

# Ensure password hashing algorithm is SHA-512
grep -q '^password\s+sufficient\s+pam_unix.so.*sha512' /etc/pam.d/system-auth || echo "password hashing algorithm is not SHA-512"


#*******************************************************************************************************************


# Ensure minimum days between password changes is configured
grep -q "^PASS_MIN_DAYS\s*[0-9]\+" /etc/login.defs || echo "PASS_MIN_DAYS not configured"
# Ensure password expiration is 365 days or less
grep -q "^PASS_MAX_DAYS\s*90$" /etc/login.defs || echo "PASS_MAX_DAYS not configured"
# Ensure password expiration warning days is 7 or more
grep -q "^PASS_WARN_AGE\s*[0-9]\+" /etc/login.defs || echo "PASS_WARN_AGE not configured"
# Ensure inactive password lock is 30 days or less
grep -q "^INACTIVE\s*[0-9]\+" /etc/default/useradd || echo "INACTIVE not configured"
# Ensure all users last password change date is in the past
grep ":\*:$(date +%s-)" /etc/shadow && echo "Password change date is set in the future"
# Ensure system accounts are secured
awk -F: '$3 < 1000 {print $1}' /etc/passwd | xargs -n1 -I{} id -u {} | grep -v "^id: " | grep -qv "^0$" && echo "System accounts not secured"
# Ensure default group for the root account is GID 0
grep -q "^root:x:0:" /etc/passwd || echo "Default group for root account is not GID 0"


# Ensure users' home directories permissions are 750 or more restrictive
if [[ $(find /home -maxdepth 1 -type d ! -perm 0750) ]]; then
  echo "Some users' home directories have permissions less restrictive than 750."
fi

# Ensure users' dot files are not group or world writable
if [[ $(find /home -maxdepth 2 -type f \( -name ".*" ! -perm -u=w,g=w,o=w \)) ]]; then
  echo "Some users' dot files are group or world writable."
fi

# Ensure no users have .netrc files
if [[ $(find /home -maxdepth 2 -type f -name ".netrc") ]]; then
  echo "Some users have .netrc files."
fi

# Ensure no users have .forward files
if [[ $(find /home -maxdepth 2 -type f -name ".forward") ]]; then
  echo "Some users have .forward files."
fi

# Ensure no users have .rhosts files
if [[ $(find /home -maxdepth 2 -type f -name ".rhosts") ]]; then
  echo "Some users have .rhosts files."
fi

# Ensure root is the only UID 0 account
if [[ $(awk -F: '($3 == 0) {print}' /etc/passwd | grep -v '^root') ]]; then
  echo "There are accounts with UID 0 other than root."
fi

# Ensure root PATH Integrity
if [[ $(echo $PATH | grep "::") || $(echo $PATH | grep ":$") || $(echo $PATH | grep ":/:" ) || $(echo $PATH | grep -v "^/usr/local/sbin:" | grep -E "(^|:)/sbin/:" ) || $(echo $PATH | grep -v "^/usr/local/bin:" | grep -E "(^|:)/bin/:" ) || $(echo $PATH | grep -v "^/usr/sbin:" | grep -E "(^|:)/usr/bin/:" ) || $(echo $PATH | grep -v "^/usr/local/bin:" | grep -E "(^|:)/usr/local/sbin/:" ) ]]; then
  echo "Path variable does not meet root's path integrity requirements."
fi

# Ensure no duplicate UIDs exist
if [[ $(awk -F: '{print $3}' /etc/passwd | sort | uniq -d) ]]; then
  echo "Duplicate UIDs exist."
fi

# Ensure no duplicate GIDs exist
if [[ $(awk -F: '{print $3}' /etc/group | sort | uniq -d) ]]; then
  echo "Duplicate GIDs exist."
fi

# Ensure no duplicate user names exist
if [[ $(awk -F: '{print $1}' /etc/passwd | sort | uniq -d) ]]; then
  echo "Duplicate user names exist."
fi

# Ensure no duplicate group names exist
if [[ $(awk -F: '{print $1}' /etc/group | sort | uniq -d) ]]; then
  echo "Duplicate group names exist."
fi

# Ensure shadow group is empty
if [[ $(grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group) ]]; then
  echo "Shadow group is not empty."
fi
