#!/bin/bash

#!/bin/bash

animate_text() {
    text="$1"
    delay="$2"
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep "$delay"
    done
    echo
}

# ASCII art
ascii_art="               _____                       
 ___ _   _ ___| ____|_ __  _   _ _ __ ___  
/ __| | | / __|  _| | '_ \| | | | '_ \` _ \ 
\__ \ |_| \__ \ |___| | | | |_| | | | | | |
|___/\__, |___/_____|_| |_|\__,_|_| |_| |_|
     |___/                                 "

# Animated printing of ASCII art
animate_text "$ascii_art" 0.01


print_red() {
    echo -e "\e[31m$1\e[0m"
}

print_green() {
    echo -e "\e[32m$1\e[0m"
}

# Function to check and enumerate drives
check_drives() {
    echo "####################################################"
    print_red "#-------) CHECK AND ENUMERATE DRIVES (---------#"
    echo "####################################################"

    print_red "Mounted Drives:"
    df -hT

    echo ""
    echo "Unmounted Drives:"
    lsblk -o NAME,MOUNTPOINT | grep -v "/"

    echo ""
    print_red "Credentials in /etc/fstab:"
    grep -Ei "username|password" /etc/fstab

    echo ""
}
# Function to check for timers and scheduled/Cron jobs
check_timers_and_cron() {
    echo "#################################################"
    print_red "#-------) CHECK TIMERS AND CRON JOBS (---------#"
    echo "#################################################"
    
    print_red "Timers:"
    systemctl list-timers --all

    echo ""
    print_red "Cron Jobs:"
    crontab -l

    echo ""
}


# Function to check if the machine is running in a container
check_container() {
    echo "###########################################"
    print_red "#-------) CHECK CONTAINER (---------#"
    echo "###########################################"
    if [ -f /proc/1/cgroup ]; then
        if grep -q "/docker/" /proc/1/cgroup || grep -q "/lxc/" /proc/1/cgroup; then
            print_red "Machine is running in a container."
        else
            print_green "Machine is not running in a container."
        fi
    else
        echo "Cannot determine if the machine is running in a container."
    fi
    echo ""
}

# Function to check if the machine is a part of the LXD group
check_lxd_group() {
    echo "###########################################"
    print_red "#-------) CHECK LXD GROUP (---------#"
    echo "###########################################"
    if grep -q lxd /etc/group; then
        print_red "Machine is a part of the LXD group."
    else
        print_green "Machine is not a part of the LXD group."
    fi
    echo ""
}

# Function to check if the machine is an EC2 instance
check_ec2_instance() {
    echo "###########################################"
    print_red "#-------) CHECK EC2 INSTANCE (---------#"
    echo "###########################################"
    if [ -f /sys/hypervisor/uuid ] && [ "$(head -c 3 /sys/hypervisor/uuid)" == "ec2" ]; then
        print_red "Machine is an EC2 instance."
    else
        print_green "Machine is not an EC2 instance."
    fi
    echo ""
}

# Function to get OS information
get_os_info() {
    echo "###########################################"
    print_red "#-------) GET OS INFORMATION (---------#"
    echo "###########################################"
    cat /etc/os-release
    echo ""
}

# Function to check PATH and highlight writable folders in red
check_path() {
    echo "###########################################"
    print_red "#-------) CHECK PATH (---------#"
    echo "###########################################"
    writable_folders=$(echo $PATH | tr ':' '\n' | grep -E '^/tmp|^/var|^/usr/tmp|^/mnt|^/opt' | xargs)
    if [ -n "$writable_folders" ]; then
        print_red "Writable folders found in PATH: $writable_folders"
    else
        print_green "No writable folders found in PATH."
    fi
    echo ""
}

# Function to check environment details
check_env_details() {
    echo "#################################################"
    print_red "#-------) CHECK ENVIRONMENT DETAILS (---------#"
    echo "#################################################"
    env
    echo ""
}

# Function to search for kernel exploits using searchsploit
search_kernel_exploits() {
    echo "#################################################"
    print_red "#-------) SEARCH FOR KERNEL EXPLOITS (---------#"
    echo "#################################################"
    searchsploit -w dirtycow
    echo ""
}

# Function to check if the sudo version is vulnerable using searchsploit
check_sudo_vulnerability() {
    echo "#################################################"
    print_red "#-------) CHECK SUDO VULNERABILITY (---------#"
    echo "#################################################"
    searchsploit -w sudo
    echo ""
}

# Function to check dmesg signature verification failed
check_dmesg_signature() {
    echo "##################################################"
    print_red "#-------) CHECK DMESG SIGNATURE VERIFICATION (---------#"
    echo "##################################################"
    dmesg | grep "signature verification failed"
    echo ""
}

# Function for additional system enumeration
additional_system_enum() {
    echo "#################################################"
    print_red "#-------) ADDITIONAL SYSTEM ENUMERATION (---------#"
    echo "#################################################"
    echo "Current Date:"
    date
    echo ""
    echo "System Stats:"
    uptime
    echo ""
    echo "CPU Information:"
    lscpu
    echo ""
    echo "Printers Information:"
    lpstat -p
    echo ""
}

# Function to check if sudo command execution is possible and its capabilities
check_sudo_capabilities() {
    sudo -l
}

# Function to list exploitable SUID binaries listed in GTFOBins
check_exploitable_suid() {
    # Loop through each binary in the GTFOBins list
    for binary in "${gtfo_binaries[@]}"; do
        # Check if the binary exists and has the SUID bit set
        if [[ -x "$(command -v $binary)" && -u "$(command -v $binary)" ]]; then
            # Print the binary name in red color
            echo -e "\e[31m$binary (SUID)\e[0m"

            # Print the GTFOBins link for the binary
            echo "GTFOBins Link: https://gtfobins.github.io/gtfobins/$binary"
        fi
    done
}


# Function to check if sudo commands are limited by path
check_sudo_path_restrictions() {
    sudo --list
}

# Function to check if SUID binary is present without specifying a path
check_suid_binary_no_path() {
    find / -perm -4000 ! -path "/proc/*" ! -path "/sys/*" -type f -exec basename {} \; 2>/dev/null | sort -u
}

# Function to check if SUID binary is present with a specified path, allowing bypass
check_suid_binary_with_path() {
    find / -perm -4000 -path "$1" ! -path "/proc/*" ! -path "/sys/*" -type f -exec basename {} \; 2>/dev/null | sort -u
}

# Function to check for LD_PRELOAD vulnerability
check_ld_preload_vuln() {
    env | grep LD_PRELOAD
}

# Function to check for a lack of .so library in a writable folder for a SUID binary
check_ld_so_conf_d() {
    find / -writable -type d -exec sh -c 'ls -l "$1" | grep ".so"' _ {} \; 2>/dev/null
}

# Function to check if sudo tokens are available and if a new one can be created
check_sudo_tokens() {
    sudo -v && print_red "sudo tokens available"
    sudo -n true && echo "sudo token creation possible"
}

# Function to check if sudoers file can be read or modified
check_sudoers_file() {
    sudo cat /etc/sudoers
    echo "You can try modifying the sudoers file manually if you have the necessary permissions"
}

# Function to check if /etc/ld.so.conf.d/ can be modified
check_ld_so_conf_d_modification() {
    ls -l /etc/ld.so.conf.d/
    echo "You can try modifying the contents of /etc/ld.so.conf.d/ manually if you have the necessary permissions"
}

# List of GTFOBins binaries
gtfo_binaries=(
    	"7z"
	"aa-exec"
	"ab"
	"agetty"
	"alpine"
	"ansible-playbook"
	"ansible-test"
	"aoss"
	"apache2ctl"
	"apt-get"
	"apt"
	"ar"
	"aria2c"
	"arj"
	"arp"
	"as"
	"ascii-xfr"
	"ascii85"
	"ash"
	"aspell"
	"at"
	"atobm"
	"awk"
	"aws"
	"base32"
	"base58"
	"base64"
	"basenc"
	"basez"
	"bash"
	"batcat"
	"bc"
	"bconsole"
	"bpftrace"
	"bridge"
	"bundle"
	"bundler"
	"busctl"
	"busybox"
	"byebug"
	"bzip2"
	"c89"
	"c99"
	"cabal"
	"cancel"
	"capsh"
	"cat"
	"cdist"
	"certbot"
	"check_by_ssh"
	"check_cups"
	"check_log"
	"check_memory"
	"check_raid"
	"check_ssl_cert"
	"check_statusfile"
	"chmod"
	"choom"
	"chown"
	"chroot"
	"clamscan"
	"cmp"
	"cobc"
	"column"
	"comm"
	"composer"
	"cowsay"
	"cowthink"
	"cp"
	"cpan"
	"cpio"
	"cpulimit"
	"crash"
	"crontab"
	"csh"
	"csplit"
	"csvtool"
	"cupsfilter"
	"curl"
	"cut"
	"dash"
	"date"
	"dc"
	"dd"
	"debugfs"
	"dialog"
	"diff"
	"dig"
	"distcc"
	"dmesg"
	"dmidecode"
	"dmsetup"
	"dnf"
	"docker"
	"dos2unix"
	"dosbox"
	"dotnet"
	"dpkg"
	"dstat"
	"dvips"
	"easy_install"
	"eb"
	"ed"
	"efax"
	"elvish"
	"emacs"
	"enscript"
	"env"
	"eqn"
	"espeak"
	"ex"
	"exiftool"
	"expand"
	"expect"
	"facter"
	"file"
	"find"
	"finger"
	"fish"
	"flock"
	"fmt"
	"fold"
	"fping"
	"ftp"
	"gawk"
	"gcc"
	"gcloud"
	"gcore"
	"gdb"
	"gem"
	"genie"
	"genisoimage"
	"ghc"
	"ghci"
	"gimp"
	"ginsh"
	"git"
	"grc"
	"grep"
	"gtester"
	"gzip"
	"hd"
	"head"
	"hexdump"
	"highlight"
	"hping3"
	"iconv"
	"iftop"
	"install"
	"ionice"
	"ip"
	"irb"
	"ispell"
	"jjs"
	"joe"
	"join"
	"journalctl"
	"jq"
	"jrunscript"
	"jtag"
	"julia"
	"knife"
	"ksh"
	"ksshell"
	"ksu"
	"kubectl"
	"latex"
	"latexmk"
	"ld.so"
	"ldconfig"
	"less"
	"lftp"
	"ln"
	"loginctl"
	"logsave"
	"look"
	"lp"
	"ltrace"
	"lua"
	"lualatex"
	"luatex"
	"lwp-download"
	"lwp-request"
	"mail"
	"make"
	"man"
	"mawk"
	"minicom"
	"more"
	"mosquitto"
	"mount"
	"msfconsole"
	"msgattrib"
	"msgcat"
	"msgconv"
	"msgfilter"
	"msgmerge"
	"msguniq"
	"mtr"
	"multitime"
	"mv"
	"mysql"
	"nano"
	"nasm"
	"nawk"
	"nc"
	"ncdu"
	"ncftp"
	"neofetch"
	"nft"
	"nice"
	"nl"
	"nm"
	"nmap"
	"node"
	"nohup"
	"npm"
	"nroff"
	"nsenter"
	"ntpdate"
	"octave"
	"od"
	"openssl"
	"openvpn"
	"openvt"
	"opkg"
	"pandoc"
	"paste"
	"pax"
	"pdb"
	"pdflatex"
	"pdftex"
	"perf"
	"perl"
	"perlbug"
	"pexec"
	"pg"
	"php"
	"pic"
	"pico"
	"pidstat"
	"pip"
	"pkexec"
	"pkg"
	"posh"
	"pr"
	"pry"
	"psftp"
	"psql"
	"ptx"
	"puppet"
	"pwsh"
	"python"
	"rake"
	"rc"
	"readelf"
	"red"
	"redcarpet"
	"redis"
	"restic"
	"rev"
	"rlwrap"
	"rpm"
	"rpmdb"
	"rpmquery"
	"rpmverify"
	"rsync"
	"rtorrent"
	"ruby"
	"run-mailcap"
	"run-parts"
	"runscript"
	"rview"
	"rvim"
	"sash"
	"scanmem"
	"scp"
	"screen"
	"script"
	"scrot"
	"sed"
	"service"
	"setarch"
	"setfacl"
	"setlock"
	"sftp"
	"sg"
	"shuf"
	"slsh"
	"smbclient"
	"socat"
	"socket"
	"soelim"
	"softlimit"
	"sort"
	"split"
	"sqlite3"
	"sqlmap"
	"ss"
	"ssh-agent"
	"ssh-keygen"
	"ssh-keyscan"
	"ssh"
	"sshpass"
	"start-stop-daemon"
	"stdbuf"
	"strace"
	"strings"
	"su"
	"sudo"
	"sysctl"
	"systemctl"
	"systemd-resolve"
	"tac"
	"tail"
	"tar"
	"task"
	"taskset"
	"tasksh"
	"tbl"
	"tclsh"
	"tcpdump"
	"tdbtool"
	"tee"
	"telnet"
	"terraform"
	"tex"
	"tftp"
	"tic"
	"time"
	"timedatectl"
	"timeout"
	"tmate"
	"tmux"
	"top"
	"torify"
	"torsocks"
	"troff"
	"tshark"
	"ul"
	"unexpand"
	"uniq"
	"unshare"
	"unsquashfs"
	"unzip"
	"update-alternatives"
	"uudecode"
	"uuencode"
	"vagrant"
	"valgrind"
	"varnishncsa"
	"vi"
	"view"
	"vigr"
	"vim"
	"vimdiff"
	"vipw"
	"virsh"
	"volatility"
	"w3m"
	"wall"
	"watch"
	"wc"
	"wget"
	"whiptail"
	"whois"
	"wireshark"
	"wish"
	"xargs"
	"xdg-user-dir"
	"xdotool"
	"xelatex"
	"xetex"
	"xmodmap"
	"xmore"
	"xpad"
	"xxd"
	"xz"
	"yarn"
	"yash"
	"yelp"
	"yum"
	"zathura"
	"zip"
	"zsh"
	"zsoelim"
	"zypper"

    
)

# Function to gather information about users and groups
gather_users_groups_info() {
    echo "############################################################"
    print_red "#-------) GATHER USERS AND GROUPS INFORMATION (---------#"
    echo "############################################################"
    print_red "Users:"
    cat /etc/passwd | awk -F: '{print $1}'
    echo ""
    print_red "Groups:"
    cat /etc/group | awk -F: '{print $1}'
    echo ""
}

# Function to gather host information
gather_host_info() {
    echo "##############################################"
    print_red "#-------) GATHER HOST INFORMATION (---------#"
    echo "##############################################"
    echo "Host Information:"
    print_red "IP Address:"
    ip -4 addr show | grep inet | awk '{print $2}' | cut -d'/' -f1
    hostnamectl
    echo ""
}

# Function to gather network information
gather_network_info() {
    echo "##################################################"
    print_red "#-------) GATHER NETWORK INFORMATION (---------#"
    echo "##################################################"
    echo "Network Information:"
    netstat -tuln
    echo ""
}

# Function to gather domain information
gather_domain_info() {
    echo "#################################################"
    print_red "#-------) GATHER DOMAIN INFORMATION (---------#"
    echo "#################################################"
    echo "Domain Information:"
    domain=$(hostname -d)
    if [ -z "$domain" ]; then
        print_green "Domain not configured"
    else
        print_red "Domain: $domain"
    fi
    echo ""
}

# Function to gather password lockout policies
gather_password_lockout_info() {
    echo "######################################################"
    print_red "#-------) GATHER PASSWORD LOCKOUT POLICIES (---------#"
    echo "######################################################"
    echo "Password Lockout Policies:"
    grep -E "^auth\s+required\s+pam_tally2\.so" /etc/pam.d/common-auth
    grep -E "^auth\s+required\s+pam_tally2\.so" /etc/pam.d/sshd
    echo ""
}

# Function to gather common services versions
gather_service_versions() {
    echo "######################################################"
    print_red "#-------) GATHER COMMON SERVICES VERSIONS (---------#"
    echo "######################################################"
    echo "Common Services Versions:"
    apache2 -v | grep "Apache/"
    nginx -v
    mysql --version
    php --version
    echo ""
}

# Function to check for capabilities
check_capabilities() {
    echo "##############################################"
    print_red "#-------) CHECK CAPABILITIES (---------#"
    echo "##############################################"
    
    # Check for existence of nologin shell
    if [ -e /sbin/nologin ]; then
        print_red "nologin shell is available."
    else
        print_green "nologin shell is not available."
    fi

    # Check sudo privileges
    if sudo -l >/dev/null 2>&1; then
        print_red "User has sudo privileges."
    else
        print_green "User does not have sudo privileges."
    fi
    
    echo ""
}

# Function to check for sensitive files
check_sensitive_files() {
    echo "###############################################"
    print_red "#-------) CHECK SENSITIVE FILES (---------#"
    echo "###############################################"
    
    # Check for sensitive log files
    echo "Sensitive Log Files:"
    find /var/log -type f \( -name "*.log" -o -name "*.log.*" \) -exec ls -l {} +

    # Check for sensitive backup files
    echo "Sensitive Backup Files:"
    find / -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*.swp" \) -exec ls -l {} +

    # Check for SSH authorized keys
    echo "SSH Authorized Keys in ~/.ssh:"
    find /home -name "authorized_keys" -exec ls -l {} +
    echo "SSH Keys in ~/.ssh:"
    find /home -path "*/.ssh/*" -type f \( -name "id_rsa*" -o -name "id_dsa*" -o -name "id_ecdsa*" -o -name "id_ed25519*" \) -exec ls -l {} +
    echo ""
}
# Function to check services
check_services() {
    echo "###########################################"
    print_red "#-------) CHECK SERVICES (---------#"
    echo "###########################################"

    print_red "Writable .service Files:"
    find /etc/systemd/system/ -type f -name "*.service" -writable

    echo ""
    print_red "Writable Binaries Executed by Services:"
    systemctl list-unit-files --state=enabled | grep -E 'service.*enabled' | while read -r unit_file _; do
        service_path=$(systemctl show -p FragmentPath "$unit_file" | cut -d= -f2)
        echo "Service: $unit_file"
        if [ -n "$service_path" ] && [ -x "$service_path" ] && [ -w "$service_path" ]; then
            echo "Writable Binary: $service_path"
        fi
    done

    echo ""
    print_red "Writable Folders in systemd PATH:"
    path_dirs=$(systemctl show-environment | grep -oP 'PATH=\K[^:]+' | tr ':' '\n')
    for dir in $path_dirs; do
        if [ -w "$dir" ]; then
            echo "Writable Folder in PATH: $dir"
        fi
    done

    echo ""
}

# Function to check sockets
check_sockets() {
    echo "###########################################"
    print_red "#-------) CHECK SOCKETS (---------#"
    echo "###########################################"

    print_red "Writable .socket Files:"
    find /etc/systemd/system/ -type f -name "*.socket" -writable

    echo ""
    print_red "HTTP Sockets with Interesting Information:"
    netstat -tuln | grep -iE ':80|:443'

    echo ""
}
# Function to check communication with D-Bus
check_dbus_communication() {
    echo "################################################"
    print_red "#-------) CHECK D-BUS COMMUNICATION (---------#"
    echo "################################################"

    echo "Checking for D-Bus communication:"
    dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Peer.Ping > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        print_red "Communication with D-Bus successful."
    else
        print_green "Unable to communicate with D-Bus."
    fi

    echo ""
}

# Function to list open shell sessions in screen
list_screen_sessions() {
    echo "###########################################"
    print_red "#-------) Screen Sessions (---------#"
    echo "###########################################"
    screen -ls
    echo ""
    tmux ls
}

# Function to print animated dotted line in red color
print_animated_line() {
    for i in {1..17}; do
        echo -ne "\e[31m.\e[0m"
        sleep 0.1
    done
    echo ""
}

# Main function to call other functions
main() {                         

	# Call print_animated_line function before each of the specified functions
	print_animated_line
	get_os_info
	echo ""

	print_animated_line
	check_path
	echo ""

	print_animated_line
	check_env_details
	echo ""

	print_animated_line
	search_kernel_exploits
	echo ""

	print_animated_line
	check_sudo_vulnerability
	echo ""

	print_animated_line
	check_dmesg_signature
	echo ""

	print_animated_line
	additional_system_enum
	echo ""

	print_animated_line
	check_drives
	echo ""

	print_animated_line
	gather_users_groups_info
	echo ""

	print_animated_line
	gather_host_info
	echo ""

	print_animated_line
	gather_network_info
	echo ""

	print_animated_line
	gather_domain_info
	echo ""

	print_animated_line
	gather_password_lockout_info
	echo ""

	print_animated_line
	gather_service_versions
	echo ""

	print_animated_line
	check_container
	echo ""

	print_animated_line
	check_lxd_group
	echo ""

	print_animated_line
	check_ec2_instance
	echo ""

	print_animated_line
	check_capabilities
	echo ""

	print_animated_line
	check_sensitive_files
	echo ""

	check_timers_and_cron
	echo ""

	print_animated_line
	check_services
	echo ""

	print_animated_line
	check_dbus_communication
	echo ""

	print_animated_line
	list_screen_sessions
	echo ""

	print_animated_line
	check_sudo_capabilities
	echo ""

    echo "##############################################"
    print_red "#-------) Exploitable SUID Binaries (---------#"
    echo "##############################################"
	print_animated_line
	check_exploitable_suid
	echo ""

	print_animated_line
	check_sudo_tokens
	echo ""

}
main

print_red "Please review the above information for potential security vulnerabilities."
print_green "Coded by Syed Suleman Rehman"
