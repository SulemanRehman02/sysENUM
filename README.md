# sysEnum
System Enumeration and Security Assessment Script

The "sysEnum" script is a collection of functions designed for system enumeration and security assessment purposes. It performs various checks and searches on a Linux system to identify potential security risks, misconfigurations, or interesting files. Some of its features include:

- Checking and enumerating mounted and unmounted drives
- Listing credentials stored in the /etc/fstab file
- Examining timers and scheduled/Cron jobs
- Determining if the system is running in a container or is part of the LXD group
- Identifying if the system is an EC2 instance
- Retrieving OS information
- Highlighting writable folders in the PATH variable
- Checking environment details
- Searching for kernel exploits and checking for sudo vulnerabilities
- Checking for dmesg signature verification failures
- Performing additional system enumeration tasks such as displaying system stats, CPU information, and printer information.

These functions are intended to provide system administrators and security professionals with a comprehensive set of tools for system assessment and security auditing.

# Usage
1. **git clone https://github.com/SulemanRehman02/sysENUM.git**
2. **cd sysENUM**
3. **chmod 777 sysEnum.sh**
4. **./sysEnum.sh** 
