import os
import re
import sys
from datetime import datetime

# Function to check if a line contains a vulnerable syscall
def is_vulnerable_syscall(line, vulnerable_syscalls):
    match = re.match(r'\d{2}:\d{2}:\d{2} (\w+)', line)
    if match:
        syscall = match.group(1)
        return syscall in vulnerable_syscalls
    return False

# Function to scan strace output files for vulnerable syscalls
def scan_strace_files(directory, vulnerable_syscalls):
    findings = []
    for filename in os.listdir(directory):
        if filename.startswith("strace_output_"):
            file_path = os.path.join(directory, filename)
            with open(file_path, 'r') as file:
                for line in file:
                    if is_vulnerable_syscall(line, vulnerable_syscalls):
                        alert_message = f"Vulnerable syscall found in {filename}: {line.strip()}"
                        print(alert_message)
                        findings.append(alert_message)
    return findings

# Check if the script is run with a directory argument
if len(sys.argv) != 2:
    print("Usage: python3 scanner.py <path to the strace output folder>")
    sys.exit(1)

strace_output_dir = sys.argv[1]

# List of vulnerable syscalls (could be imported from a file instead)
vulnerable_syscalls = {
    'access', 'arch_prctl', 'dup2', 'dup', 'epoll_create1', 'execve', 'exit_group',
    'getegid', 'geteuid', 'getgid', 'getuid', 'pread64', 'prlimit64', 'connect',
    'fsync', 'getsockname', 'getsockopt', 'pipe2', 'recvfrom', 'recvmsg', 'sendmmsg',
    'sendto', 'setsockopt', 'unlinkat', 'vfork', 'wait4', 'sysinfo', 'capget',
    'capset', 'chown', 'clone', 'close_range', 'dup3', 'epoll_ctl', 'epoll_pwait',
    'epoll_wait', 'fstat', 'getgroups', 'getpgid', 'getpgrp', 'getpriority',
    'getresgid', 'getresuid', 'getsid', 'msync', 'nanosleep', 'ppoll', 'pwrite',
    'readlinkat', 'rt_sigpending', 'sched_getaffinity', 'sched_yield', 'setgroups',
    'setpgid', 'setpriority', 'setresgid', 'setresuid', 'setsid', 'signaltstack',
    'tgkill', 'timerfd_create', 'timerfd_settime', 'socketpair', 'getrusage',
    'faccessat2', 'fadvise64', 'getxattr', 'lgetxattr', 'statx', 'getppid',
    'getpeername', 'rt_sigreturn', 'alarm'
}

# Scanning the strace files
findings = scan_strace_files(strace_output_dir, vulnerable_syscalls)

# Generating report
report_filename = f'report_{datetime.now().strftime("%d%b%Y-%I:%M:%S%p")}.txt'
with open(report_filename, 'w') as report_file:
    for finding in findings:
        report_file.write(finding + '\n')

print(f"Report generated: {report_filename}")
