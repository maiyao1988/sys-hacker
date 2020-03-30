#define MAX_SYSCALL_NUM 381
#include "syscalls.h"
struct syscall_entry syscalls[] = {
  [0] = {
    "restart_syscall",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [1] = {
    "exit",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [2] = {
    "fork",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [3] = {
    "read",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [4] = {
    "write",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [5] = {
    "open",
    3,
    {ARG_STR, ARG_INT, ARG_INT, -1, -1, -1}},
  [6] = {
    "close",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [8] = {
    "creat",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [9] = {
    "link",
    2,
    {ARG_STR, ARG_STR, -1, -1, -1, -1}},
  [10] = {
    "unlink",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [11] = {
    "execve",
    3,
    {ARG_STR, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [12] = {
    "chdir",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [13] = {
    "time",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [14] = {
    "mknod",
    3,
    {ARG_STR, ARG_INT, ARG_INT, -1, -1, -1}},
  [15] = {
    "chmod",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [16] = {
    "lchown",
    3,
    {ARG_STR, ARG_INT, ARG_INT, -1, -1, -1}},
  [19] = {
    "lseek",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [20] = {
    "getpid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [21] = {
    "mount",
    5,
    {ARG_STR, ARG_STR, ARG_STR, ARG_INT, ARG_PTR, -1}},
  [22] = {
    "umount",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [23] = {
    "setuid",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [24] = {
    "getuid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [25] = {
    "stime",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [26] = {
    "ptrace",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1, -1}},
  [27] = {
    "alarm",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [29] = {
    "pause",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [30] = {
    "utime",
    2,
    {ARG_STR, ARG_PTR, -1, -1, -1, -1}},
  [33] = {
    "access",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [34] = {
    "nice",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [36] = {
    "sync",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [37] = {
    "kill",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [38] = {
    "rename",
    2,
    {ARG_STR, ARG_STR, -1, -1, -1, -1}},
  [39] = {
    "mkdir",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [40] = {
    "rmdir",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [41] = {
    "dup",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [42] = {
    "pipe",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [43] = {
    "times",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [45] = {
    "brk",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [46] = {
    "setgid",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [47] = {
    "getgid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [49] = {
    "geteuid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [50] = {
    "getegid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [51] = {
    "acct",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [52] = {
    "umount2",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [54] = {
    "ioctl",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [55] = {
    "fcntl",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [57] = {
    "setpgid",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [60] = {
    "umask",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [61] = {
    "chroot",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [62] = {
    "ustat",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [63] = {
    "dup2",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [64] = {
    "getppid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [65] = {
    "getpgrp",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [66] = {
    "setsid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [67] = {
    "sigaction",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [70] = {
    "setreuid",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [71] = {
    "setregid",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [72] = {
    "sigsuspend",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [73] = {
    "sigpending",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [74] = {
    "sethostname",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [75] = {
    "setrlimit",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [76] = {
    "getrlimit",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [77] = {
    "getrusage",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [78] = {
    "gettimeofday",
    2,
    {ARG_PTR, ARG_PTR, -1, -1, -1, -1}},
  [79] = {
    "settimeofday",
    2,
    {ARG_PTR, ARG_PTR, -1, -1, -1, -1}},
  [80] = {
    "getgroups",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [81] = {
    "setgroups",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [82] = {
    "select",
    5,
    {ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, -1}},
  [83] = {
    "symlink",
    2,
    {ARG_STR, ARG_STR, -1, -1, -1, -1}},
  [85] = {
    "readlink",
    3,
    {ARG_STR, ARG_STR, ARG_INT, -1, -1, -1}},
  [86] = {
    "uselib",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [87] = {
    "swapon",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [88] = {
    "reboot",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, -1, -1}},
  [89] = {
    "readdir",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [90] = {
    "mmap",
    6,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT}},
  [91] = {
    "munmap",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [92] = {
    "truncate",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [93] = {
    "ftruncate",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [94] = {
    "fchmod",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [95] = {
    "fchown",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [96] = {
    "getpriority",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [97] = {
    "setpriority",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [99] = {
    "statfs",
    2,
    {ARG_STR, ARG_PTR, -1, -1, -1, -1}},
  [100] = {
    "fstatfs",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [102] = {
    "socketcall",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [103] = {
    "syslog",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [104] = {
    "setitimer",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [105] = {
    "getitimer",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [106] = {
    "stat",
    2,
    {ARG_STR, ARG_PTR, -1, -1, -1, -1}},
  [107] = {
    "lstat",
    2,
    {ARG_STR, ARG_PTR, -1, -1, -1, -1}},
  [108] = {
    "fstat",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [111] = {
    "vhangup",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [113] = {
    "syscall",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [114] = {
    "wait4",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, -1, -1}},
  [115] = {
    "swapoff",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [116] = {
    "sysinfo",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [117] = {
    "ipc",
    6,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_INT}},
  [118] = {
    "fsync",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [119] = {
    "sigreturn",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [120] = {
    "clone",
    5,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, -1}},
  [121] = {
    "setdomainname",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [122] = {
    "uname",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [124] = {
    "adjtimex",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [125] = {
    "mprotect",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [126] = {
    "sigprocmask",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [128] = {
    "init_module",
    3,
    {ARG_PTR, ARG_INT, ARG_STR, -1, -1, -1}},
  [129] = {
    "delete_module",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [131] = {
    "quotactl",
    4,
    {ARG_INT, ARG_STR, ARG_INT, ARG_PTR, -1, -1}},
  [132] = {
    "getpgid",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [133] = {
    "fchdir",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [134] = {
    "bdflush",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [135] = {
    "sysfs",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [136] = {
    "personality",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [138] = {
    "setfsuid",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [139] = {
    "setfsgid",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [140] = {
    "_llseek",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [141] = {
    "getdents",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [142] = {
    "_newselect",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [143] = {
    "flock",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [144] = {
    "msync",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [145] = {
    "readv",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [146] = {
    "writev",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [147] = {
    "getsid",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [148] = {
    "fdatasync",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [149] = {
    "_sysctl",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [150] = {
    "mlock",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [151] = {
    "munlock",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [152] = {
    "mlockall",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [153] = {
    "munlockall",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [154] = {
    "sched_setparam",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [155] = {
    "sched_getparam",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [156] = {
    "sched_setscheduler",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [157] = {
    "sched_getscheduler",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [158] = {
    "sched_yield",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [159] = {
    "sched_get_priority_max",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [160] = {
    "sched_get_priority_min",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [161] = {
    "sched_rr_get_interval",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [162] = {
    "nanosleep",
    2,
    {ARG_PTR, ARG_PTR, -1, -1, -1, -1}},
  [163] = {
    "mremap",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1}},
  [164] = {
    "setresuid",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [165] = {
    "getresuid",
    3,
    {ARG_PTR, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [168] = {
    "poll",
    3,
    {ARG_PTR, ARG_INT, ARG_INT, -1, -1, -1}},
  [169] = {
    "nfsservctl",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [170] = {
    "setresgid",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [171] = {
    "getresgid",
    3,
    {ARG_PTR, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [172] = {
    "prctl",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1}},
  [173] = {
    "rt_sigreturn",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [174] = {
    "rt_sigaction",
    4,
    {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, -1, -1}},
  [175] = {
    "rt_sigprocmask",
    4,
    {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, -1, -1}},
  [176] = {
    "rt_sigpending",
    2,
    {ARG_PTR, ARG_INT, -1, -1, -1, -1}},
  [177] = {
    "rt_sigtimedwait",
    4,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_INT, -1, -1}},
  [178] = {
    "rt_sigqueueinfo",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [179] = {
    "rt_sigsuspend",
    2,
    {ARG_PTR, ARG_INT, -1, -1, -1, -1}},
  [180] = {
    "pread64",
    4,
    {ARG_INT, ARG_STR, ARG_INT, ARG_INT, -1, -1}},
  [181] = {
    "pwrite64",
    4,
    {ARG_INT, ARG_STR, ARG_INT, ARG_INT, -1, -1}},
  [182] = {
    "chown",
    3,
    {ARG_STR, ARG_INT, ARG_INT, -1, -1, -1}},
  [183] = {
    "getcwd",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [184] = {
    "capget",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [185] = {
    "capset",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [186] = {
    "sigaltstack",
    2,
    {ARG_PTR, ARG_PTR, -1, -1, -1, -1}},
  [187] = {
    "sendfile",
    4,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, -1, -1}},
  [190] = {
    "vfork",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [191] = {
    "ugetrlimit",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [192] = {
    "mmap2",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [193] = {
    "truncate64",
    2,
    {ARG_STR, ARG_INT, -1, -1, -1, -1}},
  [194] = {
    "ftruncate64",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [195] = {
    "stat64",
    2,
    {ARG_STR, ARG_PTR, -1, -1, -1, -1}},
  [196] = {
    "lstat64",
    2,
    {ARG_STR, ARG_PTR, -1, -1, -1, -1}},
  [197] = {
    "fstat64",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [198] = {
    "lchown32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [199] = {
    "getuid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [200] = {
    "getgid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [201] = {
    "geteuid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [202] = {
    "getegid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [203] = {
    "setreuid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [204] = {
    "setregid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [205] = {
    "getgroups32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [206] = {
    "setgroups32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [207] = {
    "fchown32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [208] = {
    "setresuid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [209] = {
    "getresuid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [210] = {
    "setresgid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [211] = {
    "getresgid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [212] = {
    "chown32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [213] = {
    "setuid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [214] = {
    "setgid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [215] = {
    "setfsuid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [216] = {
    "setfsgid32",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [217] = {
    "getdents64",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [218] = {
    "pivot_root",
    2,
    {ARG_STR, ARG_STR, -1, -1, -1, -1}},
  [219] = {
    "mincore",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [220] = {
    "madvise",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [221] = {
    "fcntl64",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [224] = {
    "gettid",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [225] = {
    "readahead",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [226] = {
    "setxattr",
    5,
    {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, -1}},
  [227] = {
    "lsetxattr",
    5,
    {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, -1}},
  [228] = {
    "fsetxattr",
    5,
    {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, -1}},
  [229] = {
    "getxattr",
    4,
    {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, -1, -1}},
  [230] = {
    "lgetxattr",
    4,
    {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, -1, -1}},
  [231] = {
    "fgetxattr",
    4,
    {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, -1, -1}},
  [232] = {
    "listxattr",
    3,
    {ARG_STR, ARG_STR, ARG_INT, -1, -1, -1}},
  [233] = {
    "llistxattr",
    3,
    {ARG_STR, ARG_STR, ARG_INT, -1, -1, -1}},
  [234] = {
    "flistxattr",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [235] = {
    "removexattr",
    2,
    {ARG_STR, ARG_STR, -1, -1, -1, -1}},
  [236] = {
    "lremovexattr",
    2,
    {ARG_STR, ARG_STR, -1, -1, -1, -1}},
  [237] = {
    "fremovexattr",
    2,
    {ARG_INT, ARG_STR, -1, -1, -1, -1}},
  [238] = {
    "tkill",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [239] = {
    "sendfile64",
    4,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, -1, -1}},
  [240] = {
    "futex",
    6,
    {ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT}},
  [241] = {
    "sched_setaffinity",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [242] = {
    "sched_getaffinity",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [243] = {
    "io_setup",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [244] = {
    "io_destroy",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [245] = {
    "io_getevents",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, -1}},
  [246] = {
    "io_submit",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [247] = {
    "io_cancel",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [248] = {
    "exit_group",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [249] = {
    "lookup_dcookie",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [250] = {
    "epoll_create",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [251] = {
    "epoll_ctl",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, -1, -1}},
  [252] = {
    "epoll_wait",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, -1, -1}},
  [253] = {
    "remap_file_pages",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1}},
  [256] = {
    "set_tid_address",
    1,
    {ARG_PTR, -1, -1, -1, -1, -1}},
  [257] = {
    "timer_create",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [258] = {
    "timer_settime",
    4,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, -1, -1}},
  [259] = {
    "timer_gettime",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [260] = {
    "timer_getoverrun",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [261] = {
    "timer_delete",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [262] = {
    "clock_settime",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [263] = {
    "clock_gettime",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [264] = {
    "clock_getres",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [265] = {
    "clock_nanosleep",
    4,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, -1, -1}},
  [266] = {
    "statfs64",
    3,
    {ARG_STR, ARG_INT, ARG_PTR, -1, -1, -1}},
  [267] = {
    "fstatfs64",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [268] = {
    "tgkill",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [269] = {
    "utimes",
    2,
    {ARG_STR, ARG_PTR, -1, -1, -1, -1}},
  [270] = {
    "arm_fadvise64_64",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [271] = {
    "pciconfig_iobase",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [272] = {
    "pciconfig_read",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [273] = {
    "pciconfig_write",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [274] = {
    "mq_open",
    4,
    {ARG_STR, ARG_INT, ARG_INT, ARG_PTR, -1, -1}},
  [275] = {
    "mq_unlink",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [276] = {
    "mq_timedsend",
    5,
    {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_PTR, -1}},
  [277] = {
    "mq_timedreceive",
    5,
    {ARG_INT, ARG_STR, ARG_INT, ARG_PTR, ARG_PTR, -1}},
  [278] = {
    "mq_notify",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [279] = {
    "mq_getsetattr",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [280] = {
    "waitid",
    5,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, -1}},
  [281] = {
    "socket",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [282] = {
    "bind",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [283] = {
    "connect",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [284] = {
    "listen",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [285] = {
    "accept",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [286] = {
    "getsockname",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [287] = {
    "getpeername",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [288] = {
    "socketpair",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, -1, -1}},
  [289] = {
    "send",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, -1, -1}},
  [290] = {
    "sendto",
    6,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_INT}},
  [291] = {
    "recv",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [292] = {
    "recvfrom",
    6,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_PTR}},
  [293] = {
    "shutdown",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [294] = {
    "setsockopt",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_STR, ARG_INT, -1}},
  [295] = {
    "getsockopt",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_STR, ARG_PTR, -1}},
  [296] = {
    "sendmsg",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [297] = {
    "recvmsg",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [298] = {
    "semop",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [299] = {
    "semget",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [300] = {
    "semctl",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1, -1}},
  [301] = {
    "msgsnd",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, -1, -1}},
  [302] = {
    "msgrcv",
    5,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, -1}},
  [303] = {
    "msgget",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [304] = {
    "msgctl",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [305] = {
    "shmat",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [306] = {
    "shmdt",
    1,
    {ARG_STR, -1, -1, -1, -1, -1}},
  [307] = {
    "shmget",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [308] = {
    "shmctl",
    3,
    {ARG_INT, ARG_INT, ARG_PTR, -1, -1, -1}},
  [309] = {
    "add_key",
    5,
    {ARG_STR, ARG_STR, ARG_PTR, ARG_INT, ARG_INT, -1}},
  [310] = {
    "request_key",
    4,
    {ARG_STR, ARG_STR, ARG_STR, ARG_INT, -1, -1}},
  [311] = {
    "keyctl",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1}},
  [312] = {
    "semtimedop",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, -1, -1}},
  [313] = {
    "vserver",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [314] = {
    "ioprio_set",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [315] = {
    "ioprio_get",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [316] = {
    "inotify_init",
    0,
    {-1, -1, -1, -1, -1, -1}},
  [317] = {
    "inotify_add_watch",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [318] = {
    "inotify_rm_watch",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [319] = {
    "mbind",
    6,
    {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
  [320] = {
    "get_mempolicy",
    5,
    {ARG_PTR, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, -1}},
  [321] = {
    "set_mempolicy",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [322] = {
    "openat",
    4,
    {ARG_INT, ARG_STR, ARG_INT, ARG_INT, -1, -1}},
  [323] = {
    "mkdirat",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [324] = {
    "mknodat",
    4,
    {ARG_INT, ARG_STR, ARG_INT, ARG_INT, -1, -1}},
  [325] = {
    "fchownat",
    5,
    {ARG_INT, ARG_STR, ARG_INT, ARG_INT, ARG_INT, -1}},
  [326] = {
    "futimesat",
    3,
    {ARG_INT, ARG_STR, ARG_PTR, -1, -1, -1}},
  [327] = {
    "fstatat64",
    4,
    {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, -1, -1}},
  [328] = {
    "unlinkat",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [329] = {
    "renameat",
    4,
    {ARG_INT, ARG_STR, ARG_INT, ARG_STR, -1, -1}},
  [330] = {
    "linkat",
    5,
    {ARG_INT, ARG_STR, ARG_INT, ARG_STR, ARG_INT, -1}},
  [331] = {
    "symlinkat",
    3,
    {ARG_STR, ARG_INT, ARG_STR, -1, -1, -1}},
  [332] = {
    "readlinkat",
    4,
    {ARG_INT, ARG_STR, ARG_STR, ARG_INT, -1, -1}},
  [333] = {
    "fchmodat",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [334] = {
    "faccessat",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [335] = {
    "pselect6",
    6,
    {ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [336] = {
    "ppoll",
    5,
    {ARG_PTR, ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, -1}},
  [337] = {
    "unshare",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [338] = {
    "set_robust_list",
    2,
    {ARG_PTR, ARG_INT, -1, -1, -1, -1}},
  [339] = {
    "get_robust_list",
    3,
    {ARG_INT, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [340] = {
    "splice",
    6,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
  [341] = {
    "arm_sync_file_range",
    6,
    {ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR, ARG_PTR}},
  [342] = {
    "tee",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1, -1}},
  [343] = {
    "vmsplice",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, -1, -1}},
  [344] = {
    "move_pages",
    6,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, ARG_PTR, ARG_INT}},
  [345] = {
    "getcpu",
    3,
    {ARG_PTR, ARG_PTR, ARG_PTR, -1, -1, -1}},
  [346] = {
    "epoll_pwait",
    6,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, ARG_INT}},
  [347] = {
    "kexec_load",
    4,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_INT, -1, -1}},
  [348] = {
    "utimensat",
    4,
    {ARG_INT, ARG_STR, ARG_PTR, ARG_INT, -1, -1}},
  [349] = {
    "signalfd",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [350] = {
    "timerfd_create",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [351] = {
    "eventfd",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [352] = {
    "fallocate",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1, -1}},
  [353] = {
    "timerfd_settime",
    4,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, -1, -1}},
  [354] = {
    "timerfd_gettime",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [355] = {
    "signalfd4",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, -1, -1}},
  [356] = {
    "eventfd2",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [357] = {
    "epoll_create1",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [358] = {
    "dup3",
    3,
    {ARG_INT, ARG_INT, ARG_INT, -1, -1, -1}},
  [359] = {
    "pipe2",
    2,
    {ARG_PTR, ARG_INT, -1, -1, -1, -1}},
  [360] = {
    "inotify_init1",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [361] = {
    "preadv",
    5,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, -1}},
  [362] = {
    "pwritev",
    5,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_INT, -1}},
  [363] = {
    "rt_tgsigqueueinfo",
    4,
    {ARG_INT, ARG_INT, ARG_INT, ARG_PTR, -1, -1}},
  [364] = {
    "perf_event_open",
    5,
    {ARG_PTR, ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1}},
  [365] = {
    "recvmmsg",
    5,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, ARG_PTR, -1}},
  [366] = {
    "accept4",
    4,
    {ARG_INT, ARG_PTR, ARG_PTR, ARG_INT, -1, -1}},
  [367] = {
    "fanotify_init",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [368] = {
    "fanotify_mark",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_STR, -1}},
  [369] = {
    "prlimit64",
    4,
    {ARG_INT, ARG_INT, ARG_PTR, ARG_PTR, -1, -1}},
  [370] = {
    "name_to_handle_at",
    5,
    {ARG_INT, ARG_STR, ARG_PTR, ARG_PTR, ARG_INT, -1}},
  [371] = {
    "open_by_handle_at",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [372] = {
    "clock_adjtime",
    2,
    {ARG_INT, ARG_PTR, -1, -1, -1, -1}},
  [373] = {
    "syncfs",
    1,
    {ARG_INT, -1, -1, -1, -1, -1}},
  [374] = {
    "sendmmsg",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, -1, -1}},
  [375] = {
    "setns",
    2,
    {ARG_INT, ARG_INT, -1, -1, -1, -1}},
  [376] = {
    "process_vm_readv",
    6,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
  [377] = {
    "process_vm_writev",
    6,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_PTR, ARG_INT, ARG_INT}},
  [378] = {
    "kcmp",
    5,
    {ARG_INT, ARG_INT, ARG_INT, ARG_INT, ARG_INT, -1}},
  [379] = {
    "finit_module",
    3,
    {ARG_INT, ARG_STR, ARG_INT, -1, -1, -1}},
  [380] = {
    "sched_setattr",
    3,
    {ARG_INT, ARG_PTR, ARG_INT, -1, -1, -1}},
  [381] = {
    "sched_getattr",
    4,
    {ARG_INT, ARG_PTR, ARG_INT, ARG_INT, -1, -1}},
};
