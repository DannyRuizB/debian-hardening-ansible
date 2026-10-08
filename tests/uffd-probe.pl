#!/usr/bin/perl
# kernel_surface behavioural probe, run ON the node as the calling account (piped
# over ssh: `on_node perl < uffd-probe.pl`). Prints one line, never fails:
# the caller decides what the line must say.
# userfaultfd(2) from the calling account. Flags 0 asks for a descriptor that
# can also catch faults the KERNEL takes on user memory (the exploit use);
# UFFD_USER_MODE_ONLY (1) asks for user-mode faults only, which
# unprivileged_userfaultfd=0 still allows - the anchor that the syscall is
# reachable at all, so an EPERM on the first is the knob and not seccomp.
my %nr = (x86_64 => 323, aarch64 => 282);
chomp(my $arch = `uname -m`);
my $n = $nr{$arch};
defined $n or do { print "arch=$arch unsupported\n"; exit 0 };
$! = 0; my $full = syscall($n, 0); my $fe = $! + 0;
$! = 0; my $um = syscall($n, 1); my $ue = $! + 0;
printf "full=%s usermode=%s\n", ($full >= 0 ? 'open' : "errno$fe"), ($um >= 0 ? 'open' : "errno$ue");
