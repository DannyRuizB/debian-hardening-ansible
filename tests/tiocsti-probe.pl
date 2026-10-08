#!/usr/bin/perl
# tiocsti role (step 56 in the Bash twin) behavioural probe: can the calling account push a byte into the
# input queue of its OWN terminal with TIOCSTI (0x5412)? That is the whole
# attack: a process left in an admin's terminal (after `su`, inside `sudo`)
# types commands the shell then runs as the admin. Run it inside a pty
# (`script -qc "perl tiocsti-probe.pl" FILE`); it prints one line and never
# fails - the caller decides what the line must say. Measured on the CI
# runner: legacy_tiocsti=1 -> INJECTED for nobody, 0 -> "Input/output error"
# for nobody, root (CAP_SYS_ADMIN) INJECTED either way.
open(my $t, "+<", "/dev/tty") or do { print "no /dev/tty: $!\n"; exit 0 };
my $c = "x"; $! = 0; my $r = ioctl($t, 0x5412, $c);
printf "uid %d: TIOCSTI %s\n", $<, ($r ? "INJECTED" : "refused: $!");
