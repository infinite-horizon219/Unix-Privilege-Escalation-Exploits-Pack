#!/bin/sh

###################################################################################
# gw-notexit.sh: Linux kernel <2.6.29 exit_notify() local root exploit              
# 
# by Milen Rangelov (gat3way-at-gat3way-dot-eu)
#
# Based on 'exit_notify()' CAP_KILL verification bug found by Oleg Nestorov.
# Basically it allows us to send arbitrary signals to a privileged (suidroot)
# parent process. Due to a bad check, the child process with appropriate exit signal
# already set can first execute a suidroot binary then exit() and thus bypass
# in-kernel privilege checks. We use chfn and gpasswd for that purpose.
#
# !!!!!!!!!!!
# Needs /proc/sys/fs/suid_dumpable set to 1 or 2. The default is 0 
# so you'll be out of luck most of the time. 
# So it is not going to be the script kiddies' new killer shit :-)
# !!!!!!!!!!!
#
# if you invent a better way to escalate privileges by sending arbitrary signals to 
# the parent process, please mail me :) That was the best I could think of today :-(
#
# This one made me nostalgic about the prctl(PR_SET_DUMPABLE,2) madness
#
# Skuchna rabota...
#
####################################################################################

