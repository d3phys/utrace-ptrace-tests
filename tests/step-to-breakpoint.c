/* utrace kernels may skip two instructions with a single PTRACE_SINGLESTEP.
   The kernel just needs to get broken by using a watchpoint on an unrelated
   process before (even the debugging process can be different).

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#ifdef __ia64__
#define ia64_fpreg ia64_fpreg_DISABLE
#define pt_all_user_regs pt_all_user_regs_DISABLE
#endif	/* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
#undef ia64_fpreg
#undef pt_all_user_regs
#endif	/* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
#include <sys/debugreg.h>
#endif

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stddef.h>
#include <sched.h>
#include <string.h>
#include <time.h>

/* This testcase would make sense to enlist as a CRASHER as it affects the
   behavior of the other testcases run later.  */

/* In fact it gets reproduced in the first/second cycle.  */
#define DEFAULT_TESTTIME 2	/* seconds */

/* The testcase works with any of the DR registers 0..3 but we just run it
   with the register 0 for some simplicity.  */
#define PREP_USE_HW_REG	0

/* It is only important to bind to some single CPU.  We would need to check the
   number of processors on the system if it would not be 0.  See also the CPU
   parameter of CHILD_CPU_BIND.  */
#define PREP_USE_CPU 0

/* #define DEBUG  */

#ifdef __i386__
/*
 * DR_LEN_8 is required for the reproducibility.
# define PC eip
# define STACKP "%ebp"
*/
#endif
#ifdef __x86_64__
# define PC rip
# define STACKP "%rsp"
#endif

#ifndef PC

int
main (void)
{
  return 77;
}

#else	/* supported arch */

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (SIGABRT, SIG_DFL);
  assert (0);
}

/* Without this function you may also use the kernel parameter "maxcpus=1".
   CPU should be always passed as 0.  You can try passing 0 and 1 for PREP
   and VERIFY, respectively - you will see the problem is reliably
   unreproducible.  But still you permanently harm the PREP CPU this way and it
   fails if you switch the CPU numbers later.  Also under some unclear
   conditions you may "unbreak" the CPU by running some other apps.  */

static void
child_cpu_bind (int cpu)
{
  cpu_set_t cpuset;
  int i;

  assert (child > 0);

  assert (CPU_SETSIZE >= 1);

  CPU_ZERO (&cpuset);
  CPU_SET (cpu, &cpuset);
  i = sched_setaffinity (child, sizeof cpuset, &cpuset);
  assert (i == 0);

  /* Only sanity check it was set right.  */

  i = sched_getaffinity (child, sizeof cpuset, &cpuset);
  assert (i == 0);
  for (i = 0; i < 8 * sizeof cpuset; i++)
    assert (CPU_ISSET (i, &cpuset) == (i == cpu));
}

/* The PREP part starts here.  */

/* Debug registers' indices.  */
#define DR_NADDR	4	/* The number of debug address registers.  */
#define DR_CONTROL	7	/* Index of debug control register (DR7). */

/* DR7 Debug Control register fields.  */

/* How many bits to skip in DR7 to get to R/W and LEN fields.  */
#define DR_CONTROL_SHIFT	16
/* How many bits in DR7 per R/W and LEN field for each watchpoint.  */
#define DR_CONTROL_SIZE		4

/* Watchpoint/breakpoint read/write fields in DR7.  */
#define DR_RW_WRITE	(0x1)	/* Break on data writes.  */

/* Watchpoint/breakpoint length fields in DR7.  The 2-bit left shift
   is so we could OR this with the read/write field defined above.  */
#ifndef DR_LEN_8
# define DR_LEN_8	(0x2 << 2) /* 8-byte region watch (AMD64).  */
#elif DR_LEN_8 != (0x2 << 2)
# error "DR_LEN_8?"
#endif

/* Local and Global Enable flags in DR7.

   When the Local Enable flag is set, the breakpoint/watchpoint is
   enabled only for the current task; the processor automatically
   clears this flag on every task switch.  When the Global Enable flag
   is set, the breakpoint/watchpoint is enabled for all tasks; the
   processor never clears this flag.

   Currently, all watchpoint are locally enabled.  If you need to
   enable them globally, read the comment which pertains to this in
   i386_insert_aligned_watchpoint below.  */
#define DR_LOCAL_ENABLE_SHIFT	0 /* Extra shift to the local enable bit.  */
#define DR_ENABLE_SIZE		2 /* Two enable bits per debug register.  */

/* Local and global exact breakpoint enable flags (a.k.a. slowdown
   flags).  These are only required on i386, to allow detection of the
   exact instruction which caused a watchpoint to break; i486 and
   later processors do that automatically.  We set these flags for
   backwards compatibility.  */
#define DR_LOCAL_SLOWDOWN	(0x100)

static volatile unsigned long prep_var;

static int
prep (void)
{
  long l;
  pid_t pid;
  int i, status;
  unsigned long control;
  int retval;

  assert (child == 0);
  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);
      i = raise (SIGUSR1);
      assert (i == 0);
      asm volatile ("int3" ::: "memory");
      /* If we get here it is already a failure.  */
      raise (SIGUSR2);
      assert (0);
    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  child_cpu_bind (PREP_USE_CPU + 0);

  assert (PREP_USE_HW_REG >= 0);
  assert (PREP_USE_HW_REG < DR_NADDR);

  /* Other PREP_VAR sizes or non-setting of some of the DR registers makes the
     problem unreproducible.  */

  assert (sizeof (prep_var) == 8);
  /* PREP_VAR is LONG-aligned?  */
  assert ((((unsigned long) &prep_var) & 0x7) == 0);

  control = ((DR_LEN_8 | DR_RW_WRITE)
	     << (DR_CONTROL_SHIFT + PREP_USE_HW_REG * DR_CONTROL_SIZE))
	    | DR_LOCAL_SLOWDOWN
	    | (1 << (DR_LOCAL_ENABLE_SHIFT + PREP_USE_HW_REG * DR_ENABLE_SIZE));
  assert (PREP_USE_HW_REG !=0 || control == 0x90101);

  errno = 0;
  l = ptrace (PTRACE_POKEUSER, child,
	      offsetof (struct user, u_debugreg[PREP_USE_HW_REG]),
	      (unsigned long) &prep_var);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  l = ptrace (PTRACE_POKEUSER, child,
	      offsetof (struct user, u_debugreg[DR_CONTROL]), control);
  assert_perror (errno);
  assert (l == 0);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) == SIGUSR2)
    {
      /* Seen on:
       * vendor_id	: GenuineIntel
       * cpu family	: 15
       * model		: 6
       * model name	:                   Intel(R) Xeon(TM) CPU 3.20GHz
       * stepping	: 4
       * kernel-2.6.18-88.el5.x86_64, Red Hat host 10.12.4.222.  */
      retval = 1;
      goto cleanup;
    }
  assert (WSTOPSIG (status) == SIGTRAP);

  control &= ~(1 << (DR_LOCAL_ENABLE_SHIFT + PREP_USE_HW_REG * DR_ENABLE_SIZE));
  assert (PREP_USE_HW_REG !=0 || control == 0x90100);

  errno = 0;
  l = ptrace (PTRACE_POKEUSER, child,
	      offsetof (struct user, u_debugreg[DR_CONTROL]), control);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  l = ptrace (PTRACE_POKEUSER, child,
	      offsetof (struct user, u_debugreg[PREP_USE_HW_REG]),
	      (unsigned long) NULL);
  assert_perror (errno);
  assert (l == 0);

  retval = 0;
cleanup:
  assert (child > 0);
  i = kill (child, SIGKILL);
  assert (i == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSIGNALED (status));
  assert (WTERMSIG (status) == SIGKILL);

  child = 0;

  return retval;
}

/* The PREP part ends here.  */

/* The VERIFY part starts here.  */

asm (
"	.text				\n"
"func0:	int3				\n"
"func1:	mov	%eax,-0x8(" STACKP ")		\n"
"func2:	nop				\n"
"func3:	int3				\n"
);
extern void func0 (void);
extern void func1 (void);
extern void func2 (void);
extern void func3 (void);

/* Required to get the right addresses in the -fPIE mode.  OTOH `-fPIE -pie' is
   not required for the reproducibility.  */
#ifdef DEBUG
static void (*func0addr) (void) = func0;
#endif
static void (*func1addr) (void) = func1;
static void (*func2addr) (void) = func2;
static void (*func3addr) (void) = func3;

static int
verify (void)
{
  long l;
  int status, i;
  pid_t pid;
  struct user_regs_struct regs;
#ifdef PTRACE_GETSIGINFO
  siginfo_t siginfo;
#endif

  assert (child == 0);
  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);
      i = raise (SIGUSR1);
      func0 ();
      assert (0);
    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  child_cpu_bind (PREP_USE_CPU + 0);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

#ifdef PTRACE_GETSIGINFO
  l = ptrace (PTRACE_GETSIGINFO, child, NULL, &siginfo);
  assert (l == 0);
# ifdef DEBUG
  printf ("si_signo = %d, si_errno = %d, si_code = %d\n", siginfo.si_signo,
	  siginfo.si_errno, siginfo.si_code);
# endif	/* DEBUG */
  assert (siginfo.si_signo == SIGTRAP);
  assert_perror (siginfo.si_errno);
  assert (siginfo.si_code != 0);
#endif	/* PTRACE_GETSIGINFO */

# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, child, &regs, NULL);
# else
  l = ptrace (PTRACE_GETREGS, child, NULL, &regs);
# endif
  assert (l == 0);
#ifdef DEBUG
  printf ("func0 = 0x%p\n", func0addr);
  printf ("func1 = 0x%p\n", func1addr);
  printf ("func2 = 0x%p\n", func2addr);
  printf ("func3 = 0x%p\n", func3addr);
  printf ("pc=0x%lx\n", regs.PC);
#endif

  assert (regs.PC == (unsigned long) func1addr);

  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

#ifdef PTRACE_GETSIGINFO
  l = ptrace (PTRACE_GETSIGINFO, child, NULL, &siginfo);
  assert (l == 0);
# ifdef DEBUG
  printf ("si_signo = %d, si_errno = %d, si_code = %d\n", siginfo.si_signo,
	  siginfo.si_errno, siginfo.si_code);
# endif	/* DEBUG */
  assert (siginfo.si_signo == SIGTRAP);
  assert_perror (siginfo.si_errno);
  assert (siginfo.si_code != 0);
#endif	/* PTRACE_GETSIGINFO */

# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, child, &regs, NULL);
# else
  l = ptrace (PTRACE_GETREGS, child, NULL, &regs);
# endif
  assert (l == 0);
#ifdef DEBUG
  printf ("pc=0x%lx\n", regs.PC);
#endif

  assert (child > 0);
  i = kill (child, SIGKILL);
  assert (i == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSIGNALED (status));
  assert (WTERMSIG (status) == SIGKILL);

  child = 0;

  /* Fedora 8 GOLD kernel-2.6.23.1-42.fc8.x86_64  */
  if (regs.PC == (unsigned long) func3addr)
    return 1;
  assert (regs.PC == (unsigned long) func2addr);

  return 0;
}

/* The VERIFY part ends here.  */

int
main (void)
{
  char *testtime = getenv ("TESTTIME");
  int testtime_i = (testtime != NULL ? atoi (testtime) : DEFAULT_TESTTIME);
  time_t testend = time (NULL) + testtime_i;
  int retval;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (testtime_i + 2);

  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);

  do
    {
      /* We need to FUBAR the kernel ptrace first, it is a fully independent
	 operation from VERIFY, it could be even run some time before by
	 a different user from a different process.  */

      retval = prep ();
      if (retval != 0)
        break;

      retval = verify ();
      if (retval != 0)
        break;
    }
  while (time (NULL) < testend);

  return retval;
}

#endif	/* supported arch */
