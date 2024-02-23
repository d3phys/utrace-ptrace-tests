/* ...DESCRIPTION...

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
/* #include <pthread.h> */
/* Dance around ptrace.h + user.h incompatibility */
#ifdef __ia64__
# define ia64_fpreg ia64_fpreg_DISABLE
# define pt_all_user_regs pt_all_user_regs_DISABLE
#endif
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#ifdef __ia64__
# undef ia64_fpreg
# undef pt_all_user_regs
#endif
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
# include <sys/debugreg.h>
#endif

/************** Register I/O code (delete if don't need it) *******/

#if defined __x86_64__
# define REGISTER_IP(ur) ((ur).rip)
#elif defined __i386__
# define REGISTER_IP(ur) ((ur).eip)
#elif defined __powerpc__
# define REGISTER_IP(ur) ((ur).nip)
# define user_regs_struct pt_regs
#elif defined __s390__
# define REGISTER_IP(ur) ((ur).psw.addr)
#elif defined __s390x__
/* __s390x__ should have both symbols defined, this should not happen: */
# error "__s390x__ is defined but __s390__ is not, bailing out"
#elif defined __ia64__
# include <asm/ptrace_offsets.h>
/* FIXME: # define REGISTER_IP(ur) [PT_CR_IIP / 8] */
#endif
#if !defined PTRACE_PEEKUSR_AREA && !defined PTRACE_GETREGS
# undef REGISTER_IP
#endif
/* if REGISTER_IP isn't defined here, we don't know how to get/set it */

static long
get_regs (pid_t pid, struct user_regs_struct *ur)
{
  long l;
  /* s390[x] defines PTRACE_GETREGS but it EIOs,
   * using PTRACE_GETREGS only if we have no PTRACE_PEEKUSR_AREA
   */
#ifndef PTRACE_PEEKUSR_AREA
# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, pid, ur, NULL);
# else
  l = ptrace (PTRACE_GETREGS, pid, NULL, ur);
# endif
#else
  ptrace_area parea;
  parea.process_addr = (unsigned long) ur;
  parea.kernel_addr = 0;
  parea.len = sizeof (*ur);
  l = ptrace (PTRACE_PEEKUSR_AREA, pid, &parea, NULL);
#endif
  return l;
}

static long
set_regs (pid_t pid, struct user_regs_struct *ur)
{
  long l;
#ifndef PTRACE_POKEUSR_AREA
# ifdef __sparc__
  l = ptrace (PTRACE_SETREGS, pid, ur, NULL);
# else
  l = ptrace (PTRACE_SETREGS, pid, NULL, ur);
# endif
#else
  ptrace_area parea;
  parea.process_addr = (unsigned long) ur;
  parea.kernel_addr = 0;
  parea.len = sizeof (*ur);
  l = ptrace (PTRACE_POKEUSR_AREA, pid, &parea, NULL);
# if defined __s390__ && !defined __s390x__
  /* s390x kernel does not support s390 debuggers.
   * All attempts to run a s390 binary on s390x will fail here.  */
# endif
#endif
  return l;
}

#ifdef REGISTER_IP
static void
set_pc (struct user_regs_struct *ur, void *func)
{
  REGISTER_IP (*ur) = (unsigned long) func;
# ifdef __powerpc64__
  ur->nip = ((const unsigned long *) func)[0];	/* entry */
  ur->gpr[2] = ((const unsigned long *) func)[1];	/* TOC */
# endif
  /* GDB amd64_linux_write_pc():  */
  /* We must be careful with modifying the program counter.  If we
     just interrupted a system call, the kernel might try to restart
     it when we resume the inferior.  On restarting the system call,
     the kernel will try backing up the program counter even though it
     no longer points at the system call.  This typically results in a
     SIGSEGV or SIGILL.  We can prevent this by writing `-1' in the
     "orig_rax" pseudo-register.

     Note that "orig_rax" is saved when setting up a dummy call frame.
     This means that it is properly restored when that frame is
     popped, and that the interrupted system call will be restarted
     when we resume the inferior on return from a function call from
     within GDB.  In all other cases the system call will not be
     restarted.  */
# ifdef __x86_64__
  ur->orig_rax = -1L;
# elif defined __i386__
  ur->orig_eax = -1L;
# elif defined __powerpc__
  ur->trap = 0;			/* Equivalent to disable syscall restart on powerpc.  */
# endif
}
#endif

/****************** End of register I/O code **********************/

static int verbose;

#define VERBOSE(...) do { \
  if (verbose) \
    { \
      printf (__VA_ARGS__); \
      fflush (stdout); \
    } \
} while (0)

static pid_t child;
/*static pid_t grandchild;*/

static void
sigkill (pid_t * pp)
{
  pid_t pid = *pp;
  *pp = 0;
  if (pid > 0)
    kill (pid, SIGKILL);
}

static void
cleanup (void)
{
  /*sigkill (&grandchild); */
  sigkill (&child);
  while (waitpid (-1, NULL, __WALL) > 0)
    continue;
}

static void
handler_fail (int signo)
{
  sigset_t set;
  signal (SIGABRT, SIG_DFL);
  signal (SIGALRM, SIG_DFL);
  /* SIGALRM may be blocked in sighandler, need to unblock */
  sigfillset (&set);
  sigprocmask (SIG_UNBLOCK, &set, NULL);
  /* Due to kernel bugs, waitpid may block. Need to have a timeout */
  alarm (1);
  cleanup ();
  assert (0);
}

/****************** Standard scaffolding ends here ****************/

/*
 * Extended commentary of the entire test.
 *
 * What kernels / patches exhibit it? When it was fixed?
 * Is it CPU vendor/model dependent? SMP dependent?
 * Is it deterministic?
 * How easy/hard is to reproduce it
 * (always? a dozen loops? a second? minute? etc)
 */

/* If the test is not deterministic:
 * Amount of seconds needed to almost 100% catch it */
#define DEFAULT_TESTTIME 5
/* or (if reproducible in a few loops only) */
#define DEFAULT_LOOPS 100

/* If nothing strange happens, just returns.
 * Notable events (which are not bugs) print some sort of marker
 * if verbose is on, but still continue and return normally.
 * Known bugs also print a message if verbose, but they exit (1).
 * New bugs are likely to trip asserts or cause hang/kernel crash :)
 */
static void
reproduce (void)
{
  VERBOSE (".");
  alarm (1);

  /* Typical scenario starts like this.  */
  child = fork ();
  assert (child != -1);
  if (child == 0)
    {
      ...;
    }

  ...;
  cleanup ();
}

int
main (int argc, char **argv)
{
#if defined DEFAULT_TESTTIME || defined DEFAULT_LOOPS
  int i;
  char *env_testtime = getenv ("TESTTIME");	/* misnomer */
  int testtime = (env_testtime ? atoi (env_testtime) : 1);
#endif

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  verbose = (argc - 1);

#if defined DEFAULT_TESTTIME
  testtime *= DEFAULT_TESTTIME;
  for (i = 0; i < testtime; i++)
    {
      time_t t = time (NULL);
      while (t == time (NULL))
        {
          VERBOSE (".");
	  reproduce ();
        }
    }
  VERBOSE ("\n");
#elif defined DEFAULT_LOOPS
  testtime *= DEFAULT_LOOPS;
  for (i = 0; i < testtime; i++)
    {
      VERBOSE (".");
      reproduce ();
    }
  VERBOSE ("\n");
#else
  reproduce ();
#endif

  return 0;
}
