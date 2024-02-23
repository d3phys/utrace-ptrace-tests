/* Test for PTRACE_DETACH + SIGKILL races.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#ifdef __ia64__
# define ia64_fpreg ia64_fpreg_DISABLE
# define pt_all_user_regs pt_all_user_regs_DISABLE
#endif /* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
# undef ia64_fpreg
# undef pt_all_user_regs
#endif /* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
# include <sys/debugreg.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/syscall.h>


static int verbose;

#define VERBOSE(...) do { \
  if (verbose) \
    { \
      printf (__VA_ARGS__); \
      fflush (stdout); \
    } \
} while (0)

#ifdef __ia64__
extern int __clone2 (int (*fn)(void *), void *child_stack_base,
		     size_t stack_size, int flags, void *arg, ...);
#define clone2 __clone2
#else
#define clone2(func, stack_base, size, flags, arg...) \
	clone (func, (stack_base) + (size), flags, arg)
#endif

static pid_t child;
static pid_t clone_tid;
static pid_t grandchild;
static pid_t grandchild2;

static void
sigkill (pid_t *pp)
{
  pid_t pid = *pp;
  *pp = 0;
  if (pid > 0)
    kill (pid, SIGKILL);
}

static void
cleanup (void)
{
  sigkill (&grandchild2);
  sigkill (&grandchild);
  sigkill (&clone_tid);
  sigkill (&child);
  while (waitpid (-1, NULL, __WALL) > 0)
    continue;
}

static void
handler_fail (int signo)
{
  sigset_t set;

  /* NB: we use SIGINT to stop tasks if one task detected the bug,
   * be silent on SIGINT.
   */

  if (signo != SIGINT)
    VERBOSE ("process %u has unreapable dead child %u\n", getpid (), child);
  signal (SIGABRT, SIG_DFL);
  signal (SIGALRM, SIG_DFL);
  /* SIGALRM may be blocked in sighandler, need to unblock */
  sigfillset (&set);
  sigprocmask (SIG_UNBLOCK, &set, NULL);
  /* Due to kernel bugs, waitpid may block. Need to have a timeout */
  alarm (1);
  cleanup ();
  if (signo == SIGINT)
    _exit (1);			/* exit silently */
  assert (0);
}

/****************** Standard scaffolding ends here ****************/

/* There are two bugs we are looking for:
 * 1. PTRACE_DETACH + SIGKILL race may leave unreapable zombie,
 * Mainline kernels <= 2.6.28 are affected
 * Also observed on Fedora 2.6.29-0.28.rc1.fc11.x86_64
 * 2. PTRACE_ATTACH + PTRACE_DETACH unblocks pause () in the traced process.
 * (I think bug #2 is also covered in other testsuite entries)
 *
 * Both bugs are non-deterministic, bug #2 happens within a few seconds
 * for me, but bug #1 hits ~90% only with TESTTIME=60. Bumping up PARALLEL
 * to 8 _decreased_ the probability of hitting it on my 2 CPU machine.
 * Perhaps PARALLEL should be set to ~ (no_of_CPUs / 2).
 */

#define PARALLEL 1

/* If the test is not deterministic:
 * Amount of seconds needed to almost 100% catch it */
/* #define DEFAULT_TESTTIME 5 */
/* or (if reproducible in a few loops only) */
#define DEFAULT_LOOPS 2000

static int
tfunc (void *arg)
{
  pause ();
  // Bug #2: pause may finish because of SIGSTOP from PTRACE_ATTACH,
  // even though this SIGSTOP _is supposed to be_ unobservable
  // by us (the tracee)
  return 42;
}

static char stack[16 * 1024];

/* If nothing strange happens, should be killed by SIGKILL
 * by its own children.
 * The bug causes it to not die.
 */
static void
reproduce (void)
{
  pid_t pid;

  /* Make two threads, both blocked on pause(), and a grandchild */
  clone_tid = clone2 (tfunc, stack, sizeof (stack) / 2,
		      CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
		      CLONE_VM, NULL);
  assert (clone_tid > 0);
  grandchild = fork ();
  assert (grandchild >= 0);
  if (grandchild != 0)
    for (;;)
      pause ();			/* thread group leader is here */

  /* Grandchild: attach to the thread which isn't a thread group leader */
  errno = 0;
  ptrace (PTRACE_ATTACH, clone_tid, NULL, NULL);
  assert_perror (errno);
  pid = waitpid (-1, NULL, __WALL | WUNTRACED);
  assert (pid == clone_tid);

  /* Simultaneously PTRACE_DETACH and SIGKILL the thread.
   * NB: fatal signals kill ALL threads in the thread group,
   * even if sent by t[g]kill.
   */
  // Bug #1: kernel may fail to destroy the thread (it will stay as zombie,
  // which should never happen with non-thread group leaders).
  // Therefore the whole thread group becomes unreapable.
  grandchild2 = fork ();
  assert (grandchild2 >= 0);
  if (grandchild2 != 0)
    ptrace (PTRACE_DETACH, clone_tid, NULL, 0);	/* grandchild */
  else
    syscall (__NR_tkill, clone_tid, SIGKILL);	/* grand-grandchild */

  _exit (0);
}

int
main (int argc, char **argv)
{
  pid_t pidvec[PARALLEL];
  int i;
  char *env_testtime = getenv ("TESTTIME");	/* misnomer */
  int testtime = (env_testtime ? atoi (env_testtime) : 1);

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  verbose = (argc - 1);

  /* Create N copies of the test */
  i = PARALLEL;
  while (i--)
    {
      pidvec[i] = fork ();
      assert (pidvec[i] >= 0);
      if (pidvec[i] == 0)
	break;
    }

  if (i < 0)
    {
      /* Parent: wait for tests. If any of them fail, kill all. */
      int ws;
      while (wait (&ws) > 0)
	if (!WIFEXITED (ws) || WEXITSTATUS (ws) != 0)
	  {
	    i = PARALLEL;
	    while (i--)
	      kill (pidvec[i], SIGINT);
	    return 1;
	  }
      VERBOSE ("\n");
      return 0;
    }

  /* Child (N copies) */
  testtime *= DEFAULT_LOOPS;
  for (i = 0; i < testtime; i++)
    {
      int ws;
      pid_t pid;

      if ((i & 0x7f) == 0)
	VERBOSE (".");

      alarm (2);

      child = fork ();
      assert (child >= 0);
      if (child == 0)
	reproduce ();		/* does not return */

      pid = wait (&ws);
      assert (pid == child);
      if (WIFSIGNALED (ws) && WTERMSIG (ws) == SIGKILL)
	{
	  // VERBOSE("%u was killed by SIGKILL as expected\n", pid);
	}
      else
	{
	  if (WIFSIGNALED (ws))
	    {
	      VERBOSE ("%u killed by signal %d\n", pid, WTERMSIG (ws));
	      _exit (1);
	    }
	  if (WIFEXITED (ws))
	    {
	      // Bug #2
	      VERBOSE ("%u exited %d\n", pid, WEXITSTATUS (ws));
	      // We want to catch bug #1... for now, disabled: _exit (1);
	      continue;
	    }
	  VERBOSE ("%u has unexpected status %x\n", pid, ws);
	  _exit (1);
	}
    }
  return 0;
}
