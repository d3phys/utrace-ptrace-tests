/* Test that waitpit doesn't report already reported stopped traced process.

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

/* If waitpid reported that tracee has stopped, subsequent waitpid's
 * should never report it again until it is restarted
 * and stopped again, exited or killed.
 * The bug makes it report the stop again, with bogus signal# 0.
 * On RHEL5.3 kernels, it happens on ia64, x86_64, i386.
 * It happens on the first try.
 */

/* Test a few times. Paranoia. */
#define DEFAULT_LOOPS 30

/* If nothing strange happens, just returns.
 * Notable events (which are not bugs) print some sort of marker
 * is verbose is on, but still continue and return normally.
 * Known bugs also print a message if verbose, but they exit (1).
 * New bugs are likely to trip asserts or cause hang/kernel crash :)
 */
static void
reproduce (void)
{
  int pid, ws;

  VERBOSE (".");
  alarm (1);

  child = fork ();
  assert (child >= 0);
  if (child == 0)
    {
      ptrace (PTRACE_TRACEME, 0, 0, 0);
      kill (getpid (), SIGSTOP);
      _exit (42);
    }

  /* Confirm SIGSTOP stop */
  pid = waitpid (-1, &ws, 0);
  assert (pid == child);
  assert (WIFSTOPPED (ws) && WSTOPSIG (ws) == SIGSTOP);

  /* Stop on entry to exit syscall */
  errno = 0;
  // SIGSTOP is crucial for bug to happen! 0 would work ok
  ptrace (PTRACE_SYSCALL, pid, NULL, SIGSTOP);
  assert_perror(errno);
  pid = waitpid (-1, &ws, 0);
  assert (pid == child);
  assert (WIFSTOPPED (ws) && WSTOPSIG (ws) == SIGSTOP);

  /* This waitpid should return 0: "no waitable processes" */
  pid = waitpid (-1, &ws, WNOHANG);
  assert (pid == 0 || pid == child);

  cleanup ();

  if (pid == 0)
    return;
  // Bug: RHEL5.3 returns child's pid again,
  // with WIFSTOPPED != 0 and WSTOPSIG == 0
  VERBOSE ("bug: waitpid re-reported stopped task. status %x: ", ws);
  if (WIFSIGNALED (ws))
    VERBOSE ("killed by signal %d\n", WTERMSIG (ws));
  else if (WIFEXITED (ws))
    VERBOSE ("exited %d\n", WEXITSTATUS (ws));
  else if (WIFSTOPPED (ws))
    VERBOSE ("stopped by %d\n", WSTOPSIG (ws));
  else
    VERBOSE ("unexpected status!\n");
  _exit (1);
}

int
main (int argc, char **argv)
{
  int i;
#if defined DEFAULT_TESTTIME || defined DEFAULT_LOOPS
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
	reproduce ();
    }
  VERBOSE ("\n");
#elif defined DEFAULT_LOOPS
  testtime *= DEFAULT_LOOPS;
  for (i = 0; i < testtime; i++)
    reproduce ();
  VERBOSE ("\n");
#else
  reproduce ();
#endif

  return 0;
}
