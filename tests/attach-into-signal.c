/* Attaching/detaching a process while it signals itself
   in an endless loop.

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
#endif /* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
#undef ia64_fpreg
#undef pt_all_user_regs
#endif /* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
#include <sys/debugreg.h>
#endif

#include <signal.h>
#include <assert.h>
#include <dirent.h>
#include <limits.h>
#include <sys/wait.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

static int verbose;

#define VERBOSE(...) do { \
  if (verbose) \
    { \
      printf (__VA_ARGS__); \
      fflush (stdout); \
    } \
} while (0)

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
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
  sigfillset(&set);
  sigprocmask(SIG_UNBLOCK, &set, NULL);
  /* Due to kernel bugs, waitpid may block. Need to timeout */
  alarm (1);
  cleanup ();
  assert (0);
}

static void
fire_again (int signo)
{
  raise (signo);
}

/* https://bugzilla.redhat.com/show_bug.cgi?id=470249: */
/* "PTRACE_DETACH,SIGALRM kills the trace" */

/* If nothing strange happens, just returns.
 * Notable events (which are not bugs) print some sort of marker
 * is verbose is on (say, "[signo]" is we got an unusual signal),
 * but still continue and return normally.
 * Known bugs also print a message if verbose, but they exit (1).
 * Known bugs which are not in mainline are explained using
 * C++ style comments (//xxxx).
 * New bugs are likely to trip asserts.
 */
static void reproduce (void)
{
  pid_t pid;
  int status, sig;

  errno = 0;
  child = fork ();
  assert (child >= 0);
  if (child == 0)
    {
      struct sigaction sa;
      memset (&sa, 0, sizeof (sa));
      sa.sa_flags = SA_RESTART;
      sa.sa_handler = fire_again;
      sigaction (SIGQUIT, &sa, NULL);
      raise (SIGQUIT);
      /* may be reached only if tracer makes us "lose" signal */
      _exit (0);
    }

  /* let child start raise (SIGQUIT) in a loop */
  usleep (20 * 1000);

  /* attach. */
  ptrace (PTRACE_ATTACH, child, 0, 0);
  assert_perror (errno);
  /* tracee usually stops with SIGSTOP, but sometimes SIGQUIT gets here faster */
  sig = 0;
  while (1)
    {
      pid = waitpid (child, &status, 0);
      assert (pid == child);
      assert (WIFSTOPPED (status));
      if (WSTOPSIG (status) == SIGSTOP)
	break;
      VERBOSE ("<%d>!", WSTOPSIG (status));
      /* Jan says we should just go back and wait again.
         Don't know, maybe that is what was intended, but
         at least vanilla 2.6.26 does not work that way,
         it will hang in the waitpid. Doing PTRACE_CONT
         prevents this: */
      sig = WSTOPSIG (status);
      ptrace (PTRACE_CONT, child, (void *) 1, (void *) (long) sig);
    }

  /* let tracee run. it must stop very soon with SIGQUIT */
  /* NB: PTRACE_CONT, even though it has "signal" 0 as the last argument,
     nevertheless does not make tracee to continue without signal delivered.
     SIGQUIT was "buffered" for it when we attached. */
  ptrace (PTRACE_CONT, child, (void *) 1, (void *) (long) 0);
  assert_perror (errno);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGQUIT);
  /* let tracee run. it must stop very soon with SIGQUIT */
  /* here we have to pass SIGQUIT, othewise tracee would lose the signal
     and stop looping */
  ptrace (PTRACE_CONT, child, (void *) 1, (void *) SIGQUIT);
  assert_perror (errno);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGQUIT);

  /* detach with SIGQUIT/attach. */
  /* NB: detach without SIGQUIT would make tracee stop looping,
     because we make current raise (SIGQUIT) to _not_ raise SIGQUIT! */
  ptrace (PTRACE_DETACH, child, (void *) 1, (void *) SIGQUIT);
  assert_perror (errno);
  /* attach again */
  ptrace (PTRACE_ATTACH, child, (void *) 0, (void *) 0);
  assert_perror (errno);
  /* tracee usually stops with SIGSTOP, but sometimes SIGQUIT gets here faster */
  sig = 0;
  while (1)
    {
      pid = waitpid (child, &status, 0);
      assert (pid == child);
      assert (WIFSTOPPED (status));
      if (WSTOPSIG (status) == SIGSTOP)
	break;
      VERBOSE ("[%d]!", WSTOPSIG (status));
      sig = WSTOPSIG (status);
      ptrace (PTRACE_CONT, child, (void *) 1, (void *) (long) sig);
    }

  /* let tracee run. it must stop very soon with SIGQUIT */
  ptrace (PTRACE_CONT, child, (void *) 1, (void *) (long) 0);
  assert_perror (errno);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  // unlike vanilla, 2.6.26.6-79.fc9 exits here.
  // workaround is to pass SIGQUIT, not 0, in PTRACE_CONT above
  if (WIFEXITED (status))
    {
      VERBOSE ("<exit:%d>!", WEXITSTATUS (status));
      exit (1);
    }
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGQUIT);

  /* detach with SIGPIPE/attach. This should kill tracee */
  ptrace (PTRACE_DETACH, child, (void *) 1, (void *) SIGPIPE);
  assert_perror (errno);
  ptrace (PTRACE_ATTACH, child, (void *) 0, (void *) 0);
  if (errno == ESRCH)		/* got killed already? */
    {
      errno = 0;
      pid = waitpid (child, &status, 0);
      assert (pid == child);
      assert (WIFSIGNALED (status) && WTERMSIG (status) == SIGPIPE);
      child = 0;
      return;
    }
  if (errno == EPERM)		/* vanilla 2.6.26: sometimes EPERM! why? */
    {
      VERBOSE ("EPERM!");
      return;
    }
  if (errno)
    VERBOSE ("(%d:%s)!", errno, strerror (errno));
  assert_perror (errno);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  /* got killed after attach but before SIGSTOP? */
  if (WIFSIGNALED (status) && WTERMSIG (status) == SIGPIPE)
    {
      child = 0;
      return;
    }
  /* SIGPIPE was still pending and it has not been yet delivered.  */
  if (WIFSTOPPED (status) && WSTOPSIG (status) == SIGPIPE)
    {
      VERBOSE ("Forbidden to catch pending signal from PTRACE_DETACH");
      exit (1);
    }
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);
  /* let tracee run. it must be killed very soon by SIGPIPE */
  ptrace (PTRACE_CONT, child, (void *) 1, (void *) 0);
  assert_perror (errno);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  // unlike vanilla, 2.6.26.6-79.fc9 exits here.
  // passing a SIGPIPE to PTRACE_ATTACH does not help
  if (WIFEXITED (status))
    {
      VERBOSE ("[exit:%d]!", WEXITSTATUS (status));
      exit (1);
    }
  assert (WIFSIGNALED (status));
  assert (WTERMSIG (status) == SIGPIPE);
  child = 0;
}

#define DEFAULT_LOOPS 400

int
main (int argc, char **argv)
{
  int i;
  char *env_testtime = getenv ("TESTTIME"); /* misnomer */
  int testtime = (env_testtime ? atoi (env_testtime) : 1);

  verbose = (argc - 1);
  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);

  // utrace fixes in 2.6.29-0.28.rc1.fc11.x86_64 fixed many regressions,
  // but this test still fails, now nondeterministically and rarely.
  // Even DEFAULT_LOOPS of 400 is not enough to catch it reliably.
  // With TESTTIME=60 or more it should be close to 100%,
  // but takes long time (~10 minutes).
  for (i = 0; i < DEFAULT_LOOPS * testtime; i++)
    {
      alarm (1);
      VERBOSE (".");
      reproduce ();
      alarm (0);
      cleanup ();
    }
  VERBOSE ("\n");
  return 0;
}
