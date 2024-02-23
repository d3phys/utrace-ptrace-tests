/* Attach to a T (Stopped) process and detach it sleeping (=not stopped).
   Use the universal attaching magic as implemented (only) by F/RH GDB.

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

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

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

/* We attach to process which is SIGSTOPed.
 * (This emulates what gdb has to do in order to correctly attach
 * to a stopped process, without disturbing it and without hanging itself).
 * Then we detach it (not re-injecting SIGSTOP). The bug is that
 * it may remain stopped.
 *
 * RHEL4 (2.6.9-78.ELsmp) is unaffected.
 * Vanilla kernels up to 2.6.29 are not affected.
 * Vanilla kernels are affected at least for 2.6.30-rc7.git3.
 * The bug is deterministic
 * (sans races, but sleep (1) is hopefully big enough).
 */

/* Amount of seconds needed to almost 100% catch it */
/*define DEFAULT_TESTTIME 5*/
/* or (if reproducible in a few loops only) */
/*#define DEFAULT_LOOPS 100*/

/* Is PID in "(T) Stopped" state?  */
static int
pid_is_stopped (pid_t pid, int show_state)
{
  int fd, i;
  char buf[100];
  char *s;

  snprintf (buf, sizeof (buf), "/proc/%d/status", (int) pid);
  fd = open (buf, O_RDONLY);
  assert (fd >= 0);

  /* /proc read never returns partial result.  */
  i = read (fd, buf, sizeof (buf) - 1);
  close (fd);
  assert (i > 0);
  buf[i] = 0;
  s = strstr (buf, "State:");
  assert (s);

  if (strstr (s, "T (stopped)") == NULL)
    {
      *strchrnul (s, '\n') = 0;
      if (show_state)
	VERBOSE ("pid %d: '%s'\n", (int) pid, s);
      return 0;
    }
  return 1;
}

/* If nothing strange happens, just returns.
 * Notable events (which are not bugs) print some sort of marker
 * is verbose is on, but still continue and return normally.
 * Known bugs also print a message if verbose, but they exit (1).
 * New bugs are likely to trip asserts or cause hang/kernel crash :)
 */
static void
reproduce (void)
{
  long l;
  int status, i;
  pid_t pid;

  alarm (3);

  child = fork ();
  switch (child)
    {
    case 0:
      errno = 0;
      i = raise (SIGSTOP);
      assert_perror (errno);
      assert (i == 0);

      pause ();
      /* NOTREACHED */
      assert_perror (errno);
      assert (0);
    case -1:
      assert_perror (errno);
      assert (0);
    default:
      break;
    }

  errno = 0;
  i = sleep (1);
  assert_perror (errno);
  assert (i == 0);

  /* The task is still "T (Stopped)", not "T (tracing stop)",
     even after PTRACE_ATTACH.  */
  if (!pid_is_stopped (child, 1))
    {
      VERBOSE ("Unexpected state after 1st attach\n");
      assert (0);
    }

  errno = 0;
  l = ptrace (PTRACE_ATTACH, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  /* No tkill/PTRACE_CONT is needed with kernel-3.x.  Also process is
     immediately in `t (tracing stop)' mode.  */

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) == 0)
    {
      VERBOSE ("SIG_0\n");
      assert (0);
    }
  assert (WSTOPSIG (status) == SIGSTOP);

  errno = 0;
  l = ptrace (PTRACE_DETACH, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  /* PTRACE_DETACH (SIGCONT) does not work.  */
  errno = 0;
  i = kill (child, SIGCONT);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  i = sleep (1);
  assert_perror (errno);
  assert (i == 0);

  if (pid_is_stopped (child, 1))
    {
      VERBOSE ("child got stopped");
      exit (1);
    }

  cleanup ();
}

/* SKIP if kernel major version is not $ver.  */

static void
kernel (int ver)
{
  struct utsname utsname;
  int i, major, minor;

  assert (ver == 2 || ver == 3);

  i = uname (&utsname);
  assert_perror (errno);
  assert (i == 0);
  assert (strcmp (utsname.sysname, "Linux") == 0);

  i = sscanf (utsname.release, "%d.%d", &major, &minor);
  assert (i == 2);

  if (ver == 2 && major > 2)
    exit (77);
  if (ver == 3 && major < 3)
    exit (77);
}

int
main (int argc, char **argv)
{
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

  kernel (3);

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
