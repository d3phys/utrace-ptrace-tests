/* Attach to a process which is blocked in read syscall on inotify fd.
   Syscall should be restarted. It is not.

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

#include <sys/inotify.h>

/*
 * Read from inotify fd is spuriously interrupted by PTRACE_ATTACH.
 *
 * Kernel 3.2.1-3.fc16 (and probably many kernels before it) is affected.
 * The bug is deterministic.
 *
 * This is not a ptrace bug per se, it's a bug in inotify code:
 * in one place it returns -EINTR instead of -ERESTARTSYS. But users
 * perceive it as ptrace bug because wrong behaviour is only observable
 * on PTRACE_ATTACH.
 *
 * While inotify bug will probably be fixed soon, many other read/write
 * paths (files/sockets/pipes/etc) are susceptible to having a similar bug.
 * If you find one, extend this testcase to test for it too.
 */

/* If the test is not deterministic:
 * Amount of seconds needed to almost 100% catch it */
//#define DEFAULT_TESTTIME 5
/* or (if reproducible in a few loops only) */
//#define DEFAULT_LOOPS 10

/* If nothing strange happens, just returns.
 * Notable events (which are not bugs) print some sort of marker
 * if verbose is on, but still continue and return normally.
 * Known bugs also print a message if verbose, but they exit (1).
 * New bugs are likely to trip asserts or cause hang/kernel crash :)
 */
static void
reproduce(void)
{
  int status;

  child = fork();
  assert (child != -1);
  if (child == 0)
    {
      char buf[4096];
      int inotify_fd, wd;
      int len;
      const char *filename = getenv("TEST_FILENAME");
      if (!filename)
        filename = "/dev/null";

      inotify_fd = inotify_init();
      assert(inotify_fd >= 0);
      wd = inotify_add_watch(inotify_fd, filename, IN_DELETE_SELF);
      assert(wd >= 0);

      signal(SIGALRM, SIG_DFL);
      alarm(1);

      raise(SIGSTOP);

      errno = 0;
      len = read(inotify_fd, buf, sizeof(buf));
      if (len < 0)
        VERBOSE("bug: read was interrupted by attach, errno: %s\n", strerror(errno));
      exit(0);
    }

  /* Wait for child to stop before read */
  assert(waitpid(-1, &status, WUNTRACED) == child);
  assert(WIFSTOPPED(status));
  assert(WSTOPSIG(status) == SIGSTOP);
  kill(child, SIGCONT);
  usleep(500*1000);
  /* now child has to be blocked in read syscall */

  alarm(2);

  /* Attach and continue */
  assert(ptrace(PTRACE_ATTACH, child, 0, 0) == 0);
  assert(waitpid(-1, &status, 0) == child);
  assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);

  /* Kernel should restart read syscall. ALRM should arrive to child in ~0.5 second */
  assert(waitpid(-1, &status, 0) == child);
  if (WIFEXITED(status)) /* we saw the bug */
    exit(1);
  assert(WIFSTOPPED(status));
  assert(WSTOPSIG(status) == SIGALRM);
  cleanup();
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
