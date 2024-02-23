/* Verify if a debugger attaches to and detaches from a T (Stopped) process the
   SIGSTOP notification to its former-real parent is left existing/non-existing
   as it was before the debugger attachment/detachment.  `detach-stopped' PASS
   is a prerequisite for this testcase.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* 1 for a non-threaded process, 2 for single pthread_create(), 3 for two
   pthread_create calls etc.  */
#define THREADS 3

#if THREADS < 1
# error "Use THREADS 1 for a non-threaded process."
#endif

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
#if THREADS > 1
# include <pthread.h>
#endif

static int verbose;

#define VERBOSE(...) do { \
  if (verbose) \
    { \
      printf (__VA_ARGS__); \
      fflush (stdout); \
    } \
} while (0)

static pid_t child[THREADS];

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
  sigkill (&child[0]);
  while (waitpid (-1, NULL, __WALL) > 0)
    continue;
}

static volatile int alrm_expected;
static volatile int alrm_hit;

static void
handler_fail (int signo)
{
  sigset_t set;

  if (signo == SIGALRM && alrm_expected)
    {
      alrm_hit = 1;
      return;
    }

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

/* We attach to threads which are SIGSTOPed, and some are even waited for.
 * (This emulates what gdb has to do in order to correctly attach
 * to a stopped process, without disturbing it and without hanging itself).
 * Then we detach them, re-injecting SIGSTOP. The bug is that
 * not all threads remain stopped.
 *
 * RHEL4 (2.6.9-78.ELsmp) is unaffected.
 * Vanilla kernels are affected at least up to 2.6.29-rc5.
 * The bug is deterministic
 * (sans races, but sleep (1) is hopefully big enough).
 */

/* Amount of seconds needed to almost 100% catch it */
/*define DEFAULT_TESTTIME 5*/
/* or (if reproducible in a few loops only) */
/*#define DEFAULT_LOOPS 100*/

#if THREADS > 1
static void *
child_thread (void *data)
{
  pause ();

  /* NOTREACHED */
  assert (0);
}
#endif /* THREADS > 1 */

/* Spawn THREADS - 1 threads and SIGSTOP ourselves.  */
static void
child_func (void)
{
#if THREADS > 1
  int thread_count;

  for (thread_count = 1; thread_count < THREADS; thread_count++)
    {
      pthread_t thread;
      int i;

      i = pthread_create (&thread, NULL, child_thread, NULL);
      assert (i == 0);
    }
#endif

  /* This stops all threads, not just us (thread group leader).  */
  errno = 0;
  raise (SIGSTOP);
  assert_perror (errno);

  pause ();

  /* NOTREACHED */
  assert (0);
}

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

/* Does PID have a SIGSTOP signal notification we can wait for?  Ensure the
   signal notification is left intact to be possibly retrieved later (again).
   Do not use WNOHANG as we cannot be sure the signal from child has been
   already delivered to us and it would be racy.  */

static int
pid_notifying_sigstop (pid_t pid, int show_state)
{
  siginfo_t siginfo;
  int i, errno_saved;

  assert (alrm_expected == 0);
  assert (alrm_hit == 0);
  alrm_expected = 1;

  /* Do not permit already pending alarm - it must be re-set again after this
     function.  */
  i = alarm (1);
  assert (i == 0);

  errno = 0;
  i = waitid (P_PID, pid, &siginfo, WUNTRACED | WCONTINUED | WNOWAIT);
  errno_saved = errno;

  alarm (0);
  alrm_expected = 0;

  if (i == -1 && errno_saved == EINTR)
    {
      assert (alrm_hit == 1);
      alrm_hit = 0;

      if (show_state)
	VERBOSE ("pid %d: no SIGSTOP, alrm_hit\n", (int) pid);

      return 0;
    }
  
  assert (i == 0);
  assert_perror (errno_saved);
  assert (alrm_hit == 0);
  assert (siginfo.si_pid == pid);
  assert (siginfo.si_uid == getuid ());
  assert (siginfo.si_signo == SIGCHLD);
  assert (siginfo.si_code == CLD_STOPPED);
  assert (siginfo.si_status == SIGSTOP);

  if (show_state)
    VERBOSE ("pid %d: seen available SIGSTOP notification\n", (int) pid);

  return 1;
}

/* Expect CHILD[0] to be set to the PID of the (threaded) process.  */

static void
attach_detach (void)
{
  long l;
  int status, i;
  pid_t pid;
  char dirname[64];
  int child_count;
  DIR *dir;

  errno = 0;
  l = ptrace (PTRACE_ATTACH, child[0], NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  /* The task is still "T (Stopped)", not "T (tracing stop)",
     even after PTRACE_ATTACH.  */
  if (!pid_is_stopped (child[0], 1))
    VERBOSE ("Unexpected state after 1st attach\n");

  /* Sending another SIGSTOP to get SIGSTOP reported by waitpid reliably.
     The danger is, if the task we attach to was already stopped,
     and waited for, PTRACE_ATTACH will not generate another SIGSTOP
     notification. In real-world usage (gdb) tracer must be prepared
     for this case.
     Copied from GDB linux_nat_post_attach_wait().
     This code is required for the reproducibility.  */
  errno = 0;
  i = syscall (__NR_tkill, child[0], SIGSTOP);
  assert_perror (errno);
  assert (i == 0);

  /* Transition from "(T) Stopped" to "T (tracing stop)" happens somewhere
     between PTRACE_CONT and waitpid.  */
  errno = 0;
  l = ptrace (PTRACE_CONT, child[0], NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  pid = waitpid (child[0], &status, 0);
  assert (pid == child[0]);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) == 0)
    {
      VERBOSE ("SIG_0\n");
      exit (1);
    }
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Read TIDs from /proc/PID/task.  */
  snprintf (dirname, sizeof dirname, "/proc/%d/task", (int) child[0]);
  dir = opendir (dirname);
  assert (dir != NULL);
  child_count = 1;
  for (;;)
    {
      struct dirent *dirent;
      char *s;
      pid_t tid;

      errno = 0;
      dirent = readdir (dir);
      if (!dirent)
	{
	  assert_perror (errno);
	  break;
	}

      if (dirent->d_name[0] == '.')
	continue;

      tid = l = strtol (dirent->d_name, &s, 10);
      assert (l > 0 && l <= INT_MAX && *s == 0);
      if (tid == child[0])
	continue;
      assert (child_count < THREADS);
      child[child_count++] = tid;

      /* Threads must be in "stopped" state because of raise (SIGSTOP)
         in thread group leader. Checking.  */
      assert (pid_is_stopped (tid, 1));

      errno = 0;
      ptrace (PTRACE_ATTACH, tid, NULL, NULL);
      assert_perror (errno);

      /* This sleep isn't strictly needed, but helps to ensure that
         pid_is_stopped checks state _after_ PTRACE_ATTACH affected
         the task.  */
      sleep (1);
      if (!pid_is_stopped (tid, 1))
	VERBOSE ("Unexpected state after thread is attached to\n");

      /* Sending SIGSTOP to get SIGSTOP reported by waitpid reliably.  */
      errno = 0;
      i = syscall (__NR_tkill, tid, SIGSTOP);
      assert_perror (errno);
      assert (i == 0);

      errno = 0;
      l = ptrace (PTRACE_CONT, tid, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);

      pid = waitpid (tid, &status, __WCLONE);
      assert (pid == tid);
      assert (WIFSTOPPED (status));
      assert (WSTOPSIG (status) == SIGSTOP);
    }
  assert (child_count == THREADS);

  closedir (dir);

  for (child_count = THREADS - 1; child_count >= 0; child_count--)
    {
      /* The delay is essential for reproducibility (for example,
         on 2.6.25-14.fc9.x86_64). Vanilla 2.6.29-rc5 does not
         require it and still exhibits the bug.  */
      sleep (1);

      errno = 0;
      l = ptrace (PTRACE_DETACH, child[child_count], NULL, (void *) SIGSTOP);
      assert_perror (errno);
      assert (l == 0);
    }
  sleep (1);

  /* Check that all tasks are stopped now.  */
  // This is the bug the testcase was created for.
  // Some threads ignore the SIGSTOP in detach.
  //
  // On vanilla 2.6.29-rc5, observed behavior is that thread leader
  // reaches pause () and thus is displayed as "S (sleeping)",
  // and all but one thread are "R (running)" - they sched_yield ()
  // in infinite loop.
  // Only the last thread (one we detached first) seems to be properly
  // "T (stopped)".
  // Example with THREADS = 3:
  // # ./detach-stopped v
  // pid 30489: 'State:      S (sleeping)'
  // pid 30490: 'State:      R (running)'
  // (pid 30489 is the thread group leader)
  i = 0;
  for (child_count = 0; child_count < THREADS; child_count++)
    i += !pid_is_stopped (child[child_count], 1);

  if (i)
    {
      VERBOSE ("(pid %d is the thread group leader)\n", (int) child[0]);
      exit (1);
    }
}

/* If nothing strange happens, just returns.  Notable events (which are not
   bugs) print some sort of marker is verbose is on, but still continue and
   return normally.  Known bugs also print a message if verbose, but they exit
   (1).  New bugs are likely to trip asserts or cause hang/kernel crash. :)  */

static void
reproduce (void)
{
  pid_t pid;
  int i, status;

  i = alarm (1);
  assert (i == 0);

  pid = fork ();
  switch (pid)
    {
    case -1:
      assert_perror (errno);
      assert (0);
      /* NOTREACHED */
    case 0:
      child_func ();
      assert (0);
      /* NOTREACHED */
    default:
      child[0] = pid;
      break;
    }

  /* Verify SIGSTOP notification is now available.  */

  /* FIXME: Verify always all the tasks, not just the first task - as the whole
     thread group (=process).  But we need waitid - not waitpid - to use
     WNOWAIT - and at the same time waitid does not support __WALL (while
     waitpid does support __WALL).  */

  alarm (0);
  if (!pid_notifying_sigstop (child[0], 1))
    VERBOSE ("No waiting SIGSTOP after the first wait on SIGSTOP\n");

  if (!pid_is_stopped (child[0], 1))
    VERBOSE ("Child not stopped after the first wait on SIGSTOP\n");

  /* Verify WNOWAIT works and pid_notifying_sigstop did not ate our lunch.  */
  if (!pid_notifying_sigstop (child[0], 1))
    VERBOSE ("No waiting SIGSTOP after the second wait on SIGSTOP\n");

  i = alarm (2 * THREADS + 10);
  assert (i == 0);

  attach_detach ();

  /* Verify SIGSTOP notification is still available even after attach/detach.
     */

  alarm (0);
  if (!pid_notifying_sigstop (child[0], 1))
    VERBOSE ("No waiting SIGSTOP after the first attach/detach\n");

  i = alarm (1);
  assert (i == 0);

  /* Eat the SIGSTOP notification.  */

  /* FIXME: Why WUNTRACTED is not needed in attach_detach?  */
  errno = 0;
  pid = waitpid (child[0], &status, WUNTRACED);
  assert (pid == child[0]);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  alarm (0);
  if (pid_notifying_sigstop (child[0], 1))
    VERBOSE ("Excessive waiting SIGSTOP after it was already waited for\n");

  i = alarm (2 * THREADS + 10);
  assert (i == 0);

  attach_detach ();

  /* Verify SIGSTOP notification did not appear again due to attach/detach if
     it was already eaten-out before attach/detach.  */

  alarm (0);
  if (pid_notifying_sigstop (child[0], 1))
    VERBOSE ("Excessive waiting SIGSTOP after the second attach/detach\n");

  cleanup ();
}

/* Standard */
int
main (int argc, char **argv)
{
#if defined DEFAULT_TESTTIME || defined DEFAULT_LOOPS
  char *env_testtime = getenv ("TESTTIME");	/* misnomer */
  int testtime = (env_testtime ? atoi (env_testtime) : 1);
#endif
  struct sigaction act;
  int i;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);

  memset (&act, 0, sizeof (act));
  act.sa_handler = handler_fail;
  i = sigemptyset (&act.sa_mask);
  assert (i == 0);
  /* SA_RESTART would be set by the signal call - so we use sigaction.  It is
     being used by ALRM_EXPECTED which needs to break the wait calls.  */
  act.sa_flags = 0;
  i = sigaction (SIGALRM, &act, NULL);
  assert (i == 0);

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
