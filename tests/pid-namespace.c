/* Test case for ptrace events across pid namespaces.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/*
  - A child process is forked that calls PTRACE_TRACEME
  - That child then forks a new grandchild process using CLONE_NEWPID
to setup a new pid namespace
  - The grandchild process then vforks a great-grandchild process that
exits with exit code 42.
    + vfork() is needed because the grandchild is "pid 1" for its
namespace; if it exits early, then the great-grandchild will get
SIGKILL'd by the kernel

  - The parent process watches for waitid and ptrace events, collects
the pid_t values it sees for both, and makes sure they're equal sets
  - Also, it makes sure that it sees exit code 42 to make sure it saw
all of the processes.  */

#define _GNU_SOURCE 1
#ifdef __ia64__
#define ia64_fpreg ia64_fpreg_DISABLE
#define pt_all_user_regs pt_all_user_regs_DISABLE
#endif  /* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
#undef ia64_fpreg
#undef pt_all_user_regs
#endif  /* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static int verbose;

static int
must(int x, const char *s)
{
  if (x == -1)
    err(1, "%s", s);
  return x;
}

#define X3(e, file, line) must (e, file ":" #line ": " #e)
#define X2(e, file, line) X3 (e, file, line)
#define X(e) X2 (e, __FILE__, __LINE__)

#define nitems(a) (sizeof((a)) / sizeof((a)[0]))

static void
printpids(const char *s, pid_t *p, size_t n)
{
  if (! verbose)
    return;
  fprintf (stderr, "%s = { ", s);
  for (size_t i = 0; i < n; i++)
    fprintf (stderr, "%lld, ", (long long)p[i]);
  fprintf (stderr, "}\n");
}

static int
pidcompare(const void *a, const void *b)
{
  pid_t x = *(const pid_t *)a;
  pid_t y = *(const pid_t *)b;
  return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static void
test (void)
{
  errno = 0;
  pid_t child = syscall (__NR_clone, SIGCHLD | CLONE_NEWPID, 0, 0, 0);
  if (child == -1 && errno == EPERM)
    exit (77);
  assert_perror (errno);
  assert (child >= 0);
  if (child == 0)
    _exit (13);
  int status;
  pid_t got = wait (&status);
  assert_perror (errno);
  assert (got == child);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 13);
}

static volatile pid_t cleanup_child;

static void
cleanup (void)
{
  kill (cleanup_child, SIGKILL);
}

int
main (int argc, char **argv)
{
  if (argc >= 2)
    verbose = 1;
  test ();

  pid_t p = X(fork());
  if (!p) {
    X(ptrace(PTRACE_TRACEME, 0, 0, 0));
    X(raise(SIGSTOP));

    if (X(syscall(__NR_clone, SIGCHLD | CLONE_NEWPID, 0, 0, 0)))
      _exit(0);

    /*
     * We're "pid 1" here, so if we exit before our children do,
     * they'll be killed with SIGKILL.  Using vfork() ensures
     * that doesn't happen.
     */
    if (X(vfork()))
      _exit(0);
    _exit(42);
  }
  cleanup_child = p;
  atexit (cleanup);

  pid_t forked[10];
  size_t numforked = 0;
  pid_t waited[10];
  size_t numwaited = 0;

  forked[numforked++] = p;

  int setopts = 0;
  int sawexit42 = 0;

  for (;;) {
    siginfo_t si;
    if (waitid(P_ALL, 0, &si, WEXITED | WSTOPPED) == -1) {
      if (errno == ECHILD)
	break;
      err(1, "unexpected waitid error");
    }

    if (si.si_code == CLD_EXITED) {
      assert(numwaited < nitems(waited));
      waited[numwaited++] = si.si_pid;
      if (si.si_status == 42)
	sawexit42 = 1;
    }

    if (si.si_code == CLD_TRAPPED) {
      if (!setopts) {
	X(ptrace(PTRACE_SETOPTIONS, p, 0,
	  (void *)(PTRACE_O_TRACEFORK |
	  PTRACE_O_TRACEVFORK)));
	setopts = 1;
      }
      int event = si.si_status >> 8;
      if (event == PTRACE_EVENT_FORK ||
	  event == PTRACE_EVENT_VFORK) {
	unsigned long msg;
	X(ptrace(PTRACE_GETEVENTMSG, si.si_pid, 0,
	  &msg));
	assert(numforked < nitems(forked));
	forked[numforked++] = msg;
      }
      X(ptrace(PTRACE_CONT, si.si_pid, 0, 0));
    }
  }

  qsort(forked, numforked, sizeof(forked[0]), pidcompare);
  qsort(waited, numwaited, sizeof(waited[0]), pidcompare);

  printpids("forked", forked, numforked);
  printpids("waited", waited, numwaited);

  assert(sawexit42);
  assert(numforked == numwaited);

  int rc = 0;
  for (size_t i = 0; i < numforked; i++)
    if (forked[i] != waited[i])
      {
	rc = 1;
	if (verbose)
	  fprintf (stderr, "forked %d != waited %d\n", forked[i], waited[i]);
      }

  return rc;
}
