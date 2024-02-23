/* This software is provided 'as-is', without any express or implied
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

#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>

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
  signal (signo, SIG_DFL);
  raise (signo);
}

static int
create_zombie (void)
{
  pid_t got_pid;
  long l;
  char buf[0x1000];
  ssize_t got;
  int fd;
  int status;

  child = fork ();
  if (child < 0)
    abort ();
  if (child == 0)
    {
      ptrace (PTRACE_TRACEME);
      raise (SIGUSR1);
      _exit (23);
      /* NOTREACHED */
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  /* We must open the status file first as if CHILD would finish in between
     PTRACE_CONT and this OPEN we would fail with ESRCH as no zombie is left
     as we have set the SIGCHLD handler to SIG_IGN (kernel reaps the dead
     children without creating any zombies).  */
  snprintf (buf, sizeof buf, "/proc/%d/status", (int) child);
  fd = open (buf, O_RDONLY);
  assert (fd != -1);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  do
    {
      sched_yield ();
      errno = 0;
      got = lseek (fd, SEEK_SET, 0);
      assert_perror (errno);
      assert (got == 0);
      got = read (fd, buf, sizeof buf - 1);
      if (got < 0)
	{
	  if (errno == ESRCH)
	    break;
	  assert_perror (errno);
	}
      assert (got > 0);
      assert (got < sizeof buf);
      buf[got] = 0;
    }
  while (strstr (buf, "\nState:\tZ ") == NULL);

  /* Now it should have exited.  */

  return fd;
}

static int
check_reaped (int fd)
{
  char buf[0x1000];
  ssize_t got;
  const char *p;

  errno = 0;
  got = lseek (fd, SEEK_SET, 0);
  assert_perror (errno);
  assert (got == 0);
  got = read (fd, buf, sizeof buf - 1);
  if (got < 0)
    {
      if (errno == ESRCH)
	return 0;
      assert_perror (errno);
    }
  assert (got > 0);
  assert (got < sizeof buf);
  buf[got] = 0;

  p = strstr (buf, "\nState:\t");
  assert (p);
  ++p;
  *strchr (p, '\n') = '\0';

  if (p[sizeof "State:\t" - 1] == 'X')
    return 0;

  printf ("%d left in %s\n", (int) child, p);

  return 1;
}

static void *
threadfn (void *arg)
{
  int fd = (uintptr_t) arg;

  /* Wait for the main thread to exit.  */
  sleep (1);

  exit (check_reaped (fd));

  return NULL;
}

int
main (void)
{
  pthread_t th;
  int err;
  int fd;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);

  /* SIG_IGN as we want no zombies left - kernel reaps the dead children
     without creating any zombies.  */
  signal (SIGCHLD, SIG_IGN);

  fd = create_zombie ();

  err = pthread_create (&th, NULL, &threadfn, (void *) (uintptr_t) fd);
  assert_perror (err);

  /* Now the parent thread exits.  */
  pthread_exit (0);

  /* NOTREACHED */
}
