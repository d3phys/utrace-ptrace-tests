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

#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <error.h>
#include <time.h>
#include <sys/utsname.h>

#include <asm/unistd.h>
#include <unistd.h>
#define tkill(tid, sig) syscall (__NR_tkill, (tid), (sig))

/* Failure occurs either immediately or in about 20 runs.
   But sometimes not.  */
#define DEFAULT_TESTTIME 10	/* seconds */

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

int main (void)
{
  char *testtime = getenv ("TESTTIME");
  time_t testend = time (NULL) + (testtime != NULL ? atoi (testtime)
						   : DEFAULT_TESTTIME);
  unsigned long loops;
  pid_t got_pid;
  int status;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  /* Be careful with SIGALRM / ALARM due to false positives under load.  */

  kernel (3);

  unsigned long bad = 0;
  loops = 0;
  do
    {
      alarm (20);

      child = fork ();
      switch (child)
	{
	case -1:
	  abort ();
	case 0:
	  raise (SIGSTOP);
	  for (;;)
	    pause ();
	  /* NOTREACHED */
	default:
	  break;
	}

      /* We must never WAITPID/WAITID on the child for this testcase.  */

      /* We need to wait till CHILD becomes stopped.  Any DELAY may be
       * race-prone, check its `/proc/${child}/status'.  */
      for (;;)
	{
	  char buf[0x1000];
	  ssize_t got;
	  int fd, i;

	  snprintf (buf, sizeof buf, "/proc/%d/status", (int) child);
	  fd = open (buf, O_RDONLY);
	  assert (fd != -1);
	  got = read (fd, buf, sizeof buf);
	  assert (got > 0);
	  assert (got < sizeof buf);
	  buf[got] = 0;
	  i = close (fd);
	  assert (i == 0);
	  if (strstr (buf, "\nState:\tT (stopped)\n"))
	    break;
	}

      /* Here is a point where we - as a debugger - start to attach.  */
      errno = 0;
      ptrace (PTRACE_ATTACH, child, NULL, NULL);
      assert_perror (errno);

      /* Any DELAY makes no difference here.  */

      /* `PTRACE_CONT, SIGSTOP' does not work in 100% cases as sometimes SIGSTOP
	 gets remembered by kernel during the first PTRACE_CONT later and we get
	 spurious SIGSTOP event.  Expecting the signal may get delivered to
	 a different task of the thread group.
	 `tkill (SIGSTOP)' has no effect in this moment (it is already stopped).  */
      errno = 0;
      tkill (child, SIGCONT);
      assert_perror (errno);

      /* Here must not be any DELAY() to properly test utrace.  The bug was
	 that WAITPID reported a previous job-control-stop condition even
	 though SIGCONT has cleared the TASK_STOPPED state.  */

      got_pid = waitpid (child, &status, 0);
      assert (got_pid == child);
      assert (WIFSTOPPED (status));
      /* SIGSTOP is expected only since kernel-3.x.  See attach-sigcont-wait.c
         for kernel-2.x.  */
      if (WSTOPSIG (status) != SIGSTOP)
	{
#if 0
	  error (0, 0, "%s after %lu iterations",
		 strsignal (WSTOPSIG (status)), loops);
#endif
	  ++bad;
	}
      else
	{
	  /* This point is no longer a part of the test, if we want to validate
	     ptrace(2) below here also must be no DELAY().  */

	  /* At this moment we should be already able to ptrace(2) the inferior.
	     After the fix of Bug 248532 Comment 5 above there should be no problem
	     here.  */
	  errno = 0;
	  ptrace (PTRACE_PEEKUSER, child, (void *) 0UL, NULL);
	  assert_perror (errno);
	}

      /* Cleanup.  */
      errno = 0;
      kill (child, SIGKILL);
      assert_perror (errno);

      got_pid = waitpid (child, &status, 0);
      assert (got_pid == child);

      loops++;
    }
  while (time (NULL) < testend);
  alarm (0);

  if (bad)
    {
      printf ("%lu bad in %lu iterations: %.2f%%\n",
	      bad, loops, 100.0 * bad / loops);
      return 1;
    }

  return 0;
}
