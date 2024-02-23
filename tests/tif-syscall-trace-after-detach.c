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
#include <error.h>
#include <time.h>

/* Let it both enter and exit the syscall.  */
#define PTRACES 2

#if PTRACES % 2
#error "Let it both enter and exit the syscall!"
#endif

#define DEFAULT_TESTTIME 10	/* seconds */

#define DELAY_USEC (1000000 / 10)

static void loop (void)
{
  /* Loop with any immediately returning syscall.  */
  for (;;)
    alarm (0);
  /* NOTREACHED */
  abort ();
}

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    {
      pid_t pid_got;

      /* Red Hat 2.6.9-57.ELsmp would sometimes lock on WAITPID otherwise.  */
      ptrace (PTRACE_CONT, child, NULL, NULL);
      ptrace (PTRACE_DETACH, child, NULL, NULL);
      kill (child, SIGKILL);

      pid_got = waitpid (child, NULL, 0);
      assert (pid_got == child);

      child = 0;
    }
}

static void
handler (int signo)
{
  cleanup ();
  signal (signo, SIG_DFL);
  raise (signo);
}

int main (void)
{
  char *testtime = getenv ("TESTTIME");
  time_t testend = time (NULL) + (testtime != NULL ? atoi (testtime)
						   : DEFAULT_TESTTIME);
  unsigned long loops;
  pid_t pid_got;
  int status;
  int ptraces;
  unsigned long bad = 0;

  void (*handler_orig) (int signo);

  setbuf (stdout, NULL);
  atexit (cleanup);
  handler_orig = signal (SIGINT, handler);
  assert (handler_orig == SIG_DFL);
  handler_orig = signal (SIGABRT, handler);
  assert (handler_orig == SIG_DFL);
  handler_orig = signal (SIGALRM, handler);
  assert (handler_orig == SIG_DFL);

  loops = 0;
  do
    {
      alarm (3);

      if (child == 0)
        {
	  child = fork ();
	  switch (child)
	    {
	      case -1:
		abort ();
	      case 0:
		loop ();
		/* NOTREACHED */
		abort ();
	      default:
		break;
	    }
        }

      errno = 0;
      ptrace (PTRACE_ATTACH, child, NULL, NULL);
      assert_perror (errno);

      pid_got = waitpid (child, &status, 0);
      assert (pid_got == child);
      assert (WIFSTOPPED (status));
      if (WSTOPSIG (status) == SIGTRAP)
	{
	  error (0, 0, "%s after %lu iterations",
		 strsignal (WSTOPSIG (status)), loops);
	  ++bad;
	  cleanup ();
	  continue;
	}
      assert (WSTOPSIG (status) == SIGSTOP);

      for (ptraces = 0; ptraces < PTRACES; ptraces++)
	{
	  errno = 0;
	  ptrace (PTRACE_SYSCALL, child, (void *) 1UL, (void *) 0UL);
	  assert_perror (errno);

	  pid_got = waitpid (child, &status, 0);
	  assert (pid_got == child);
	  assert (WIFSTOPPED (status));
	  assert (WSTOPSIG (status) == SIGTRAP);
	}

      errno = 0;
      ptrace (PTRACE_DETACH, child, (void *) 1UL, (void *) 0UL);
      assert_perror (errno);

      usleep (DELAY_USEC);
      loops++;
    }
  while (time (NULL) < testend);
  alarm (0);

  if (bad)
    {
      printf ("%lu bad in %lu iterations - may occur in 1 of 2 runs: %.2f%% * 2 = %.2f%%\n",
	      bad, loops, 100.0 * bad / loops, 2 * (100.0 * bad / loops));
#if 0
      puts ("FAIL");
#endif
      return 1;
    }
#if 0
  puts ("PASS");
#endif
  return 0;
}
