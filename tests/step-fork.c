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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/syscall.h>
#include <signal.h>

/* ia64 does not defined __NR_fork as it uses clone syscall.
   But disabled it as kernel-2.6.18-187.el5.ia64 crashed anyway.  */

#if !defined PTRACE_SINGLESTEP || !defined __NR_fork

int main (void) { return 77; }

#else

// The process to trace.
static pid_t child = -1;

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
  signal (SIGABRT, SIG_DFL);
  assert (0);
}

int
main (int argc, char **argv)
{
  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  child = fork ();
  assert (child >= 0);
  switch (child)
    {
    case 0:
      {
	sigset_t mask;
	sigemptyset (&mask);
	sigaddset (&mask, SIGCHLD);
	sigprocmask (SIG_BLOCK, &mask, NULL);
	ptrace (PTRACE_TRACEME);
	raise (SIGUSR1);

	/*
	 * Can't use fork() directly because on powerpc it loops inside libc under
	 * PTRACE_SINGLESTEP. See http://marc.info/?l=linux-kernel&m=125927241130695
	 */
	if (syscall (__NR_fork) == 0)
	  {
	    /* Check against: `ignoring return value of ‘read’, declared with
	       attribute warn_unused_result  */
	    if (read (-1, NULL, 0) == -1)
	      ;
	    _exit (22);
	  }
	else
	  {
	    int status;
	    pid_t grandchild = wait (&status);
	    assert (grandchild >= 0);
	    if (WIFEXITED (status))
	      assert (WEXITSTATUS (status) == 22);
	    else
	      _exit (33);
	  }
	_exit (44);
      }

    default:
      {
	// Parent, attched to child, waits for signal, steps through.

	int status;
	pid_t pid = wait (&status);
	assert (pid == child);
	assert (WIFSTOPPED (status));
	assert (WSTOPSIG (status) == SIGUSR1);

	do
	  {
	    long l = ptrace (PTRACE_SINGLESTEP, child, 0, 0);
	    assert (l == 0);
	    pid = wait (&status);
	    assert (pid == child);
	  }
	while (WIFSTOPPED (status) && WSTOPSIG (status) == SIGTRAP);
	if (WIFSTOPPED (status))
	  assert (WSTOPSIG (status) == SIGTRAP);
	else
	  {
	    assert (WIFEXITED (status));
	    switch (WEXITSTATUS (status))
	      {
	      case 33:
		return 1;
	      case 44:
		break;
	      default:
		printf ("unexpected exit status %u\n", WEXITSTATUS (status));
		return 2;
	      }
	  }

	return 0;
      }
    }
}
#endif // supported architecture
