/* Test case whether waitpid() on parent returns PTRACE_EVENT_VFORK_DONE.

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

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <sched.h>

/* On RHEL-4 it is present only in <linux/ptrace.h> in
   /lib/modules/`uname -r`/{build,source}.  */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS	0x4200
#endif
#ifndef PTRACE_O_TRACEVFORKDONE
#define PTRACE_O_TRACEVFORKDONE	0x00000020
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD	0x00000001
#endif
#ifndef PTRACE_EVENT_VFORK_DONE
#define PTRACE_EVENT_VFORK_DONE	5
#endif

static void
test_vfork (void)
{
  pid_t gkid;
  long l;
  int i;

  errno = 0;
  l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  /* First, let parent know I'm here by sending myself a signal */
  errno = 0;
  i = raise (SIGUSR1);
  assert_perror (errno);
  assert (i == 0);

  /* Now vfork() and see what parent thinks of that... */
  gkid = vfork ();
  if (gkid == 0)
    _exit (43);

  /* vfork returns only after the child has begun exiting and so no longer
     shares our address space.  But it can return before the child finishes
     exit and sends us SIGCHLD.  So wait for it.  */
  assert (gkid > 0);
  l = wait (&i);
  assert (l == gkid);
  assert (WIFEXITED (i));
  assert (WEXITSTATUS (i) == 43);

  _exit (42);
}

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
test_vfork_done (int syscall)
{
  int status, exit_code = 0;
  pid_t pid;
  long l;

  errno = 0;
  child = fork ();
  assert_perror (errno);
  assert (child >= 0);
  if (child == 0) /* child */
    test_vfork (); /* never returns */

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  errno = 0;
  l = ptrace (PTRACE_SETOPTIONS, child, NULL,
	      (void *) (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORKDONE));
  assert_perror (errno);
  assert (l == 0);

  if (syscall)
    {
      do
	{
	  errno = 0;
	  l = ptrace (PTRACE_SYSCALL, child, NULL, NULL);
	  assert_perror (errno);
	  assert (l == 0);
	  pid = waitpid (child, &status, 0);
	  assert_perror (errno);
	  assert (pid == child);
	}
      while (WIFSTOPPED (status) && WSTOPSIG (status) == (SIGTRAP|0x80));
    }
  else
    {
      errno = 0;
      l = ptrace (PTRACE_CONT, child, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);
      pid = waitpid (child, &status, 0);
      assert_perror (errno);
      assert (pid == child);
    }

  if (!WIFSTOPPED (status))
    {
      /* kernel-2.6.26.6-49.fc8.x86_64 error.  */
      assert (WIFEXITED (status));
      assert (WEXITSTATUS (status) == 42);
#ifdef TALKATIVE
      fprintf (stderr, "%ssyscall tracing: child exited (missed SIGTRAP)!\n",
	       syscall ? "" : "no ");
#endif
      return 1;
    }

  if (WSTOPSIG (status) != SIGTRAP)
    {
      /* kernel-2.6.27-17.fc10.x86_64 error.  */
#ifdef TALKATIVE
      fprintf (stderr, "%schild stopped with signal %d instead of SIGTRAP!\n",
	       syscall ? "" : "no ", WSTOPSIG (status));
#endif
      exit_code = 1;
    }
  else
    {
      assert (status >> 16 == PTRACE_EVENT_VFORK_DONE);

      errno = 0;
      l = ptrace (PTRACE_CONT, child, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);

      errno = 0;
      pid = waitpid (child, &status, 0);
      assert_perror (errno);
      assert (pid == child);
      assert (WIFSTOPPED (status));
    }
  assert (WSTOPSIG (status) == SIGCHLD);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 42);

  return exit_code;
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

  return (test_vfork_done (0) | test_vfork_done (1));
}
