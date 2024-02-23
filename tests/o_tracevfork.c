/* Test case whether PTRACE_O_TRACEVFORK works right.

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
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK	0x00000002
#endif
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK	0x00000004
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE	0x00000008
#endif

static void
test_vfork (void)
{
  pid_t gkid;
  if (ptrace (PTRACE_TRACEME, 0, 0, 0) == -1)
    {
      perror ("ptrace(PTRACE_TRACEME)");
      exit (2);
    }

  /* First, let parent know I'm here by sending myself a signal */
  kill (getpid (), SIGUSR1);

  /* Now vfork() and see what parent thinks of that... */
  gkid = vfork ();
  if (gkid == (pid_t) - 1)
    perror ("vfork");
  _exit (0);
}

pid_t child;
pid_t grandchild;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  if (grandchild > 0)
    kill (grandchild, SIGKILL);
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (SIGABRT, SIG_DFL);
  assert (0);
}

int
main (int ac, char *av[])
{
  int status;
  pid_t pid;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (2);

  child = fork ();
  if (child == (pid_t) - 1)
    {
      perror ("fork");
      exit (1);
    }
  if (child == 0)
    test_vfork ();		/* does not return */

  errno = 0;

  /* I am the parent, I'll be debugging the child which will
   * call vfork(). The first thing I expect to see from the
   * child is a SIGUSR1 it sends to itself.
   */
  pid = waitpid (-1, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  /* Set trace flags so we'll follow [v]fork/clone */
  ptrace (PTRACE_SETOPTIONS, child, 0,
	  PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
  assert_perror (errno);

  /* Let child continue and vfork */
  ptrace (PTRACE_CONT, child, 0, 0);
  assert_perror (errno);

  /* PTRACE_O_TRACEVFORK: child should get SIGTRAP, and grandchild SIGSTOP */
  pid = waitpid (child, &status, 0);
  /* until kernel-2.6.27-0.372 utrace-patched kernels weren't
     getting it here, they were getting it later, after child
     was unblocked by grandchild's exit: */
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  grandchild = waitpid (-1, &status, 0);
  assert (grandchild != child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Continue both */
  ptrace (PTRACE_CONT, child, 0, 0);
  assert_perror (errno);
  ptrace (PTRACE_CONT, grandchild, 0, 0);
  assert_perror (errno);

  /* See that both exited */
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 0);

  pid = waitpid (-1, &status, 0);
  assert (pid == grandchild);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 0);

  return 0;
}
