/* Test for a hang when traced vfork parent is never reported.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/*
21168: ptrace (PTRACE_TRACEME, 0, (nil), (nil)) = 0x0
21167: waitpid (21168, 0xa7f, 0x0) = 21168
21167: ptrace (PTRACE_SETOPTIONS, 21168, PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE | 0x0) = 0x0
21167: ptrace (PTRACE_CONT, 21168, (nil), (nil)) = 0x0
##### Here is the point where the ptrace-on-utrace emulation hangs.
21167: waitpid (21168, 0x2057f, 0x0) = 21168
*/

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
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK	0x00000004
#endif
#ifndef PTRACE_O_TRACEVFORKDONE
#define PTRACE_O_TRACEVFORKDONE	0x00000020
#endif
#ifndef PTRACE_EVENT_VFORK
#define PTRACE_EVENT_VFORK	2
#endif

static pid_t child;

static void
cleanup (void)
{
  /* Kill the whole process group - incl. the grandchild whose PID
     we do not know.  */
  if (child > 0)
    kill (-child, SIGKILL);
  child = 0;
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (signo, SIG_DFL);
  raise (signo);
}

static volatile int fail_expected;

static void
handler_alrm (int signo)
{
  /* Known FAIL.  */
  if (fail_expected)
    exit (1);

  handler_fail (signo);
}

int
main (int argc, char **argv)
{
  long l;
  int i, status;
  pid_t pid;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_alrm);

  alarm (1);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      /* Child */
      errno = 0;
      /* Create a new process group (cleanup uses it) */
      i = setpgrp ();
      assert_perror (errno);
      assert (i == 0);

      errno = 0;
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);

      errno = 0;
      i = raise (SIGUSR1);
      assert_perror (errno);
      assert (i == 0);

      vfork ();

      /* Correct kernels never get to this point.  FAILing ones do.  */
      raise (SIGKILL);
      assert (0);

    default:
      break;
    }

  /* Parent */
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  /* Both options are essential for the problem reproducibility.  */
  errno = 0;
  l = ptrace (PTRACE_SETOPTIONS, child, NULL,
              (void *) (PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE));
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  /* Using waitpid (-1) here can result in catching either child
     or grandchild, and we don't want that. Using waitpid (child)
     instead. */
  errno = 0;
  fail_expected = 1;
  pid = waitpid (child, &status, 0);
  /* On buggy kernel (for example 2.6.29-0.218.rc7.git2.fc11.x86_64),
     waitpid never returns (handler_alrm will detect that and exit).
     vfork'ed child is left to run freely.  IIRC parent is stuck.  */
  fail_expected = 0;
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);
  assert (status >> 16 == PTRACE_EVENT_VFORK);

  return 0;
}
