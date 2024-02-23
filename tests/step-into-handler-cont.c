/* See https://bugzilla.kernel.org/show_bug.cgi?id=16061 and the comments
   below.

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

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

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

static void
handler (int n)
{
}

static int
child_func (void)
{
  long l;
  int i;
  sighandler_t orig;

  orig = signal (SIGINT, handler);
  assert_perror (errno);
  assert (orig == SIG_DFL);

  l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  i = raise (SIGINT);
  assert_perror (errno);
  assert (i == 0);

  return 0x23;
}

int
main (void)
{
  pid_t pid;
  int status, i;
  long l;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  i = alarm (10);
  assert (i == 0);

  child = fork ();
  assert_perror (errno);
  assert (child != -1);
  if (!child)
    return child_func ();

  pid = wait (&status);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGINT);

  /* Cancel the pending SIGINT and turn TIF_SINGLESTEP/etc on.  */
  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  pid = wait (&status);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  /* Turn SIGTRAP into SIGINT, the tracee should step into handler.
     handle_signal() in kernel clears X86_EFLAGS_TF/TIF_FORCED_TF but doesn't
     clear TIF_SINGLESTEP.  */
  l = ptrace (PTRACE_SINGLESTEP, child, NULL, (void *) SIGINT);
  assert_perror (errno);
  assert (l == 0);

  pid = wait (&status);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  /* Enable_single_step() sets X86_EFLAGS_TF again, but without TIF_FORCED_TF
     because TIF_SINGLESTEP is still set.  */
  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  pid = wait (&status);
  assert_perror (errno);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  /* user_disable_single_step() doesn't clear X86_EFLAGS_TF without
     "tf-was-set-by-us" TIF_FORCED_TF flag, and the tracee gets another trap.
     */
  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  pid = wait (&status);
  assert_perror (errno);
  assert (pid == child);

  /* Fixed?  */
  if (WIFEXITED (status) && WEXITSTATUS (status) == 0x23)
    return 0;

  /* No, it must be another trap...  */
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  return 1;
}
