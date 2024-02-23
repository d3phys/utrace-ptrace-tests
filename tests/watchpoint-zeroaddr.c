/* Test case for setting watchpoint by writing into the control register
   first.

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

#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#if !(defined __x86_64__ || defined __i386__)

int
main (void)
{
  return 77;
}

#else

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
set_watchpoint (pid_t pid)
{
  unsigned long dr7;
  long l;

  /* DR7 must be written before DR0.  */

  dr7 = (DR_RW_WRITE << DR_CONTROL_SHIFT);

#ifdef DR_LEN_8
  /*
   * For a 32-bit build, DR_LEN_8 might be defined by the header.
   * On a 64-bit kernel, we might even be able to use it.
   * But we can't tell, and we don't really need it, so just use DR_LEN_4.
   */
  if (sizeof (long) > 4)
    dr7 |= (DR_LEN_8 << DR_CONTROL_SHIFT);
  else
#endif
    dr7 |= (DR_LEN_4 << DR_CONTROL_SHIFT);
  dr7 |= (1UL << DR_LOCAL_ENABLE_SHIFT);
  dr7 |= (1UL << DR_GLOBAL_ENABLE_SHIFT);

  l = ptrace (PTRACE_POKEUSER, pid, offsetof (struct user, u_debugreg[7]), dr7);
  if (errno == EINVAL)
    {
      /* FAIL */
      cleanup ();
      exit (1);
    }
  assert_perror (errno);
  assert (l == 0);

  /* Normally, we'd set u_debugreg[0] := brk_address here, but for this test
   * it's not essential what the address is - we test whether u_debugreg[7]
   * can be set above.
   */
}

int
main (void)
{
  pid_t got_pid;
  int status;
  long l;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  assert (child >= 0);
  if (child == 0)
    {
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);
      raise (SIGUSR1);
      /* NOTREACHED */
      assert (0);
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  /* Still fails on i686, linux-3.1.6: */
  set_watchpoint (child);

  cleanup ();
  return 0;
}

#endif
