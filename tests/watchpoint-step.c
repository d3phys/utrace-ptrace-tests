/* Test case for a watchpoint behing hit during a singlestep.

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
#include <stdint.h>

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

static volatile long data;

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

  l = ptrace (PTRACE_POKEUSER, pid, offsetof (struct user, u_debugreg[0]), &data);
  if (errno == EINVAL)
    {
      /* FAIL */
      cleanup ();
      exit (1);
    }
  assert_perror (errno);
  assert (l == 0);
}

static void
clear_watchpoint_hit (pid_t pid)
{
  long l;

  l = ptrace (PTRACE_POKEUSER, pid, offsetof (struct user, u_debugreg[6]), 0l);
  if (errno == EINVAL)
    {
      /* FAIL */
      cleanup ();
      exit (1);
    }
  assert_perror (errno);
  assert (l == 0);
}

static int
get_watchpoint_hit (pid_t pid)
{
  unsigned long dr6;

  errno = 0;
  dr6 = ptrace (PTRACE_PEEKUSER, pid, offsetof (struct user, u_debugreg[6]), 0l);
  if (errno == EINVAL)
    {
      /* FAIL */
      cleanup ();
      exit (1);
    }
  assert_perror (errno);

  // There is some garbage in the upper bits.
  dr6 &= 0x0f;

  assert(dr6 == 0 || dr6 == 1);
  return dr6;
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

      // Without 'asm' compiler will interleave other instructions with the
      // 'data' statements and PTRACE_SINGLESTEP will not work.
      asm volatile ("" ::: "memory");
      data = 1;
      asm volatile ("" ::: "memory");
      data = 2;
      asm volatile ("" ::: "memory");

      /* NOTREACHED */
      assert (0);
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  set_watchpoint (child);
  clear_watchpoint_hit (child);
  assert(!get_watchpoint_hit (child));

  errno = 0;
  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  errno = 0;
  data = ptrace (PTRACE_PEEKDATA, child, &data, 0l);
  assert_perror (errno);

  assert(data == 1);
  assert(get_watchpoint_hit (child));
  clear_watchpoint_hit (child);

  errno = 0;
  l = ptrace (PTRACE_SINGLESTEP, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  errno = 0;
  data = ptrace (PTRACE_PEEKDATA, child, &data, 0l);
  assert_perror (errno);

  assert(data == 2);
  if (!get_watchpoint_hit (child))
    {
      /* FAIL */
      cleanup ();
      exit (1);
    }

  cleanup ();
  return 0;
}

#endif
