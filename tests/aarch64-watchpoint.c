/* Test case for setting a memory-write unaligned watchpoint on aarch64.

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
#include <sys/uio.h>
#include <elf.h>
#include <error.h>

static __attribute__((unused)) pid_t child;

static __attribute__((unused)) void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
}

static __attribute__((unused)) void
handler_fail (int signo)
{
  cleanup ();
  signal (signo, SIG_DFL);
  raise (signo);
}

#ifdef __aarch64__

#define	SET_WATCHPOINT set_watchpoint

/* Macros to extract fields from the hardware debug information word.  */
#define AARCH64_DEBUG_NUM_SLOTS(x) ((x) & 0xff)
#define AARCH64_DEBUG_ARCH(x) (((x) >> 8) & 0xff)
/* Macro for the expected version of the ARMv8-A debug architecture.  */
#define AARCH64_DEBUG_ARCH_V8 0x6
#define DR_CONTROL_ENABLED(ctrl)        (((ctrl) & 0x1) == 1)
#define DR_CONTROL_LENGTH(ctrl)         (((ctrl) >> 5) & 0xff)

static void
set_watchpoint (pid_t pid, volatile void *addr, unsigned len_mask)
{
  struct user_hwdebug_state dreg_state;
  struct iovec iov;
  long l;

  assert (len_mask >= 0x01);
  assert (len_mask <= 0xff);

  iov.iov_base = &dreg_state;
  iov.iov_len = sizeof (dreg_state);
  errno = 0;
  l = ptrace (PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov);
  assert (l == 0);
  assert (AARCH64_DEBUG_ARCH (dreg_state.dbg_info) == AARCH64_DEBUG_ARCH_V8);
  assert (AARCH64_DEBUG_NUM_SLOTS (dreg_state.dbg_info) >= 1);

  assert (!DR_CONTROL_ENABLED (dreg_state.dbg_regs[0].ctrl));
  dreg_state.dbg_regs[0].ctrl |= 1;
  assert ( DR_CONTROL_ENABLED (dreg_state.dbg_regs[0].ctrl));

  assert (DR_CONTROL_LENGTH (dreg_state.dbg_regs[0].ctrl) == 0);
  dreg_state.dbg_regs[0].ctrl |= len_mask << 5;
  assert (DR_CONTROL_LENGTH (dreg_state.dbg_regs[0].ctrl) == len_mask);

  dreg_state.dbg_regs[0].ctrl |= 2 << 3; // write
  dreg_state.dbg_regs[0].ctrl |= 2 << 1; // GDB: ???: enabled at el0
  //printf("ctrl=0x%x\n",dreg_state.dbg_regs[0].ctrl);

  dreg_state.dbg_regs[0].addr = (uintptr_t) addr;

  iov.iov_base = &dreg_state;
  iov.iov_len = (offsetof (struct user_hwdebug_state, dbg_regs)
		 + sizeof (dreg_state.dbg_regs[0]));
  errno = 0;
  l = ptrace (PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov);
  if (errno != 0)
    error (1, errno, "PTRACE_SETREGSET: NT_ARM_HW_WATCH");
  assert (l == 0);
}

#endif

#ifndef SET_WATCHPOINT

int
main (void)
{
  return 77;
}

#else

static volatile long long check;

int
main (void)
{
  pid_t got_pid;
  int i, status;
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
      i = raise (SIGUSR1);
      assert (i == 0);
      check = -1;
      i = raise (SIGUSR2);
      /* NOTREACHED */
      assert (0);
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  // PASS:
  //SET_WATCHPOINT (child, &check, 0xff);
  // FAIL:
  SET_WATCHPOINT (child, &check, 0x02);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) == SIGUSR2)
    {
      /* We missed the watchpoint - unsupported by hardware?  */
      cleanup ();
      return 2;
    }
  assert (WSTOPSIG (status) == SIGTRAP);

  cleanup ();
  return 0;
}

#endif
