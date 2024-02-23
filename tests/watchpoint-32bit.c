/* Test case for setting a memory-write watchpoint.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* It may sometimes fail (between 1% and 100% of cases for me) even on a kernel
   generally working, expecting the same bug affecting `ppc-dabr-race' even
   while this testcase does not use threads.
   
   Testcase returns rc 2 on a missed (therefore unsupported) watchpoint.  */

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

#ifdef __powerpc__

#define	SET_WATCHPOINT set_watchpoint

#ifndef PTRACE_GET_DEBUGREG
# define PTRACE_GET_DEBUGREG	25
#endif
#ifndef PTRACE_SET_DEBUGREG
# define PTRACE_SET_DEBUGREG	26
#endif

static void
set_watchpoint (pid_t pid, volatile void *addr)
{
  long dabr;
  long l;

  errno = 0;
  l = ptrace (PTRACE_GET_DEBUGREG, pid, 0l, &dabr);
  if (l == -1l)
    {
      assert (errno == EIO); /* Missing kernel/hw support should get this.  */
      cleanup ();
      exit (77);
    }
  else
    {
      assert_perror (errno);
      assert (l == 0);
      assert (dabr == 0);
    }

  dabr = (unsigned long) addr;
  dabr |= 7;
  l = ptrace (PTRACE_SET_DEBUGREG, pid, 0l, dabr);
  assert_perror (errno);
  assert (l == 0);
}

#elif defined __x86_64__ || defined __i386__

#define	SET_WATCHPOINT set_watchpoint

static void
set_watchpoint (pid_t pid, volatile void *addr)
{
  unsigned long dr7;
  long l;

  errno = 0;
  l = ptrace (PTRACE_POKEUSER, pid,
	      offsetof (struct user, u_debugreg[0]), (unsigned long) addr);
  assert_perror (errno);
  assert (l == 0);

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
  assert_perror (errno);
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

static volatile uint8_t check_array[32];

int
main (void)
{
  pid_t got_pid;
  int i, status;
  long l;
  volatile uint8_t *check8p;
  volatile uint32_t *check32p;
  
  check8p = &check_array[15];
  check8p -= ((uintptr_t) check8p) & 0xf;
  check32p = (volatile uint32_t *) check8p;

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
      *check32p = 1;
      i = raise (SIGUSR2);
      /* NOTREACHED */
      assert (0);
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  // printf ("check32p=%p\n", check32p);
  SET_WATCHPOINT (child, check32p);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) == SIGUSR2)
    {
      /* We missed the watchpoint - unsupported by hardware?  Found on:
	 + qemu-system-x86_64 0.9.1-6.fc9.x86_64
	 + qemu-kvm kvm-65-7.fc9.x86_64 + kernel-2.6.25.9-76.fc9.x86_64.  */
      cleanup ();
      return 2;
    }
  assert (WSTOPSIG (status) == SIGTRAP);

  cleanup ();
  return 0;
}

#endif
