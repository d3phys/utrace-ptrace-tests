/* Test case for PTRACE_GETVRREGS regressions on powerpc.

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
#include <string.h>
#include <errno.h>
#include <endian.h>

#ifndef PTRACE_SETVRREGS

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

int
main (void)
{
  pid_t got_pid;
  int i, status;
  long l;
  unsigned int vrregs[33*4 + 1];
  int missing = 0;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
      case -1:
        assert (0);
      case 0:
	l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
	assert (l == 0);

	i = raise (SIGUSR1);
	assert (i == 0);

	/* Poke the Altivec hardware.
	   We'll get SIGILL here on a machine not Altivec support.  */
	asm volatile ("vspltisb 0,-1" : : : "v0", "memory");
	asm volatile ("mtspr 256,%0" : : "r" (0x01010101UL) : "memory");

	/* raise (SIGUSR2); would corrupt caller-saved registers.  */
	asm volatile ("trap");

	/* NOTREACHED */
	assert (0);
      default:
        break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  errno = 0;
  l = ptrace (PTRACE_GETVRREGS, child, 0l, vrregs);
  if (l == -1l)
    {
      assert (errno == EIO); /* Missing kernel/hw support should get this.  */
      return 77;
    }
  else
    {
      assert_perror (errno);
      assert (l == 0);
    }

  memset (vrregs, 0xa5, sizeof vrregs);

  l = ptrace (PTRACE_SETVRREGS, child, 0l, vrregs);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));

  /* If we got SIGILL on the vector insn above, skip it
     and check for the expected processor status.  */
  if (WSTOPSIG (status) == SIGILL)
    {
      errno = 0;
      l = ptrace (PTRACE_PEEKUSER, child, PT_MSR*sizeof(long), 0l);
      assert_perror (errno);
      assert ((l & (1UL << 25)) == 0); /* MSR_VEC not set */
      missing = 1;
      l = ptrace (PTRACE_PEEKUSER, child, PT_NIP*sizeof(long), 0l);
      assert_perror (errno);
      l += 4;
      l = ptrace (PTRACE_POKEUSER, child, PT_NIP*sizeof(long), l);
      assert_perror (errno);
      l = ptrace (PTRACE_CONT, child, 0l, 0l);
      assert_perror (errno);
      assert (l == 0);
      got_pid = waitpid (child, &status, 0);
      assert (got_pid == child);
      assert (WIFSTOPPED (status));
    }

  assert (WSTOPSIG (status) == SIGTRAP);

  memset (vrregs, 0xb6, sizeof vrregs);

  l = ptrace (PTRACE_GETVRREGS, child, 0l, vrregs);
  assert_perror (errno);
  assert (l == 0);

  status = missing ? 77 : 0;
  for (i = 0; i < sizeof vrregs / sizeof vrregs[0]; ++i)
    if (vrregs[i] != (missing ? 0xa5a5a5a5
		      : i < 4 ? -1
		      : i < 32*4 ? 0xa5a5a5a5
#if BYTE_ORDER == LITTLE_ENDIAN
		      : i == 32*4 ? 0x010001
		      : i < 33*4 ? 0
#elif BYTE_ORDER == BIG_ENDIAN
		      : i < 33*4-1 ? 0
		      : i == 33*4-1 ? 0x010001
#else
# error "!LITTLE_ENDIAN && !BIG_ENDIAN"
#endif
		      : i < sizeof vrregs / sizeof vrregs[0] - 1
		      ? 0xa5a5a5a5 : 0x01010101))
      {
	printf ("[%d] %#08x\n", i, vrregs[i]);
	status = 1;
      }

  return status;
}

#endif
