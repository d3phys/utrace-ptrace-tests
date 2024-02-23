/* Test case for PTRACE_SINGLESTEP to step to the first signal handler instr.

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
#include <asm/unistd.h>

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <string.h>
#include <stddef.h>

#if defined __x86_64__
#define REGISTER_IP regs.rip
#elif defined __i386__
#define REGISTER_IP regs.eip
#elif defined __powerpc__
#define REGISTER_IP regs.nip
/* __s390x__ defines both the symbols.  */
#elif defined __s390__
#define REGISTER_IP regs.psw.addr
#elif defined __s390x__
#error "__s390__ should be defined"
#endif

/* __ia64__ is currently not being tested as it steps into `__kernel_sigtramp'
   (and correctly to its first instruction).  Otherwise handler_alrm_get() would
   also have to follow the function descriptor like __powerpc64__.  Tricky may
   be to get the runtime address of `__kernel_sigtramp' as it comes from the
   kernel vDSO.
     elif defined __ia64__
     include <asm/ptrace_offsets.h>
     define REGISTER_IP regs[PT_CR_IIP / 8]  */

#ifndef REGISTER_IP

int
main (void)
{
  return 77;
}

#else	/* REGISTER_IP */

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
  signal (SIGABRT, SIG_DFL);
  abort ();
}

static void
handler_alrm (int signo)
{
  assert (0);
}

static void *
ip_get (void)
{
  long l;
  errno = 0;
  l = ptrace (PTRACE_PEEKUSER, child,
              (void *) (unsigned long) offsetof (struct user, REGISTER_IP),
              NULL);
  assert_perror (errno);
/* __s390x__ defines both the symbols.  */
#if defined __s390__ && !defined __s390x__
  l = l & 0x7fffffff;
#endif
  return (void *) l;
}

static void *
handler_alrm_get (void)
{
#if defined __powerpc64__
  /* ppc64 `handler_alrm' resolves to the function descriptor.  */
  union
    {
      void (*f) (int signo);
      struct
	{
	  void *entry;
	  void *toc;
	}
      *p;
    }
  const func_u = { handler_alrm };

  return func_u.p->entry;
/* __s390x__ defines both the symbols.  */
#elif defined __s390__ && !defined __s390x__
  /* s390 bit 31 is zero here but I am not sure if it cannot be arbitrary.  */
  return (void *) (0x7fffffff & (unsigned long) handler_alrm);
#else
  return handler_alrm;
#endif
}

int
main (void)
{
  long l;
  int status;
  pid_t pid;
  sighandler_t handler_orig;
  void *ip, *ip_expected;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);

    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      handler_orig = signal (SIGALRM, handler_alrm);
      assert (handler_orig == handler_fail);

      // Prevent rt_sigprocmask() call called by glibc after raise().
      syscall (__NR_tkill, getpid (), SIGSTOP);
      assert (0);

    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* We should be in raise () but local resolving of the `raise' symbol points
     to PLT.  This check would be too fragile due to many other issues.  */

  l = ptrace (PTRACE_SINGLESTEP, child, NULL, (void *) (unsigned long) SIGALRM);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  ip = ip_get ();
  ip_expected = handler_alrm_get ();

  if (ip == ip_expected)
    return 0;

  /* Known FAIL is now only on kernel-2.6.9 (RHEL-4) s390*.  */
#ifdef __s390__
  /* Expecting the HANDLER_ALRM's first instruction: stm %r11,%r15,44(%r15)  */
  if (ip == ip_expected + 4)
    return 1;
#endif
#ifdef __s390x__
  /* Expecting the HANDLER_ALRM's first instruction: stmg %r11,%r15,88(%r15)  */
  if (ip == ip_expected + 6)
    return 1;
#endif

  fprintf (stderr, "PC %p != expected %p\n", ip, ip_expected);
  assert (0);
  return 1;
}

#endif	/* REGISTER_IP */
