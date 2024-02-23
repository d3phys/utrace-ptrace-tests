/* Test case for PTRACE_SINGLEBLOCK.

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

#ifndef PTRACE_SINGLEBLOCK
# if defined __x86_64__ || defined __i386__
#  define PTRACE_SINGLEBLOCK	33	/* resume execution until next branch */
# elif defined __powerpc__
#  define PTRACE_SINGLEBLOCK	0x100	/* resume execution until next branch */
# endif
#endif

#if defined __ia64__
/* Stopgap measure to be able to run "make" on an ia64 */
# undef PTRACE_SINGLEBLOCK
#endif

#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#define CHECK_VALUE	22
static volatile unsigned long int check;

#ifndef PTRACE_SINGLEBLOCK

int
main (int argc, char **argv)
{
  return 77;
}

#else  /* PTRACE_SINGLEBLOCK */

# if defined __x86_64__ || defined __i386__

static void
test (void)
{
  int reg;
asm volatile
      ("int3\n"			/* Starting SIGTRAP.  */
       "movb %2, %1\n"		/* Single-step does only this.  */
       "mov %2, %0\n"
       "or %0, %0\n"		/* Set condition codes.  */
       "jz 0f\n"		/* Branch not taken.  */
       "nop\n"
       "add %0, %1\n"		/* Block-step should get past this store.  */
       "jmp 1f\n"
       "0: hlt\n"
       "1: nop\n"		/* Single-step should execute only this...  */
       "add %0, %1\n"		/* ... and not this.  */
       : "=r" (reg), "=m" (check) : "g" (CHECK_VALUE) : "memory");
}

static void
after_initial_stop (pid_t child)
{
}

# elif defined __powerpc__

#  ifdef __powerpc64__
#   define ST	"std"
#   define SLI	"sldi"
#  else
#   define ST	"stw"
#   define SLI	"slwi"
#  endif

static void
test (void)
{
  int reg;
asm volatile
      ("trap\n"			/* Starting SIGTRAP.  */
       ST" %2, %1\n"		/* Single-step does only this.  */
       "li %0, %3\n"
       ST" %0, %1\n"		/* Block-step should get past this store.  */
       "b 1f\n"
       "0: twi 31,0,0\n"
       "1:"
       "li %0, %4\n"		/* Single-step should execute only this...  */
       ST" %0, %1\n"		/* ... and not this.  */
       : "=r" (reg), "=m" (check)
       : "i" (CHECK_VALUE), "i" (CHECK_VALUE * 2), "i" (CHECK_VALUE * 3)
       : "memory");
}

static void
after_initial_stop (pid_t child)
{
  long l, pc;

  errno = 0;
  pc = ptrace (PTRACE_PEEKUSER, child, offsetof (struct pt_regs, nip), 0l);
  assert_perror (errno);

  pc += 4;

  errno = 0;
  l = ptrace (PTRACE_POKEUSER, child, offsetof (struct pt_regs, nip), pc);
  assert_perror (errno);
  assert (l == 0);
}

# else
#  error "Port this test to this machine!"
# endif

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
  int status;
  long l;

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

      test ();

      assert (check == CHECK_VALUE * 3);

      _exit (0);

    default:
      break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  after_initial_stop (child);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, &check, 0l);
  assert_perror (errno);
  assert (l == 0);

  errno = 0;
  l = ptrace (PTRACE_SINGLEBLOCK, child, 0l, 0l);

  /* Unsupported by the kernel?  */
  if (errno == EIO)
    return 1;

  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, &check, 0l);
  assert_perror (errno);

  /* Supported by the kernel but wrmsr (MSR_IA32_DEBUGCTLMSR) is not supported
     by the hardware?  */
  if (l == CHECK_VALUE)
    return 77;

  assert (l == CHECK_VALUE * 2);

  errno = 0;
  l = ptrace (PTRACE_SINGLESTEP, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, &check, 0l);
  assert_perror (errno);
  assert (l == CHECK_VALUE * 2);

  errno = 0;
  l = ptrace (PTRACE_SINGLESTEP, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, &check, 0l);
  assert_perror (errno);
  assert (l == CHECK_VALUE * 3);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 0);

  return 0;
}

#endif	/* PTRACE_SINGLEBLOCK */
