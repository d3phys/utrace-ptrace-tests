/* Test case for return into non-executable page.  It was "fixed" by:
   Fedora kernel 88fa1f0332d188795ed73d7ac2b1564e11a0b4cd - disable 32bit nx

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
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

#if !defined __i386__ && !defined __x86_64__

int main (void)
{
  return 77;
}

#else	/* defined __i386__ || defined __x86_64__ */

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

static void *return_address;

extern char ret_instr;
static void
child_func (void)
{
#if defined __x86_64__
  asm volatile ("pushq %0; .globl ret_instr; ret_instr: ret"
		: : "r" (return_address) : "memory");
#elif defined __i386__
  asm volatile ("pushl %0; .globl ret_instr; ret_instr: ret"
		: : "r" (return_address) : "memory");
#else
# error
#endif
  assert (0);
}

int
main (void)
{
  pid_t got_pid;
  int status;
  long l;
  void *page, *pc;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  page = mmap (NULL, 0x1000, PROT_READ | PROT_WRITE,
	       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert_perror (errno);
  assert (page != MAP_FAILED);
  assert (page != NULL);

#if defined __x86_64__
  memset (page, 0xcc, 0x1000);
#elif defined __i386__
  memset (page, 0xcc, 0x1000);
#else
# error
#endif

  return_address = page + 0x1000 / 2;

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);

    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      child_func ();
      _exit (42);

    default:
      break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));

  /* We may get SIGSEGV due to missing PROT_EXEC of the page.  */
  assert (WSTOPSIG (status) == SIGTRAP || WSTOPSIG (status) == SIGSEGV);

  errno = 0;
  l = ptrace (PTRACE_PEEKUSER, child,
#if defined __x86_64__
	       (void *) offsetof (struct user_regs_struct, rip),
#elif defined __i386__
	       (void *) offsetof (struct user_regs_struct, eip),
#else
# error
#endif
	       NULL);
  assert_perror (errno);
  pc = (void *) l;

  /* + 1 is there as x86* stops after the 'int3' instruction.  */
  if (WSTOPSIG (status) == SIGTRAP && pc == return_address + 1)
    {
      /* PASS */
      return 0;
    }

  /* We may get SIGSEGV due to missing PROT_EXEC of the page.  */
  if (WSTOPSIG (status) == SIGSEGV && pc == return_address)
    {
      /* PASS */
      return 0;
    }

  assert (pc == &ret_instr);

  /* FAIL */
  return 1;
}

#endif	/* defined __i386__ || defined __x86_64__ */
