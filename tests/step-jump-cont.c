/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Test the TF (Trap Flag) bit handling does not hurt any real world debuggers
   (tested only with GDB so far) using PTRACE_SINGLESTEP and PTRACE_CONT.
   We do not care of the behavior not used by the debuggers, such as the TF
   (Trap Flag) bit modification by PTRACE_SETREGS/PTRACE_POKEUSER.  */

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
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>

#if !defined __i386__ && !defined __x86_64__ && !defined __powerpc__

int
main (void)
{
  return 77;
}

#else	/* supported arch */

#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/user.h>

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

/* PTRACE_GETREGS / PTRACE_SETREGS are not available on ppc.
   On the other hand the PTRACE_PEEKUSER / PTRACE_POKEUSER may crash on utrace:
     https://bugzilla.redhat.com/show_bug.cgi?id=431314  */

#ifdef PTRACE_GETREGS

#define REGS_TYPE(var) struct user var;
#define REGS_ACCESS(var, reg) (var).regs.reg

static void
peekuser (struct user *user)
{
  long l;

# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, child, user, NULL);
# else
  l = ptrace (PTRACE_GETREGS, child, NULL, user);
#endif
  assert (l == 0);
}

static void
pokeuser (const struct user *user)
{
  long l;

# ifdef __sparc__
  l = ptrace (PTRACE_SETREGS, child, user, NULL);
# else
  l = ptrace (PTRACE_SETREGS, child, NULL, user);
#endif
  assert (l == 0);
}

#else	/* !PTRACE_GETREGS */

#define REGS_TYPE(var) struct pt_regs var;
#define REGS_ACCESS(var, reg) (var).reg

static void
peekuser (struct pt_regs *pt_regs)
{
  long *longs = (long *) pt_regs;
  unsigned long ul;

  assert (sizeof *pt_regs % sizeof *longs == 0);
  for (ul = 0; ul < sizeof *pt_regs; ul += sizeof (long))
    {
      errno = 0;
      longs[ul / sizeof (long)] = ptrace (PTRACE_PEEKUSER, child, (void *) ul,
					  NULL);
      assert_perror (errno);
    }
}

static void
pokeuser (const struct pt_regs *pt_regs)
{
  const long *longs = (const long *) pt_regs;
  unsigned long ul;

  assert (sizeof *pt_regs % sizeof *longs == 0);
  for (ul = 0; ul < sizeof *pt_regs; ul += sizeof (long))
    {
      long l;

      l = ptrace (PTRACE_POKEUSER, child, (void *) ul,
		  (void *) longs[ul / sizeof (long)]);
      assert (l == 0);
    }
}

#endif	/* !PTRACE_GETREGS */

static void
raise_sigusr2 (void)
{
  int i;

  i = raise (SIGUSR2);
  assert (i == 0);
  assert (0);
}

int main (void)
{
  long l;
  int status;
  pid_t pid;
  REGS_TYPE (regs);

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);
      raise (SIGUSR1);
      /* The program continues at RAISE_SIGUSR2.  */
      assert (0);
    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  /* PTRACE_SINGLESTEP is here to make the singlestepping bit possibly set.  */

  errno = 0;
  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  peekuser (&regs);

  /* We must set PC to our new function as the current PC stays in the glibc
     function RAISE no matter which part of the code called it - we would have
     to save and restore the whole stack for a proper restart of the code.  */

#if defined __i386__
  REGS_ACCESS (regs, eip) = (unsigned long) raise_sigusr2;
#elif defined __x86_64__
  REGS_ACCESS (regs, rip) = (unsigned long) raise_sigusr2;
#elif defined __powerpc64__
  {
    /* ppc64 `raise_sigusr2' resolves to the function descriptor.  */
    union
      {
	void (*f) (void);
	struct
	  {
	    void *entry;
	    void *toc;
	  }
	*p;
      }
    const func_u = { raise_sigusr2 };

    REGS_ACCESS (regs, nip) = (unsigned long) func_u.p->entry;
    REGS_ACCESS (regs, gpr[2]) = (unsigned long) func_u.p->toc;
  }
#elif defined __powerpc__
  REGS_ACCESS (regs, nip) = (unsigned long) raise_sigusr2;
#else
# error "Check outer #ifdef"
#endif

  /* The PC change here is not important, only the TF bit change matters.  */

  pokeuser (&regs);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));

  /* Surprisingly it does not fail for the first call.  */

  if (WSTOPSIG (status) == SIGUSR2)
    {
      /* Surprisingly vanilla 2.6.24-0.133.rc6.git8.i686 does not fail in this
	 first call but fails in the second one below.  Anyway at this point it
	 is still the fully correct behavior.  */
    }
  else if (WSTOPSIG (status) == SIGTRAP)
    return 1;
  else
    assert (0);

  /* Rerun from the original PC point again.  */

  pokeuser (&regs);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  if (WSTOPSIG (status) == SIGUSR2)
    return 0;
  else if (WSTOPSIG (status) == SIGTRAP)
    return 1;
  else
    assert (0);
  /* NOTREACHED */
}

#endif	/* supported arch */
