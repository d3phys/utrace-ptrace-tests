/* This software is provided 'as-is', without any express or implied
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
#include <assert.h>
#include <sys/wait.h>
#include <sys/procfs.h>
#include <stddef.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#if !(defined __x86_64__ || defined __i386__)

int
main (void)
{
  return 77;
}

#else

#ifdef __x86_64__
# define FLOAT80_SIZE 16
#elif __i386__
# define FLOAT80_SIZE 10
#else
# error
#endif

/* Value 8 has false PASS while value 10 already makes it reproducible.  */
#define LOOPS 12

/* If it does not FAIL in the first cycle it will never FAIL.  Reproducibility
   is about 50%.  With running background processes the reproducibility is 0%.
   */
#define DEFAULT_TESTTIME 0	/* seconds */

#if LOOPS % 1 != 0
# error "LOOPS must be even"
#endif

static int verbose;
static const char *pname;

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
setaffinity (int cpu)
{
  cpu_set_t set;

  CPU_ZERO (&set);
  CPU_SET (cpu, &set);

  if (sched_setaffinity (getpid (), sizeof (set), &set) == 0)
    return;

  /* This system does not have enough CPUs.  */
  if (errno == ESRCH)
    {
      if (verbose)
	fprintf (stderr, "%s: Skipping test, not enough CPUs.\n", pname);
      exit (77);
    }

  if (errno == EPERM)
    {
      if (verbose)
	fprintf (stderr, "%s: Skipping test, not root for sched_setaffinity.\n",
		 pname);
      exit (77);
    }

  assert_perror (errno);
  assert (0);
}

static void
verifyaffinity (int cpu)
{
  cpu_set_t set;
  int err;

  err = sched_getaffinity (getpid (), sizeof (set), &set);
  assert_perror (errno);
  assert (err == 0);
  if (!CPU_ISSET (cpu, &set))
    {
//      if (verbose)
	fprintf (stderr,
		 "%s: Skipping test, CPU #%d not available in sched_getaffinity.\n",
		 pname, cpu);
      exit (77);
    }
}

int
main (int argc, char **argv)
{
  char *testtime = getenv ("TESTTIME");
  time_t testend = time (NULL) + (testtime != NULL ? atoi (testtime)
						   : DEFAULT_TESTTIME);
  union {
    elf_fpregset_t fpregs;
    struct {
      char pad[offsetof(elf_fpregset_t, st_space)];
      __float80 float80[4];
    } __attribute__((packed)) s;
  } fpregs_u;
#define FLOAT80(n) (fpregs_u.s.float80[(n)])
  int i, status, loop;
  long l;
  pid_t pid;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);

  pname = argv[0];
  if (argc == 2 && strcmp (argv[1], "-v") == 0)
    verbose = 1;
  else
    assert (argc == 1);

  verifyaffinity (0);
  verifyaffinity (1);

  do
    {
      alarm (1);

      child = fork();
      assert_perror (errno);
      assert (child != -1);

      if (child == 0)
	{
	  __float80 two = 2.0;

	  setaffinity (0);

	  l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
	  assert_perror (errno);
	  assert (l == 0);

	  /* Stack: 0 1 2 <--top  */
	  __asm__ __volatile__ ("fldz; fld1; fldt %0;" : : "m" (two));

	  for (loop = 0; loop < LOOPS; loop++)
	    {
	      i = raise (SIGSTOP);
	      assert_perror (errno);
	      assert (i == 0);

	      /* Use FPU; do nothing.  */
	      __asm__ __volatile__("fadd %st(2), %st;");
	    }

	  __asm__ __volatile__ ("fstpt %0;" : "=m" (two));
	  /* Make sure child also sees 42 on stack top.  */
	  assert (two == 42.0);

	  return 23;
	}

      setaffinity (1);

      for (loop = 0; loop < LOOPS; loop++)
	{
	  pid = waitpid (child, &status, 0);
	  assert_perror (errno);
	  assert (pid == child);
	  assert (WIFSTOPPED (status));

	  l = ptrace (PTRACE_GETFPREGS, child, NULL, &fpregs_u.fpregs);
	  assert_perror (errno);
	  assert (l == 0);

	  assert (FLOAT80 (1) == 1.0 && FLOAT80 (2) == 0.0);

	  if (loop < LOOPS / 2)
	    {}
	  else if (loop == LOOPS / 2)
	    {
	      /* Replace 2 on stack top with 42.  */
	      assert (FLOAT80 (0) == 2.0);
	      FLOAT80 (0) = 42.0;

	      l = ptrace (PTRACE_SETFPREGS, child, NULL, &fpregs_u.fpregs);
	      assert_perror (errno);
	      assert (l == 0);
	    }
	  else /* loop > LOOPS / 2 */
	    {
	      /* Parent should now be seeing 42.  */
	      if (FLOAT80 (0) != 42.0)
		{
		  if (verbose)
		    fprintf (stderr, "%s: FAIL\n", pname);
		  return 1;
		}
	    }

	  l = ptrace (PTRACE_CONT, child, NULL, NULL);
	  assert_perror (errno);
	  assert (l == 0);
	}

      pid = waitpid (child, &status, 0);
      assert_perror (errno);
      assert (pid == child);
      assert (WIFEXITED (status));
      assert (WEXITSTATUS (status) == 23);
    }
  while (time (NULL) < testend);
  alarm (0);

  if (verbose)
    fprintf (stderr, "%s: PASS\n", pname);
  return 0;
}

#endif
