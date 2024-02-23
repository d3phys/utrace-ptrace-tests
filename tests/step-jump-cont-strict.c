/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* A variant of `step-jump-cont.c' where all the TF (Trap Flag) behavior should
   match the ideal case.  */

/* TODO: ia64 (cr_ipsc |= ss ?)  */
/* TODO: s390 (per_info.single_step = 1)  */

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
#include <error.h>

#if defined __x86_64__
# define PT_REGS_IP_ULONG(pt_regs) (pt_regs).rip
# define PT_REGS_FLAGS(pt_regs) (pt_regs).eflags
# define PT_REGS_FLAGS_TRACE 0x100	/* EF_TF */
#ifndef PTRACE_SINGLEBLOCK
# define PTRACE_SINGLEBLOCK	33	/* resume execution until next branch */
#endif
#elif defined __i386__
# define PT_REGS_IP_ULONG(pt_regs) (pt_regs).eip
# define PT_REGS_FLAGS(pt_regs) (pt_regs).eflags
# define PT_REGS_FLAGS_TRACE 0x100	/* TF_MASK */
#ifndef PTRACE_SINGLEBLOCK
# define PTRACE_SINGLEBLOCK	33	/* resume execution until next branch */
#endif
#elif defined __powerpc__
/* FIXME: # define PT_REGS_IP_ULONG(pt_regs) (pt_regs).nip */
# define PT_REGS_FLAGS(pt_regs) (pt_regs).msr
# define PT_REGS_FLAGS_TRACE (1 << 10)	/* MSR_SE */
# define user_regs_struct pt_regs
/* __s390x__ defines both the symbols.  */
#elif defined __s390__
/* FIXME: # define PT_REGS_IP .psw.addr */
#elif defined __s390x__
# error "__s390__ should be defined"
#elif defined __ia64__
# include <asm/ptrace_offsets.h>
/* FIXME: # define PT_REGS_IP [PT_CR_IIP / 8] */
#endif

#ifndef PT_REGS_IP_ULONG

int
main (void)
{
  return 77;
}

#else	/* PT_REGS_IP_ULONG */

/* Sanity check the type - do not just cast it.  */
#define PT_REGS_IP_GET(pt_regs)					\
  ({								\
    unsigned long _ulong = PT_REGS_IP_ULONG (pt_regs);		\
    (void *) _ulong;						\
  })
#define PT_REGS_IP_SET(pt_regs, ip_voidp)			\
  ({								\
    void *_voidp = (ip_voidp);					\
    PT_REGS_IP_ULONG (pt_regs) = (unsigned long) _voidp;	\
  })

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
     https://bugzilla.redhat.com/show_bug.cgi?id=431314
   s390* defines PTRACE_GETREGS but it EIOs.  */

#ifdef PTRACE_PEEKUSR_AREA

static void
peekuser (struct user *user)
{
  ptrace_area parea;
  long l;

  parea.process_addr = (unsigned long) user;
  parea.kernel_addr = 0;
  parea.len = sizeof (*user);
  errno = 0;
  l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
  assert_perror (errno);
  assert (l == 0);
}

static void
pokeuser (const struct user *user)
{
  ptrace_area parea;
  long l;

  parea.process_addr = (unsigned long) user;
  parea.kernel_addr = 0;
  parea.len = sizeof (*user);
  errno = 0;
  l = ptrace (PTRACE_POKEUSR_AREA, child, &parea, NULL);
  /* s390x kernel does not support the s390 debuggers.  */
# if defined __s390__ && !defined __s390x__
  if (l == -1 && errno == EINVAL)
    exit (77);
# endif
  assert_perror (errno);
  assert (l == 0);
}

#elif defined PTRACE_GETREGS

static void
peekuser (struct user_regs_struct *pt_regs)
{
  long l;

  errno = 0;
# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, child, pt_regs, NULL);
# else
  l = ptrace (PTRACE_GETREGS, child, NULL, pt_regs);
# endif
  assert_perror (errno);
  assert (l == 0);
}

static void
pokeuser (const struct user_regs_struct *pt_regs)
{
  long l;

  errno = 0;
# ifdef __sparc__
  l = ptrace (PTRACE_SETREGS, child, pt_regs, NULL);
# else
  l = ptrace (PTRACE_SETREGS, child, NULL, pt_regs);
# endif
  assert_perror (errno);
  assert (l == 0);
}

#elif defined PTRACE_PEEKUSER

static void
peekuser (struct user_regs_struct *pt_regs)
{
  long *longs = (long *) pt_regs;
  unsigned long ul;

  assert (sizeof (*pt_regs) % sizeof (*longs) == 0);
  for (ul = 0; ul < sizeof (*pt_regs); ul += sizeof (long))
    {
      errno = 0;
      longs[ul / sizeof (long)] = ptrace (PTRACE_PEEKUSER, child, (void *) ul,
					  NULL);
      assert_perror (errno);
    }
}

static void
pokeuser (const struct user_regs_struct *pt_regs)
{
  const long *longs = (const long *) pt_regs;
  unsigned long ul;

  assert (sizeof (*pt_regs) % sizeof (*longs) == 0);
  for (ul = 0; ul < sizeof (*pt_regs); ul += sizeof (long))
    {
      long l;

      errno = 0;
      l = ptrace (PTRACE_POKEUSER, child, (void *) ul,
		  (void *) longs[ul / sizeof (long)]);
      assert_perror (errno);
      assert (l == 0);
    }
}

#else
# error "No user access method available"
#endif

const char *progname;

static void
check_stopped (int status, int signo, const char *signo_name, const char *where,
	       const char *file, unsigned line, const char *function);
#define CHECK_STOPPED(status, signo, where) check_stopped (status, signo,      \
							   #signo , where,     \
							   __FILE__, __LINE__, \
							   __PRETTY_FUNCTION__)
static void
check_ip (void *found, void *expected, const char *where, int instr,
	  const char *file, unsigned line, const char *function)
#define CHECK_IP(found, expected, where, instr) check_ip (found, expected,    \
							  where, instr,	      \
							  __FILE__, __LINE__, \
							  __PRETTY_FUNCTION__)
{
  if (found != expected)
    {
      fprintf (stderr, "%s: %s:%u: %s (%s, instruction %d): "
                       "IP %p expected: found %p\n",
	       progname, file, line, function, where, instr, expected, found);
      exit (1);
    }
}

static void
check_flags (struct user_regs_struct *regs, int expected, const char *where,
	     int instr, const char *file, unsigned line, const char *function)
#define CHECK_FLAGS(regsp, expected, where, instr) check_flags (regsp,	      \
								expected,     \
								where, instr, \
								__FILE__,     \
								__LINE__,     \
							   __PRETTY_FUNCTION__)
{
  int flag_found = ((PT_REGS_FLAGS (*regs) & PT_REGS_FLAGS_TRACE) != 0);
  int flag_expected = (expected != 0);

  if (flag_found != flag_expected)
    {
      fprintf (stderr, "%s: %s:%u: %s (%s, instruction %d): "
		       "Trap flag expected %d: found %d\n",
	       progname, file, line, function, where, instr, flag_expected,
	       flag_found);
      exit (1);
    }
}

#ifdef __i386__
# define X86_PUSH_AX "pushl %eax"
# define X86_POP_AX "popl %eax"
#endif
#ifdef __x86_64__
# define X86_PUSH_AX "pushq %rax"
# define X86_POP_AX "popq %rax"
#endif

#if defined X86_PUSH_AX
asm (
"		.text			\n"
/* Test we see the trap flag cleared.  But it is a known failure workarounded
   in the code below KFAIL(*1).  */
"instr0:	pushf			\n"
"instr1:	" X86_POP_AX "		\n"
"instr2:	testl	$0x100, %eax	\n"
"instr3:	jnz	instr3		\n"
/* Set the trap flag by hand and test both us and the debugger see it.  */
"instr4:	orl	$0x100, %eax	\n"
"instr5:	" X86_PUSH_AX "		\n"
"instr6:	popf			\n"
/* At this point the trap flag got turned on (*2).  */
"instr7:	pushf			\n"
/* But only at this point it the trap gets generated after PTRACE_CONT (*3).
   It does not stop here on PTRACE_SINGLEBLOCK as this stepping mode has TF
   already set and only WRMSR setting turns PTRACE_SINGLESTEP into
   PTRACE_SINGLEBLOCK (*4).  */
"instr8:	" X86_POP_AX "		\n"
"instr9:	testl	$0x100, %eax	\n"
"instr10:	jz	instr10		\n"
"instr11:	nop			\n"
/* Cause a trap if we get here - not for PTRACE_SINGLESTEP but more for
   PTRACE_CONT/PTRACE_SINGLEBLOCK.  */
"instr12:	hlt			\n"
);
extern void instr0 (void);
extern void instr1 (void);
extern void instr2 (void);
extern void instr3 (void);
extern void instr4 (void);
extern void instr5 (void);
extern void instr6 (void);
extern void instr7 (void);
extern void instr8 (void);
extern void instr9 (void);
extern void instr10 (void);
extern void instr11 (void);
extern void instr12 (void);
static void *instr[] =
  {
    instr0,
    instr1,
    instr2,
    instr3,
    instr4,
    instr5,
    instr6,
    instr7,
    instr8,
    instr9,
    instr10,
    instr11,
    instr12,
    NULL
  };

/* PTRACE_SINGLESTEP through the whole INSTR program.  */

static void
test_singlestep (void)
{
  long l;
  int status;
  pid_t pid;
  struct user_regs_struct pt_regs;
  void **instrp;

  peekuser (&pt_regs);
  PT_REGS_IP_SET (pt_regs, instr[0]);
  pokeuser (&pt_regs);

  /* Stop one instruction before last HLT.  */

  for (instrp = instr; instrp[1] != NULL; instrp++)
    {
      peekuser (&pt_regs);

      /* Test we get exactly to the next instruction each step.  */
      CHECK_IP (PT_REGS_IP_GET (pt_regs), *instrp, "", instrp - instr);

      /* Test the trap flag gets turned on at the right point (*2).  */
      CHECK_FLAGS (&pt_regs, instrp >= &instr[7], "", instrp - instr);

      errno = 0;
      l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);

      pid = waitpid (child, &status, 0);
      assert (pid == child);
      CHECK_STOPPED (status, SIGTRAP, "");

      /* KFAIL(*1) - PTRACE_SINGLESTEP trace bit is visible for PUSHF.
	 arch/x86/kernel/step.c:  */
      /*
       * pushf: NOTE! We should probably not let
       * the user see the TF bit being set. But
       * it's more pain than it's worth to avoid
       * it, and a debugger could emulate this
       * all in user space if it _really_ cares.
       */
      if (instrp == &instr[3])
	{
	  peekuser (&pt_regs);
	  CHECK_IP (PT_REGS_IP_GET (pt_regs), *instrp, "", instrp - instr);

	  PT_REGS_IP_SET (pt_regs, instr[4]);
	  pokeuser (&pt_regs);
	}
   }
}

/* PTRACE_CONT through the whole INSTR program.  */

static void
test_cont (void)
{
  long l;
  int status;
  pid_t pid;
  struct user_regs_struct pt_regs;
  void **instrp;

  peekuser (&pt_regs);
  PT_REGS_IP_SET (pt_regs, instr[0]);
  /* It may be left set since TEST_SINGLESTEP.  */
  PT_REGS_FLAGS (pt_regs) &= ~PT_REGS_FLAGS_TRACE;
  pokeuser (&pt_regs);

  errno = 0;
  l = ptrace (PTRACE_CONT, child, NULL, NULL);

  assert_perror (errno);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  CHECK_STOPPED (status, SIGTRAP, "");

  peekuser (&pt_regs);

  /* Test we got trapped after the trap flag got turned on by the inferior as
     it occurs one instruction after it got turned on (*3).  */
  instrp = &instr[8];

  for (;; instrp++)
    {
      assert (*instrp != NULL);

      peekuser (&pt_regs);

      /* Test we get exactly to the next instruction each step.  */
      CHECK_IP (PT_REGS_IP_GET (pt_regs), *instrp, "", instrp - instr);

      /* Test the trap flag is already and still turned on.  */
      CHECK_FLAGS (&pt_regs, 1, "", instrp - instr);

      errno = 0;
      l = ptrace (PTRACE_CONT, child, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);

      pid = waitpid (child, &status, 0);
      assert (pid == child);
      if (instrp < &instr[12])
	CHECK_STOPPED (status, SIGTRAP, "");
      else
        {
	  /* We stopped on HLT.  */
	  CHECK_STOPPED (status, SIGSEGV, "");
	  break;
	}
   }
}

#ifdef PTRACE_SINGLEBLOCK

/* PTRACE_SINGLEBLOCK through the whole INSTR program.  */

static void
test_singleblock (void)
{
  long l;
  int status;
  pid_t pid;
  struct user_regs_struct pt_regs;
  void *ip;

  peekuser (&pt_regs);
  PT_REGS_IP_SET (pt_regs, instr[0]);
  /* It may be left set since TEST_SINGLESTEP.  */
  PT_REGS_FLAGS (pt_regs) &= ~PT_REGS_FLAGS_TRACE;
  pokeuser (&pt_regs);

  errno = 0;
  l = ptrace (PTRACE_SINGLEBLOCK, child, NULL, NULL);

  /* Unsupported by the kernel?  We do not SKIP this testcase.  */
  if (PTRACE_SINGLEBLOCK == PTRACE_SINGLEBLOCK && l == -1 && errno == EIO)
    return;

  assert_perror (errno);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  CHECK_STOPPED (status, SIGTRAP, "");

  peekuser (&pt_regs);

  /* KFAIL PTRACE_SINGLEBLOCK which makes the TF (Trap Flag) visible to
     the inferior.  We will stop on &instr[3] due to it.
     arch/x86/kernel/step.c:  */
  /*
   * [...]
   * Note that we don't try to worry about any is_setting_trap_flag()
   * instructions after the first when using block stepping.
   * So noone should try to use debugger block stepping in a program
   * that uses user-mode single stepping itself.
   */
  ip = PT_REGS_IP_GET (pt_regs);
  // PTRACE_SINGLEBLOCK did only PTRACE_SINGLESTEP.
  // This happens for KVM guests.
  if (ip == instr[1])
    exit (77);
  CHECK_IP (ip, instr[3], "", -1);
  /* Still the ptrace shows no TF (Trap flag) is set.  */
  CHECK_FLAGS (&pt_regs, 0, "", -1);
  PT_REGS_IP_SET (pt_regs, instr[4]);
  pokeuser (&pt_regs);

  assert (PTRACE_SINGLEBLOCK == PTRACE_SINGLEBLOCK);
  errno = 0;
  l = ptrace (PTRACE_SINGLEBLOCK, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  /* And we get stopped only at final HLT (*4).  */

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  CHECK_STOPPED (status, SIGSEGV, "");

  peekuser (&pt_regs);
  CHECK_IP (PT_REGS_IP_GET (pt_regs), instr[12], "", -1);
}

#endif	/* PTRACE_SINGLEBLOCK */

asm (
"		.text			\n"
/* The first instruction is NOP for the PTRACE_SINGLEBLOCK test.  But it should
   not change anything as the trap flag is set here either way.
   arch/x86/kernel/step.c:  */
/*
 * [...]
 * Note that we don't try to worry about any is_setting_trap_flag()
 * instructions after the first when using block stepping.
 * So noone should try to use debugger block stepping in a program
 * that uses user-mode single stepping itself.
 */
"settest0:	nop			\n"
/* Test we see the trap flag set.  */
"settest1:	pushf			\n"
"settest2:	" X86_POP_AX "		\n"
"settest3:	testl	$0x100, %eax	\n"
"settest4:	jz	settest4	\n"
"settest5:	nop			\n"
/* Cause a trap if we get here.  */
"settest6:	hlt			\n"
);
extern void settest0 (void);
extern void settest1 (void);
extern void settest2 (void);
extern void settest3 (void);
extern void settest4 (void);
extern void settest5 (void);
extern void settest6 (void);
static void *settest[] =
  {
    settest0,
    settest1,
    settest2,
    settest3,
    settest4,
    settest5,
    settest6,
    NULL
  };

/* Run through the whole SETTEST program.  Test setting the trap flag
   through ptrace to make it visible for the inferior.  */

static void
test_settest (int ptrace_type, const char *ptrace_type_name)
#define TEST_SETTEST(ptrace_type) test_settest (ptrace_type, #ptrace_type )
{
  long l;
  int status;
  pid_t pid;
  struct user_regs_struct pt_regs;
  void **settestp;

  peekuser (&pt_regs);
  PT_REGS_IP_SET (pt_regs, settest[0]);
  /* This setting is the purpose of this test.  */
  PT_REGS_FLAGS (pt_regs) |= PT_REGS_FLAGS_TRACE;
  pokeuser (&pt_regs);

  /* Stop one instruction before last HLT.  */

  for (settestp = &settest[0]; settestp[1] != NULL; settestp++)
    {
      peekuser (&pt_regs);

      /* Test we get exactly to the next settestuction each step.  */
      CHECK_IP (PT_REGS_IP_GET (pt_regs), *settestp, ptrace_type_name,
		settestp - settest);

      /* Test the trap flag is already and still turned on.  The purpose of
         this test is more that the inferior code should behave as if the flag
         is set.  */
      CHECK_FLAGS (&pt_regs, 1, ptrace_type_name, settestp - settest);

      errno = 0;
      l = ptrace (ptrace_type, child, NULL, NULL);

#ifdef PTRACE_SINGLEBLOCK
      /* Unsupported by the kernel?  We do not SKIP this testcase.  */
      if (ptrace_type == PTRACE_SINGLEBLOCK && l == -1 && errno == EIO)
	return;
#endif

      assert_perror (errno);
      assert (l == 0);

      pid = waitpid (child, &status, 0);
      assert (pid == child);
      CHECK_STOPPED (status, SIGTRAP, ptrace_type_name);
   }
}

#endif

/* Forward referencing INSTR and SETTEST.  */

static void
check_stopped (int status, int signo, const char *signo_name, const char *where,
	       const char *file, unsigned line, const char *function)
{
  if (!WIFSTOPPED (status))
    {
      fprintf (stderr, "%s: %s:%u: %s (%s): WIFSTOPPED expected: status = %d\n",
	       progname, file, line, function, where, status);
      exit (1);
    }
  if (WSTOPSIG (status) != signo)
    {
      struct user_regs_struct pt_regs;
      void **instrp, **settestp;

      fprintf (stderr, "%s: %s:%u: %s (%s): "
		       "WSTOPSIG %s (%d) expected: found %d\n",
	       progname, file, line, function, where, signo_name, signo,
	       WSTOPSIG (status));
      /* We could possibly error-out also by PEEKUSER.  */
      peekuser (&pt_regs);
      for (instrp = instr; *instrp != NULL; instrp++)
        if (PT_REGS_IP_GET (pt_regs) == *instrp)
	  {
	    fprintf (stderr, "%s: %s:%u: %s (%s): "
			     "PC was there on instr%d\n",
		     progname, file, line, function, where,
		     (int) (instrp - instr));
	    exit (1);
	  }
      for (settestp = &settest[0]; *settestp != NULL; settestp++)
        if (PT_REGS_IP_GET (pt_regs) == *settestp)
	  {
	    fprintf (stderr, "%s: %s:%u: %s (%s): "
			     "PC was there on settest%d\n",
		     progname, file, line, function, where,
		     (int) (settestp - settest));
	    exit (1);
	  }
      exit (1);
    }
}

int main (int argc, char **argv)
{
  long l;
  int status;
  pid_t pid;

  progname = argv[0];
  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);

  errno = 0;
  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      errno = 0;
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);
      raise (SIGUSR1);
      /* The program continues at RAISE_SIGUSR2.  */
      assert (0);
    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  CHECK_STOPPED (status, SIGUSR1, "");

  /* PTRACE_SINGLESTEP is here to exit the syscall, syscall restarting is out
     of the scope of this test - see `erestart*'.  */

  errno = 0;
  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  CHECK_STOPPED (status, SIGTRAP, "");

  test_singlestep ();
  test_cont ();
#ifdef PTRACE_SINGLEBLOCK
  test_singleblock ();
#endif

  TEST_SETTEST (PTRACE_SINGLESTEP);
  TEST_SETTEST (PTRACE_CONT);
#ifdef PTRACE_SINGLEBLOCK
  TEST_SETTEST (PTRACE_SINGLEBLOCK);
#endif

  return 0;
}

#endif	/* PT_REGS_IP_ULONG */
