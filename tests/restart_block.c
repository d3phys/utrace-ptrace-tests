/* Test syscalls restarting after calling a function in between of an
   interrupted syscall which syscalls another restartable function.
   Restoring the outer syscall then accidentally restores the inner one.

   Restartable syscalls (here used nanosleep vs. poll) are only those mentioned
   in struct restart_block: futex_wait, futex_wait_requeue_pi, nanosleep, poll

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* On older kernels which do not support syscall restart we SKIP this test.  */

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
#include <stddef.h>
#include <pty.h>
#include <string.h>
#include <stdint.h>
#include <poll.h>
#include <time.h>

#if defined __x86_64__
# define REGISTER_IP .rip
#elif defined __i386__
# define REGISTER_IP .eip
#elif defined __powerpc__
# define REGISTER_IP .nip
# define user_regs_struct pt_regs
/* __s390x__ defines both the symbols.  */
#elif defined __s390__
# define REGISTER_IP .psw.addr
#elif defined __s390x__
# error "__s390__ should be defined"
#elif defined __ia64__
# include <asm/ptrace_offsets.h>
/* FIXME: # define REGISTER_IP [PT_CR_IIP / 8] */
#endif

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

/* PTRACE_GETREGS / PTRACE_SETREGS are not available on ppc.
   On the other hand the PTRACE_PEEKUSER / PTRACE_POKEUSER may crash on utrace:
     https://bugzilla.redhat.com/show_bug.cgi?id=431314
   s390* defines PTRACE_GETREGS but it EIOs.
   ppc* provides PTRACE_PEEKUSER / PTRACE_POKEUSER as enum (no #ifdef).  */

#ifdef PTRACE_PEEKUSR_AREA

static void
peekuser (struct user_regs_struct *pt_regs)
{
  ptrace_area parea;
  long l;

  parea.process_addr = (unsigned long) pt_regs;
  parea.kernel_addr = 0;
  parea.len = sizeof (*pt_regs);
  errno = 0;
  l = ptrace (PTRACE_PEEKUSR_AREA, child, &parea, NULL);
  assert_perror (errno);
  assert (l == 0);
}

static void
pokeuser (struct user_regs_struct *pt_regs)
{
  ptrace_area parea;
  long l;

  parea.process_addr = (unsigned long) pt_regs;
  parea.kernel_addr = 0;
  parea.len = sizeof (*pt_regs);
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

#else

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

#endif

static volatile long func_data;

static int pipefds[2];

static void
func (void)
{
  static struct pollfd pollfd;

  pollfd.fd = pipefds[0];
  pollfd.events = POLLIN;
  poll (&pollfd, 1, 3 * 1000);

  assert (0);
}

static volatile long child_retval;
static volatile long child_errno;

static int verbose;

static void
backtrace (void)
{
  char *cmd;

  if (!verbose)
    return;
  int err = asprintf (&cmd, "cat /proc/%d/stack;echo", child);
  assert (err > 0);
  err = system (cmd);
  assert (err == 0);
  free (cmd);
}

int
main (int argc, char **argv)
{
  long l;
  int status, i;
  unsigned u;
  pid_t pid;
  struct user_regs_struct user_orig, user;
  const char some_byte = 42;
  ssize_t ssize;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  if (argc >= 2 && !strcmp (argv[1], "-v"))
    verbose = 1;

  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);

  i = pipe (pipefds);
  assert (i == 0);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);
      errno = 0;
      {
	struct timespec req;
	req.tv_sec = 4;
	req.tv_nsec = 0;
	i = nanosleep (&req, NULL);
      }
      child_retval = i;
      child_errno = errno;
      raise (SIGUSR2);
      assert (0);
    default:
      break;
    }

  u = sleep (1);
  assert (u == 0);

  if (verbose)
    puts ("child is in nanosleep...");
  backtrace ();

  i = kill (child, SIGUSR1);
  assert (i == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  peekuser (&user_orig);
  /* `user_orig REGISTER_IP' is now in glibc sleep ().  */
  user = user_orig;
  user REGISTER_IP = (unsigned long) func;
#ifdef __powerpc64__
  {
    /* ppc64 `func' resolves to the function descriptor.  */
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
    const func_u = { func };

    user.nip = (uintptr_t) func_u.p->entry;
    user.gpr[2] = (uintptr_t) func_u.p->toc;
  }
#endif
  /* GDB amd64_linux_write_pc():  */
  /* We must be careful with modifying the program counter.  If we
     just interrupted a system call, the kernel might try to restart
     it when we resume the inferior.  On restarting the system call,
     the kernel will try backing up the program counter even though it
     no longer points at the system call.  This typically results in a
     SIGSEGV or SIGILL.  We can prevent this by writing `-1' in the
     "orig_rax" pseudo-register.

     Note that "orig_rax" is saved when setting up a dummy call frame.
     This means that it is properly restored when that frame is
     popped, and that the interrupted system call will be restarted
     when we resume the inferior on return from a function call from
     within GDB.  In all other cases the system call will not be
     restarted.  */
#ifdef __x86_64__
  user.orig_rax = -1L;
#elif defined __i386__
  user.orig_eax = -1L;
#elif defined __powerpc__
  user.trap = 0;   /* Equivalent to disable syscall restart on powerpc.  */
#elif defined __s390__
  /* kernel-2.6.18-164.6.1.el5.s390x will EINTR -> 77 though.  */
  user.orig_gpr2 = -1L;
#else
# error "Unsupported arch"
#endif

  pokeuser (&user);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  u = sleep (1);
  assert (u == 0);

  if (verbose)
    puts ("child is in poll...");
  backtrace ();

  i = kill (child, SIGUSR2);
  assert (i == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR2);

  pokeuser (&user_orig);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  if (verbose)
    puts ("child after restore should be in nanosleep but it is in poll...");
  backtrace ();

  // Make poll() return 1.
  ssize = write (pipefds[1], &some_byte, 1);
  assert (ssize == 1);

  u = sleep (1);
  assert (u == 0);

  if (verbose)
    puts ("child should be still in nanosleep but poll has finished...");
  backtrace ();

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR2);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, &child_retval, NULL);
  assert_perror (errno);
  child_retval = l;
  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, &child_errno, NULL);
  assert_perror (errno);
  child_errno = l;

  // nanosleep() would return 0.
  if (child_retval == 0 && child_errno == 0)
    return 0;
  // poll() returns 1 due to write() above.
  if (child_retval == 1 && child_errno == 0)
    return 1;

  fprintf (stderr, "Unexpected: retval %ld, errno %ld\n", child_retval,
	   child_errno);

  assert (0);
}

#endif	/* REGISTER_IP */
