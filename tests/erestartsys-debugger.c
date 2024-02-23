/* Test the syscall-restart-disable should work for orig_rax 0x00000000ffffffff
   with x86_64 debugger and i386 debuggee.

   This testcase requires already fixed `erestartsys' to work properly
   otherwise it will FAIL and also warn:
     FAIL type `biarch-tests/erestartsys' on x86_64(debugger)-on-i386(debuggee)-on-x86_64(kernel)
   While this FAIL type is out of the scope of this testcase we supply the
   `erestartsys' for its unsupported x86_64(debugger)-on-i386(debuggee) arch.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* On older kernels which do not support syscall restart we SKIP this test.  */

#define _GNU_SOURCE 1

#define DEBUGEE_PATHNAME "./erestartsys-debuggee"

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

#if defined __x86_64__
# define REGISTER_IP .rip
#elif defined __powerpc64__
/* FIXME:
# define REGISTER_IP .nip
# define user_regs_struct pt_regs
*/
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

typedef unsigned long child_data_t;
typedef unsigned int child_address_t;
#define CHILD_UNSIGNED_INT_FORMAT "0x%x"
#define CHILD_ADDRESS_FORMAT "0x%x"

int
main (int argc, char **argv)
{
  long l;
  int status, i;
  pid_t pid;
  struct user_regs_struct user_orig, user;
  ssize_t ssize;
  int amaster;
  const char intr_c = 003;
  struct termios termios;
  /* Its size must match `erestartsys-debuggee.c'.  */
  char buf[0x100];
  size_t buf_have = 0;
  unsigned int child_data_size;
  child_address_t func_p, func_data_p, child_retval_p, child_errno_p;
  child_data_t func_data, child_retval, child_errno;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);

  /* Simple kill (child, SIGINT) does not make it fly => using termios.  */

  /* With TERMP passed as NULL we get "\n" -> "\r\n".  */
  termios.c_iflag = IGNBRK | IGNPAR;
  termios.c_oflag = 0;
  termios.c_cflag = CS8 | CREAD | CLOCAL | HUPCL | B9600;
  termios.c_lflag = IEXTEN | NOFLSH;
  memset (termios.c_cc, _POSIX_VDISABLE, sizeof (termios.c_cc));
  termios.c_cc[VTIME] = 0;
  termios.c_cc[VMIN ] = 1;
  cfmakeraw (&termios);
#ifdef FLUSHO
  /* Workaround a readline deadlock bug in _get_tty_settings().  */
  termios.c_lflag &= ~FLUSHO;
#endif
  /* Specific for us.  */
  termios.c_cc[VINTR] = intr_c;
  termios.c_lflag |= ISIG;
  child = forkpty (&amaster, NULL, &termios, NULL);
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      execl (DEBUGEE_PATHNAME, "erestartsys-debuggee", "foo", NULL);
      assert (0);
    default:
      break;
    }

  /* FIXME: We need to get in sync with the child as it must pass the
     PTRACE_TRACEME, we may get it caught inside of write(3) otherwise.  */
  i = sleep (1);
  assert (i == 0);

  while (buf_have != sizeof buf)
    {
      ssize_t got;
      int status;

      assert (buf_have < sizeof buf);
      got = read (amaster, buf + buf_have, sizeof (buf) - buf_have);

      /* On x86_64 host without 32-bit build environment the child will just
	 return 77 as it was built with -m64 (and not -m32).  */
      if (got == 0 || (got == -1 && errno == EIO))
	{
	  /* Ignore the possible errors, just to avoid hang on WAITPID as we
	     cannot use WNOHANG there.  */
	  kill (child, SIGKILL);

	  if (waitpid (child, &status, 0) == child && WIFEXITED (status)
	       && WEXITSTATUS (status) == 77)
	    {
	      /* stderr from child would not be visible due to forkpty().  */
	      fprintf (stderr, "%s: 32-bit biarch system libraries required!\n",
		       argv[0]);
	      return 77;
	    }
	  assert (0);
	}
      assert (got > 0);
      buf_have += got;
    }
  assert (memchr (buf, 0, sizeof buf) != NULL);
  i = sscanf (buf, "data_size " CHILD_UNSIGNED_INT_FORMAT "\n"
		   "func " CHILD_ADDRESS_FORMAT "\n"
		   "func_data " CHILD_ADDRESS_FORMAT "\n"
		   "child_retval " CHILD_ADDRESS_FORMAT "\n"
		   "child_errno " CHILD_ADDRESS_FORMAT "\n",
	      &child_data_size, &func_p, &func_data_p, &child_retval_p,
	      &child_errno_p);
  assert (i == 5);
  assert (sizeof (child_data_t) == child_data_size);
  assert (func_data_p % sizeof (child_data_t) == 0);
  assert (child_retval_p % sizeof (child_data_t) == 0);
  assert (child_errno_p % sizeof (child_data_t) == 0);

  ssize = write (amaster, &intr_c, sizeof intr_c);
  assert (ssize == sizeof intr_c);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGINT);

  /* Workaround of the whole testcase problem.  */
#if 0
  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert (l == 0);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);
#endif

  peekuser (&user_orig);

  /* `user_orig REGISTER_IP' is now in glibc sleep ().  */
  user = user_orig;
  user REGISTER_IP = (unsigned long) func_p;
#ifdef __powerpc64__
  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, (void *) (unsigned long) func_p, NULL);
  assert_perror (errno);
  user.nip = l; /* entry */
  user.gpr[2] = l >> 32U; /* TOC */
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
  user.orig_rax = (unsigned int) (-1L);
#elif defined __powerpc64__
  user.trap = 0;   /* Equivalent to disable syscall restart on powerpc.  */
#else
# error "Unsupported arch"
#endif

  pokeuser (&user);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  /* We would get SIGILL (SIGSEGV?) here without the ORIG_EAX hack above.  */
  assert (WSTOPSIG (status) == SIGUSR2);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, (void *) (unsigned long) func_data_p,
	      NULL);
  assert_perror (errno);
  func_data = l;
  assert (func_data == l);
  assert (func_data == 42);

  pokeuser (&user_orig);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, (void *) (unsigned long) child_retval_p,
	      NULL);
  assert_perror (errno);
  child_retval = l;
  assert (child_retval == l);
  errno = 0;
  l = ptrace (PTRACE_PEEKDATA, child, (void *) (unsigned long) child_errno_p,
	      NULL);
  assert_perror (errno);
  child_errno = l;
  assert (child_errno == l);

  /* kernel-2.6.23.15-137.fc8.x86_64 -m64.  */
  /* kernel.org 2.6.22-rc4-git7 x86_64 -m64.  */
  /* kernel-2.6.23.15-137.fc8.i686 (-m32).  */
  if (child_retval == 0 && child_errno == 0)
    return 0;
  /* kernel.org 2.4.33 i686, it was more a missing feature that time.  */
  /* kernel-2.6.18-53.el5.s390x -m64.  */
  if (child_retval > 0 && child_errno == EINTR)
    return 77;
  /* kernel.org 2.6.22-rc4-git7 x86_64 on -m32.  */
  /* kernel-2.6.23.15-137.fc8.x86_64 -m32.  */
  if (child_retval > 0 && child_errno >= 512 && child_errno < 512 + 64)
    {
      fprintf (stderr, "%s: FAIL type `biarch-tests/erestartsys' on "
	       "x86_64(debugger)-on-i386(debuggee)-on-x86_64(kernel)\n",
	       argv[0]);
      return 1;
    }
  fprintf (stderr, "Unexpected: retval %ld, errno %ld\n", (long) child_retval,
	   (long) child_errno);
  assert (0);
}

#endif	/* REGISTER_IP */
