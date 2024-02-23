/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

// Tests whether we can ptrace single step through a child signal
// handler and return where the signal interrupted the child
// afterwards. In particular tests whether we can single step over the
// sigret syscall at the end of the handler. On some kernels
// (e.g. 2.6.24.4-64.fc8 x86) this cleared the stepping flag and let
// the child run free.

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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

#ifdef __i386__
#define PC eip
#endif
#ifdef __x86_64__
#define PC rip
#endif

#ifndef PC // unsupported architecture
int main (int argc, char **argv) { return 77; }
#else

// The process to trace.
static pid_t child = -1;

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
  assert (0);
}

// Whether to be verbose (just give any argument to the program).
static int verbose;

#define VERBOSE(output...) do { if (verbose) { \
  printf ("#%s (#%d) ", (child != 0 ? "parent" : "child"), __LINE__); \
  printf (output); \
} } while (0)

// Signal ran and process done?
static volatile int done = 0;

// When SIGALRM comes in set done flag. Nothing interesting,
// we are just interested in stepping through it, including the sigret.
static void sig_handler(int sig) { done = 1; }

// Returns the current pc value of the child pid (must be stopped).
static long int
get_pc(int pid)
{
  struct user_regs_struct regs;
  long r = ptrace (PTRACE_GETREGS, pid, NULL, &regs);
  assert (r != -1);
  return regs.PC;
}

int
main (int argc, char **argv)
{
  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  verbose = (argc > 1);

  VERBOSE ("forking\n");
  child = fork ();
  assert (child >= 0);
  switch (child)
    {
    case 0:
      {
	// Child, sets up a sigalrm handler, sets the alarm and spins.
	VERBOSE ("Setting up handler and alarm\n");
	struct sigaction sa;
	memset (&sa, 0, sizeof sa);
	sa.sa_handler = sig_handler;
	int r = sigemptyset(&sa.sa_mask);
	assert (r == 0);
	sa.sa_flags = 0;
	r = sigaction(SIGALRM, &sa, NULL);
	assert (r == 0);
	r = alarm(1);
	assert (r == 0);

	VERBOSE ("spinning till signal...\n");
	while (! done)
	  continue;

	VERBOSE ("done\n");
	_exit (0);
      }

    default:
      {
	// Parent, attched to child, waits for signal, steps through.

	VERBOSE ("ptrace attach\n");
	long r = ptrace (PTRACE_ATTACH, child, NULL, NULL);
	assert (r == 0);

	VERBOSE ("wait for attach\n");
	int status;
	pid_t pid = wait (&status);
	assert (pid == child);
	assert (WIFSTOPPED (status));
	assert (WSTOPSIG (status) == SIGSTOP);

	VERBOSE ("let child run free (till signal)\n");
	r = ptrace (PTRACE_CONT, child, 0, 0);
	assert (r == 0);

	VERBOSE ("waiting for child SIGALRM\n");
	pid = wait (&status);
	assert (pid == child);
	assert (WIFSTOPPED (status));
	assert (WSTOPSIG (status) == SIGALRM);

	// Record the current pc to see when we have returned from signal
	long int ret_addr = get_pc(child);
	VERBOSE ("child got signal at 0x%lx\n", ret_addr);

	// Step into child signal handler.
	VERBOSE ("do first step into signal handler\n");
	r = ptrace (PTRACE_SINGLESTEP, child, 0, SIGALRM);
	assert (r == 0);

	pid = wait (&status);
	assert (pid == child);
	assert (WIFSTOPPED (status));
	assert (WSTOPSIG (status) == SIGTRAP);

	// Check current pc to see that we are in the signal handler.
	long int pc = get_pc(child);
	VERBOSE ("stepped into sig_handler (0x%lx)\n", pc);
	assert (pc == (long int) sig_handler);

	// Now single step child to return from sig_handler
	do
	  {
	    VERBOSE ("single step child (0x%lx)\n", pc);
	    long r = ptrace (PTRACE_SINGLESTEP, child, 0, 0);
	    assert (r == 0);

	    pid = wait (&status);
	    assert (pid == child);

	    if (WIFEXITED (status))
	      {
		if (WEXITSTATUS (status) == 0)
		  {
		    /* Expected FAIL.  */
		    return 1;
		  }
		fprintf (stderr, "%s: tracing: WEXITSTATUS = %d\n",
			 argv[0], WEXITSTATUS (status));
		return 1;
	      }

	    if (!WIFSTOPPED (status))
	      {
		fprintf (stderr, "%s: tracing: !WIFSTOPPED; status = %d\n",
			 argv[0], status);
		return 1;
	      }
	    if (WSTOPSIG (status) != SIGTRAP)
	      {
		fprintf (stderr, "%s: tracing: WSTOPSIG %d != SIGTRAP\n",
			 argv[0], WSTOPSIG (status));
		return 1;
	      }

	    pc = get_pc(child);
	  }
	while (pc != ret_addr);

	VERBOSE ("done stepping sig_handler (0x%lx)\n", pc);
	assert (pc == ret_addr);

	VERBOSE ("Let child run free (till exit)\n");
	r = ptrace (PTRACE_CONT, child, 0, 0);
	assert (r == 0);

	VERBOSE ("waiting for child exit\n");
	pid = wait (&status);
	assert (pid == child);
	if (!WIFEXITED (status))
	  {
	    fprintf (stderr, "%s: exiting: !WIFEXITED; status = %d\n", argv[0],
		     status);
	    return 1;
	  }
	if (WEXITSTATUS (status) != 0)
	  {
	    fprintf (stderr, "%s: exiting: WEXITSTATUS = %d\n", argv[0],
		     WEXITSTATUS (status));
	    return 1;
	  }

	VERBOSE ("done\n");
	return 0;
      }
    }
}
#endif // supported architecture
