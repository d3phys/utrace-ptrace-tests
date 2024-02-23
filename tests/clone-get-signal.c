/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* zap_threads() does __ptrace_unlink(p) under write_lock(tasklist_lock),
   what if p->parent waits for tasklist_lock in ptrace_detach() ?

   This program crashes the kernel (both 2.6.15 and 2.6.16-rc2 were tested)
   very quickly (BUG() in __ptrace_unlink).  */

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

#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>

/* Crashed in 8 minutes.  */
#define DEFAULT_TESTTIME (15 * 60)	/* seconds */

static void die (const char *msg)
{
	printf ("ERR!! %s: %s\n", msg, strerror(errno));
	exit (1);
}

#ifdef __ia64__
extern int __clone2 (int (*fn)(void *), void *child_stack_base,
		     size_t stack_size, int flags, void *arg, ...);
#define clone2 __clone2
#else
#define clone2(func, stack_base, size, flags, arg...) \
	clone (func, (stack_base) + (size), flags, arg)
#endif

static pid_t clone_vm (int (*fn) (void *), void *stack_base, size_t stack_size)
{
	pid_t pid;

	pid = clone2 (fn, stack_base, stack_size, CLONE_VM, NULL);
	if (pid < 0)
		die ("clone");

	return pid;
}

static unsigned char child_stack[4096];

static int child_func (void *arg)
{
	return pause ();
}

static unsigned char cdump_stack[4096];

static int cdump_func (void *arg)
{
	return kill (syscall(__NR_getpid), SIGQUIT);
}

int main (int argc, char **argv)
{
	char *testtime = getenv ("TESTTIME");
	time_t testend = time (NULL) + (testtime != NULL ? atoi (testtime)
							 : DEFAULT_TESTTIME);
	unsigned long loops;
	int pid;

	struct rlimit lim;
	if (getrlimit(RLIMIT_NPROC, &lim))
	  perror("getrlimit");
	lim.rlim_cur = lim.rlim_max;
	if (setrlimit(RLIMIT_NPROC, &lim))
	  perror("setrlimit");

	loops = 0;
	do {
		if ((pid = fork())) {
			if (waitpid (pid, NULL, 0) != pid)
				die ("wait");
			kill (-pid, SIGKILL);
		} else {
			int child;

			if (setpgrp ())
				die("pgrp");

			child = clone_vm (child_func, child_stack,
					  sizeof child_stack);

			if (ptrace (PTRACE_ATTACH, child, NULL, 0))
				die ("ptrace");

			if (waitpid (child, NULL, __WALL) != child)
				die ("wait");

			clone_vm (cdump_func, cdump_stack, sizeof cdump_stack);

			if (ptrace (PTRACE_DETACH, child, NULL, 0))
				die ("detach");

			break;
		}
		loops++;
	} while (argc > 1 || time (NULL) < testend);

	return 0;
}
