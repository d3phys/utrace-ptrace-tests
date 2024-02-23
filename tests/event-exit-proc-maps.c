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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#define PTRACE_EVENT(status) ((status) >> 16)

/* On RHEL-4 it is present only in <linux/ptrace.h> in
   /lib/modules/`uname -r`/{build,source}.  */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS	0x4200
#endif
#ifndef PTRACE_O_TRACEEXIT
#define PTRACE_O_TRACEEXIT	0x00000040
#endif
#ifndef PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT	6
#endif

int
main(int argc, char **argv)
{
    pid_t pid;
    int result = 0;
    char *selfpath, *s;
    int i;

    s = strrchr (argv[0], '/');
    if (s != NULL)
      s++;
    else
      s = argv[0];
    i = asprintf (&selfpath, "/tmp/%s.%d.tmp", s, (int) getpid ());
    assert (i > 0);
    /* Errors may happen as the link may not have been created at all.  */
    unlink (selfpath);

    /* We would pass even on the buggy kernels if we are root.  */
    if (geteuid () == 0) {
	uid_t uid = 99;
	int i;
	char resolved[PATH_MAX];

	/* We would get `Invalid cross-device link' for a direct link from
	   `/proc/self/exe'.  */
	s = realpath ("/proc/self/exe", resolved);
	assert (s == resolved);
	i = link (resolved, selfpath);
	if (i != 0) /* link failed. Will try execing resolved /proc/self/exe */
          selfpath = resolved;
	else
          {
	    /* CHOWN should be enough as SELFPATH is already REALPATH resolved.  */
	    i = lchown (selfpath, uid, -1);
	    assert (i == 0);
          }

	i = setuid (uid);
	assert (i == 0);

	/* If we drop the privileges we still cannot PTRACE_ATTACH ourselves
	   (and we will not dump core) - as a protection from tracing/dumping
	   system root daemons which dropped its privileges.  */
	execv (selfpath, argv);
	execv ("/proc/self/exe", argv);
	assert (0);
    }
    assert (geteuid () != 0);
    assert (getuid () != 0);

    pid = fork();
    assert(pid != -1);

    if (pid == 0) {
        /* Child processes, wait a second for the parent to attach. */
        sleep(1);

        kill(getpid(), SIGABRT);
        //exit(0);
    }
    else {
        long res;
        int status;

        /* Attach to the child process. */
        res = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        assert(res != -1);

        res = waitpid(pid, &status, __WALL);
        assert(res == pid);

        res = ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT);
        assert(res != -1);

        res = ptrace(PTRACE_CONT, pid, NULL, (void *)0);
        assert(res != -1);

        /* Trace the child process until it has exited. */
        int exited = 0;
        do {
            res = waitpid(pid, &status, __WALL);
            assert(res == pid);

            if (WIFSTOPPED(status)) {
                if (PTRACE_EVENT(status) == PTRACE_EVENT_EXIT)
		  {
                    char maps[PATH_MAX];

                    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
		    struct stat st;
		    int stat_rc = stat(maps, &st);
		    assert (stat_rc == 0);
                    int status_fd = open(maps, O_RDONLY);
                    if (status_fd == -1)
		      {
			int open_errno = errno;
			printf("%s has uid %u and mode %04o\n",
			       maps, st.st_uid, st.st_mode&07777);
			error (1, open_errno, "Failed to open %s: error %d",
			       maps, open_errno);
			//raise(SIGSTOP);
		      }
                    else
		      {
			char buf[0x1000];
			res = read(status_fd, buf, sizeof(buf) - 1);
			if (res == -1)
			  {
			    printf("Failed to read %s: error %d, %m\n",
				   maps, errno);
			    result = 1;
			  }
			res = close(status_fd);
			assert(res != -1);
		      }

                    res = ptrace(PTRACE_CONT, pid, NULL, (void *)0);
                    assert(res != -1);
		  }
                else if (PTRACE_EVENT(status) == 0) {
                    res = ptrace(PTRACE_CONT, pid, NULL,
                                 (void *)(long)WSTOPSIG(status));
                    assert(res != -1);
                }
                else
                    assert(0);
            } else if (WIFEXITED(status) || WIFSIGNALED(status))
                exited = 1;
            else
                assert(0);
        } while (!exited);
    }

    return result;
}
