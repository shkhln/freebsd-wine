--- dlls/ntdll/unix/signal_x86_64.c.orig	2024-05-03 19:43:47 UTC
+++ dlls/ntdll/unix/signal_x86_64.c
@@ -144,6 +144,9 @@ __ASM_GLOBAL_FUNC( alloc_fs_sel,
 
 #elif defined(__FreeBSD__) || defined (__FreeBSD_kernel__)
 
+#include <machine/cpufunc.h>
+#include <machine/segments.h>
+#include <machine/specialreg.h>
 #include <machine/trap.h>
 
 #define RAX_sig(context)     ((context)->uc_mcontext.mc_rax)
@@ -459,7 +462,7 @@ static inline struct amd64_thread_data *amd64_thread_d
     return (struct amd64_thread_data *)ntdll_get_thread_data()->cpu_data;
 }
 
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
 static inline TEB *get_current_teb(void)
 {
     unsigned long rsp;
@@ -826,6 +829,8 @@ static inline ucontext_t *init_handler( void *sigconte
         struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&get_current_teb()->GdiTebBatch;
         arch_prctl( ARCH_SET_FS, ((struct amd64_thread_data *)thread_data->cpu_data)->pthread_teb );
     }
+#elif defined(__FreeBSD__)
+    // ?
 #endif
     return sigcontext;
 }
@@ -839,6 +844,13 @@ static inline void leave_handler( ucontext_t *sigconte
 #ifdef __linux__
     if (fs32_sel && !is_inside_signal_stack( (void *)RSP_sig(sigcontext )) && !is_inside_syscall(sigcontext))
         __asm__ volatile( "movw %0,%%fs" :: "r" (fs32_sel) );
+#elif defined(__FreeBSD__)
+    //~ struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&get_current_teb()->GdiTebBatch;
+    //~ USHORT fs = ((struct amd64_thread_data *)thread_data->cpu_data)->fs;
+    //~ if (fs != 0 && !is_inside_signal_stack((void *)RSP_sig(sigcontext)) && !is_inside_syscall(sigcontext))
+    //~ {
+        //~ load_fs(fs);
+    //~ }
 #endif
 #ifdef DS_sig
     DS_sig(sigcontext) = ds64_sel;
@@ -1607,7 +1619,7 @@ __ASM_GLOBAL_FUNC( call_user_mode_callback,
                    "movq %rsp,0x328(%r8)\n\t"  /* amd64_thread_data()->syscall_frame */
                    /* switch to user stack */
                    "movq %rdi,%rsp\n\t"        /* user_rsp */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"       /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw 0x338(%r8),%fs\n"     /* amd64_thread_data()->fs */
@@ -2207,6 +2219,7 @@ static void usr1_handler( int signal, siginfo_t *sigin
  *           LDT support
  */
 
+//TODO: machdep.max_ldt_segment?
 #define LDT_SIZE 8192
 
 #define LDT_FLAGS_DATA      0x13  /* Data segment */
@@ -2264,6 +2277,16 @@ static void ldt_set_entry( WORD sel, LDT_ENTRY entry )
 
 #if defined(__APPLE__)
     if (i386_set_ldt(index, (union ldt_entry *)&entry, 1) < 0) perror("i386_set_ldt");
+#elif defined(__FreeBSD__)
+    struct i386_ldt_args p;
+    p.start = index;
+    p.descs = (struct user_segment_descriptor *)&entry;
+    p.num   = 1;
+    if (sysarch(I386_SET_LDT, &p) == -1)
+    {
+        perror("i386_set_ldt");
+        exit(1);
+    }
 #else
     fprintf( stderr, "No LDT support on this platform\n" );
     exit(1);
@@ -2412,7 +2435,44 @@ static void *mac_thread_gsbase(void)
 }
 #endif
 
+#ifdef __FreeBSD__
+static __siginfohandler_t *libthr_signal_handlers[_SIG_MAXSIG];
 
+static void libthr_sighandler_wrapper(int sig, siginfo_t *info, void *_ucp) {
+    struct ntdll_thread_data *thread_data;
+
+    /* FreeBSD will restore %fs */
+    assert(rfs() == GSEL(GUFS32_SEL, SEL_UPL));
+
+    /* and lower 32 bits of fsbase, which is not that useful for us */
+    thread_data = (struct ntdll_thread_data *)&get_current_teb()->GdiTebBatch;
+    amd64_set_fsbase(((struct amd64_thread_data *)thread_data->cpu_data)->pthread_teb);
+
+    libthr_signal_handlers[sig - 1](sig, info, _ucp);
+}
+
+extern int __sys_sigaction(int, const struct sigaction * restrict, struct sigaction * restrict);
+
+static int wrap_libthr_signal_handlers(void) {
+    struct sigaction act;
+    int sig;
+
+    for (sig = 1; sig <= _SIG_MAXSIG; sig++) {
+
+        if (__sys_sigaction(sig, NULL, &act) == -1) return -1;
+        if (act.sa_sigaction != NULL) {
+
+            libthr_signal_handlers[sig - 1] = act.sa_sigaction;
+            act.sa_sigaction = libthr_sighandler_wrapper;
+
+            if (__sys_sigaction(sig, &act, NULL) == -1) return -1;
+        }
+    }
+
+    return 0;
+}
+#endif
+
 /**********************************************************************
  *		signal_init_process
  */
@@ -2475,6 +2535,42 @@ void signal_init_process(void)
             break;
         }
     }
+#elif defined(__FreeBSD__)
+    if (wow_teb)
+    {
+        u_int p[4];
+        u_int cpu_stdext_feature;
+
+        LDT_ENTRY fs32_entry = ldt_make_entry(wow_teb, page_size - 1, LDT_FLAGS_DATA | LDT_FLAGS_32BIT);
+
+        cs32_sel = GSEL(GUCODE32_SEL, SEL_UPL);
+
+        amd64_thread_data()->fs = LSEL(first_ldt_entry, SEL_UPL);
+        ldt_set_entry(amd64_thread_data()->fs, fs32_entry);
+
+        syscall_flags |= SYSCALL_HAVE_PTHREAD_TEB;
+
+        do_cpuid(0, p);
+        if (p[0] >= 7)
+        {
+            cpuid_count(7, 0, p);
+            cpu_stdext_feature = p[1];
+        }
+        else
+        {
+            cpu_stdext_feature = 0;
+        }
+
+        if (cpu_stdext_feature & CPUID_STDEXT_FSGSBASE)
+        {
+            syscall_flags |= SYSCALL_HAVE_WRFSGSBASE;
+            fprintf(stderr, "CPU supports wrfsbase\n");
+        }
+        else
+        {
+            fprintf(stderr, "CPU doesn't support wrfsbase\n");
+        }
+    }
 #endif
 
     sig_act.sa_mask = server_block_set;
@@ -2496,6 +2592,9 @@ void signal_init_process(void)
     if (sigaction( SIGSEGV, &sig_act, NULL ) == -1) goto error;
     if (sigaction( SIGILL, &sig_act, NULL ) == -1) goto error;
     if (sigaction( SIGBUS, &sig_act, NULL ) == -1) goto error;
+#ifdef __FreeBSD__
+    if (wrap_libthr_signal_handlers() == -1) goto error;
+#endif
     return;
 
  error:
@@ -2522,8 +2621,9 @@ void call_init_thunk( LPTHREAD_START_ROUTINE entry, vo
     arch_prctl( ARCH_SET_GS, teb );
     arch_prctl( ARCH_GET_FS, &thread_data->pthread_teb );
     if (fs32_sel) alloc_fs_sel( fs32_sel >> 3, get_wow_teb( teb ));
-#elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
-    amd64_set_gsbase( teb );
+#elif defined(__FreeBSD__)
+    amd64_set_gsbase(teb);
+    amd64_get_fsbase(&thread_data->pthread_teb);
 #elif defined(__NetBSD__)
     sysarch( X86_64_SET_GSBASE, &teb );
 #elif defined (__APPLE__)
@@ -2630,7 +2730,6 @@ __ASM_GLOBAL_FUNC( signal_start_thread,
                    "1:\tmovq %r8,%rsp\n\t"
                    "call " __ASM_NAME("call_init_thunk"))
 
-
 /***********************************************************************
  *           __wine_syscall_dispatcher
  */
@@ -2745,6 +2844,46 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                    "leaq -0x98(%rbp),%rcx\n"
                    "2:\n\t"
 #endif
+#ifdef __FreeBSD__
+                   "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 2f\n\t"
+                   "movq $0x13,%rsi\n\t"           /* GSEL(GUFS32_SEL, SEL_UPL) */
+                   "movq %rsi,%fs\n\t"
+                   "movq %gs:0x320,%rsi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "testl $8,%r14d\n\t"            /* SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 1f\n\t"
+                   "wrfsbase %rsi\n\t"
+                   "jmp 2f\n"
+                   "1:\n\t"
+# ifdef USE_AMD64_SET_FSBASE_FUNC
+                   "pushq %rax\n\t"
+                   "pushq %rcx\n\t"
+                   "pushq %rdx\n\t"
+                   "pushq %rdi\n\t"
+                   "pushq %r8\n\t"
+                   "pushq %r9\n\t"
+                   "pushq %r10\n\t"
+                   "pushq %r11\n\t"
+                   "movq %rsi,%rdi\n\t"
+                   "callq amd64_set_fsbase\n\t"
+                   "popq %r11\n\t"
+                   "popq %r10\n\t"
+                   "popq %r9\n\t"
+                   "popq %r8\n\t"
+                   "popq %rdi\n\t"
+                   "popq %rdx\n\t"
+                   "popq %rcx\n\t"
+                   "popq %rax\n\t"
+# else
+                   "pushq %r10\n\t"                /* TODO: what's this? */
+                   "mov $0xa5,%rax\n\t"            /* sysarch */
+                   "mov $0x81,%rdi\n\t"            /* AMD64_SET_FSBASE */
+                   "syscall\n\t"
+                   "leaq -0x98(%rbp),%rcx\n"
+                   "popq %r10\n\t"
+# endif
+                   "2:\n\t"
+#endif
                    "movq 0x00(%rcx),%rax\n\t"
                    "movq 0x18(%rcx),%r11\n\t"      /* 2nd argument */
                    "movl %eax,%ebx\n\t"
@@ -2823,12 +2962,17 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                    "movq 0x20(%rcx),%rsi\n\t"
                    "movq 0x08(%rcx),%rbx\n\t"
                    "leaq 0x70(%rcx),%rsp\n\t"      /* %rsp > frame means no longer inside syscall */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
                    "1:\n\t"
 #endif
+#ifdef __FreeBSD__
+                   /* reset %ss (after sysret) for AMD */
+                   "movw $0x3b,%r14w\n\t"          /* GSEL(GUDATA_SEL, SEL_UPL) */
+                   "movw %r14w,%ss\n\t"
+#endif
                    "movq 0x60(%rcx),%r14\n\t"
                    "testl $0x3,%edx\n\t"           /* CONTEXT_CONTROL | CONTEXT_INTEGER */
                    "jnz 1f\n\t"
@@ -2957,6 +3101,46 @@ __ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                    "syscall\n\t"
                    "2:\n\t"
 #endif
+#ifdef __FreeBSD__
+                   "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 2f\n\t"
+                   "movq $0x13,%rsi\n\t"           /* GSEL(GUFS32_SEL, SEL_UPL) */
+                   "movq %rsi,%fs\n\t"
+                   "movq %gs:0x320,%rsi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "testl $8,%r14d\n\t"            /* SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 1f\n\t"
+                   "wrfsbase %rsi\n\t"
+                   "jmp 2f\n"
+                   "1:\n\t"
+# ifdef USE_AMD64_SET_FSBASE_FUNC
+                   "pushq %rax\n\t"
+                   "pushq %rcx\n\t"
+                   "pushq %rdx\n\t"
+                   "pushq %rdi\n\t"
+                   "pushq %r8\n\t"
+                   "pushq %r9\n\t"
+                   "pushq %r10\n\t"
+                   "pushq %r11\n\t"
+                   "movq %rsi,%rdi\n\t"
+                   "callq amd64_set_fsbase\n\t"
+                   "popq %r11\n\t"
+                   "popq %r10\n\t"
+                   "popq %r9\n\t"
+                   "popq %r8\n\t"
+                   "popq %rdi\n\t"
+                   "popq %rdx\n\t"
+                   "popq %rcx\n\t"
+                   "popq %rax\n\t"
+# else
+                   "pushq %r10\n\t"                /* TODO: what's this? */
+                   "mov $0xa5,%rax\n\t"            /* sysarch */
+                   "mov $0x81,%rdi\n\t"            /* AMD64_SET_FSBASE */
+                   "syscall\n\t"
+                   "leaq -0x98(%rbp),%rcx\n"
+                   "popq %r10\n\t"
+# endif
+                   "2:\n\t"
+#endif
                    "movq %r8,%rdi\n\t"             /* args */
                    "callq *(%r10,%rdx,8)\n\t"
                    "movq %rsp,%rcx\n\t"
@@ -2975,11 +3159,16 @@ __ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                    /* switch to user stack */
                    "movq 0x88(%rcx),%rsp\n\t"
                    __ASM_CFI(".cfi_restore_state\n\t")
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
                    "1:\n\t"
+#endif
+#ifdef __FreeBSD__
+                   /* reset %ss (after sysret) for AMD */
+                   "movw $0x3b,%r14w\n\t"          /* GSEL(GUDATA_SEL, SEL_UPL) */
+                   "movw %r14w,%ss\n\t"
 #endif
                    "movq 0x60(%rcx),%r14\n\t"
                    "movq 0x28(%rcx),%rdi\n\t"
