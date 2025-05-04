--- dlls/ntdll/unix/signal_x86_64.c.orig	2025-05-04 02:36:40.688134000 +0300
+++ dlls/ntdll/unix/signal_x86_64.c	2025-05-04 21:37:03.756479000 +0300
@@ -152,6 +152,9 @@
 
 #elif defined(__FreeBSD__) || defined (__FreeBSD_kernel__)
 
+#include <machine/cpufunc.h>
+#include <machine/segments.h>
+#include <machine/specialreg.h>
 #include <machine/trap.h>
 
 #define RAX_sig(context)     ((context)->uc_mcontext.mc_rax)
@@ -470,7 +473,7 @@
     return (struct amd64_thread_data *)ntdll_get_thread_data()->cpu_data;
 }
 
-#if defined(__linux__) || defined(__APPLE__)
+#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
 static inline TEB *get_current_teb(void)
 {
     unsigned long rsp;
@@ -1647,7 +1650,7 @@
                    "movq %rsp,0x328(%r8)\n\t"  /* amd64_thread_data()->syscall_frame */
                    /* switch to user stack */
                    "movq %rdi,%rsp\n\t"        /* user_rsp */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $4,%r14d\n\t"        /* SYSCALL_HAVE_PTHREAD_TEB */
                    "jz 1f\n\t"
                    "movw 0x338(%r8),%fs\n"     /* amd64_thread_data()->fs */
@@ -2373,6 +2376,16 @@
 
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
@@ -2483,7 +2496,44 @@
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
@@ -2546,6 +2596,42 @@
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
@@ -2571,6 +2657,9 @@
     sig_act.sa_sigaction = sigsys_handler;
     if (sigaction( SIGSYS, &sig_act, NULL ) == -1) goto error;
 #endif
+#ifdef __FreeBSD__
+    if (wrap_libthr_signal_handlers() == -1) goto error;
+#endif
     return;
 
  error:
@@ -2600,7 +2689,8 @@
     arch_prctl( ARCH_GET_FS, &thread_data->pthread_teb );
     if (fs32_sel) alloc_fs_sel( fs32_sel >> 3, get_wow_teb( teb ));
 #elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
-    amd64_set_gsbase( teb );
+    amd64_set_gsbase(teb);
+    amd64_get_fsbase(&thread_data->pthread_teb);
 #elif defined(__NetBSD__)
     sysarch( X86_64_SET_GSBASE, &teb );
 #elif defined (__APPLE__)
@@ -2817,6 +2907,25 @@
                    "syscall\n\t"
                    "leaq -0x98(%rbp),%rcx\n"
                    "2:\n\t"
+#elif defined(__FreeBSD__)
+                   "testl $4,%r14d\n\t"            /* SYSCALL_HAVE_PTHREAD_TEB */
+                   "jz 2f\n\t"
+                   "movq $0x13,%rsi\n\t"           /* GSEL(GUFS32_SEL, SEL_UPL) */
+                   "movq %rsi,%fs\n\t"
+                   "movq 0xb8(%rcx),%rsi\n\t"      /* frame->teb */
+                   "movq 0x320(%rsi),%rsi\n\t"     /* amd64_thread_data()->pthread_teb */
+                   "testl $8,%r14d\n\t"            /* SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 1f\n\t"
+                   "wrfsbase %rsi\n\t"
+                   "jmp 2f\n"
+                   "1:\n\t"
+                   "pushq %r10\n\t"                /* TODO: what's this? */
+                   "mov $0xa5,%rax\n\t"            /* sysarch */
+                   "mov $0x81,%rdi\n\t"            /* AMD64_SET_FSBASE */
+                   "syscall\n\t"
+                   "leaq -0x98(%rbp),%rcx\n"
+                   "popq %r10\n\t"
+                   "2:\n\t"
 #elif defined __APPLE__
                    "movq 0xb8(%rcx),%rdi\n\t"      /* frame->teb */
                    "movq 0x320(%rdi),%rdi\n\t"     /* amd64_thread_data()->pthread_teb */
@@ -2861,7 +2970,7 @@
                    __ASM_CFI(".cfi_remember_state\n\t")
                    __ASM_CFI_CFA_IS_AT2(rcx, 0xa8, 0x01) /* frame->syscall_cfa */
                    "leaq 0x70(%rcx),%rsp\n\t"      /* %rsp > frame means no longer inside syscall */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $4,%r14d\n\t"            /* SYSCALL_HAVE_PTHREAD_TEB */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
@@ -2876,6 +2985,12 @@
                    "movq %rdx,%rcx\n\t"
                    "movq %r8,%rax\n\t"
 #endif
+#ifdef __FreeBSD__
+                   /* reset %ss (after sysret) for AMD */
+                   "movw $0x3b,%r14w\n\t"          /* GSEL(GUDATA_SEL, SEL_UPL) */
+                   "movw %r14w,%ss\n\t"
+#endif
+
                    "movl 0xb4(%rcx),%edx\n\t"      /* frame->restore_flags */
                    "testl $0x48,%edx\n\t"          /* CONTEXT_FLOATING_POINT | CONTEXT_XSTATE */
                    "jnz 2f\n\t"
@@ -3066,6 +3181,23 @@
                    "mov $158,%eax\n\t"             /* SYS_arch_prctl */
                    "syscall\n\t"
                    "2:\n\t"
+#elif defined(__FreeBSD__)
+                   "testl $4,%r14d\n\t"            /* SYSCALL_HAVE_PTHREAD_TEB */
+                   "jz 2f\n\t"
+                   "movq $0x13,%rsi\n\t"           /* GSEL(GUFS32_SEL, SEL_UPL) */
+                   "movq %rsi,%fs\n\t"
+                   "movq %gs:0x320,%rsi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "testl $8,%r14d\n\t"            /* SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 1f\n\t"
+                   "wrfsbase %rsi\n\t"
+                   "jmp 2f\n"
+                   "1:\n\t"
+                   "pushq %r10\n\t"                /* TODO: what's this? */
+                   "mov $0xa5,%rax\n\t"            /* sysarch */
+                   "mov $0x81,%rdi\n\t"            /* AMD64_SET_FSBASE */
+                   "syscall\n\t"
+                   "popq %r10\n\t"
+                   "2:\n\t"
 #elif defined __APPLE__
                    "movq %gs:0x320,%rdi\n\t"       /* amd64_thread_data()->pthread_teb */
                    "xorl %esi,%esi\n\t"
@@ -3090,7 +3222,7 @@
                    /* switch to user stack */
                    "movq 0x88(%rcx),%rsp\n\t"
                    __ASM_CFI(".cfi_restore_state\n\t")
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $4,%r14d\n\t"            /* SYSCALL_HAVE_PTHREAD_TEB */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
@@ -3105,6 +3237,12 @@
                    "movq %r14,%rcx\n\t"
                    "movq %rdx,%rax\n\t"
 #endif
+#ifdef __FreeBSD__
+                   /* reset %ss (after sysret) for AMD */
+                   "movw $0x3b,%r14w\n\t"          /* GSEL(GUDATA_SEL, SEL_UPL) */
+                   "movw %r14w,%ss\n\t"
+#endif
+
                    "movq 0x60(%rcx),%r14\n\t"
                    "movq 0x28(%rcx),%rdi\n\t"
                    "movq 0x20(%rcx),%rsi\n\t"
