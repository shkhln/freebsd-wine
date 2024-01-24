--- dlls/ntdll/unix/signal_x86_64.c.orig	2024-01-06 00:20:29.000000000 +0300
+++ dlls/ntdll/unix/signal_x86_64.c	2024-01-24 21:34:25.882892000 +0300
@@ -18,6 +18,9 @@
  * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
  */
 
+#define USE_FS
+#define USE_FSBASE
+
 #if 0
 #pragma makedep unix
 #endif
@@ -441,6 +444,9 @@ struct amd64_thread_data
     struct syscall_frame *syscall_frame; /* 0328 syscall frame pointer */
     SYSTEM_SERVICE_TABLE *syscall_table; /* 0330 syscall table */
     DWORD                 fs;            /* 0338 WOW TEB selector */
+#ifdef USE_FS
+    DWORD                 unix_fs;
+#endif
 };
 
 C_ASSERT( sizeof(struct amd64_thread_data) <= sizeof(((struct ntdll_thread_data *)0)->cpu_data) );
@@ -448,13 +454,16 @@ C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( str
 C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct amd64_thread_data, syscall_frame ) == 0x328 );
 C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct amd64_thread_data, syscall_table ) == 0x330 );
 C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct amd64_thread_data, fs ) == 0x338 );
+#ifdef USE_FS
+C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct amd64_thread_data, unix_fs ) == 0x33c );
+#endif
 
 static inline struct amd64_thread_data *amd64_thread_data(void)
 {
     return (struct amd64_thread_data *)ntdll_get_thread_data()->cpu_data;
 }
 
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
 static inline TEB *get_current_teb(void)
 {
     unsigned long rsp;
@@ -825,6 +834,19 @@ static inline ucontext_t *init_handler( void *sigconte
         arch_prctl( ARCH_SET_FS, ((struct amd64_thread_data *)thread_data->cpu_data)->pthread_teb );
     }
 #endif
+#ifdef __FreeBSD__
+    if (fs32_sel)
+    {
+        struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&get_current_teb()->GdiTebBatch;
+#ifdef USE_FS
+        USHORT sel = (USHORT)(((struct amd64_thread_data *)thread_data->cpu_data)->unix_fs);
+        __asm__ volatile("movw %0,%%fs" :: "r" (sel));
+#endif
+#ifdef USE_FSBASE
+        amd64_set_fsbase(((struct amd64_thread_data *)thread_data->cpu_data)->pthread_teb);
+#endif
+    }
+#endif
     return sigcontext;
 }
 
@@ -834,7 +856,7 @@ static inline ucontext_t *init_handler( void *sigconte
  */
 static inline void leave_handler( ucontext_t *sigcontext )
 {
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
     if (fs32_sel && !is_inside_signal_stack( (void *)RSP_sig(sigcontext )) && !is_inside_syscall(sigcontext))
         __asm__ volatile( "movw %0,%%fs" :: "r" (fs32_sel) );
 #endif
@@ -1598,7 +1620,7 @@ __ASM_GLOBAL_FUNC( call_user_mode_callback,
                    "movq %rsp,0x328(%r8)\n\t"  /* amd64_thread_data()->syscall_frame */
                    /* switch to user stack */
                    "movq %rdi,%rsp\n\t"        /* user_rsp */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"       /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw 0x338(%r8),%fs\n"     /* amd64_thread_data()->fs */
@@ -2174,6 +2196,7 @@ static void usr1_handler( int signal, siginfo_t *sigin
  *           LDT support
  */
 
+//TODO: machdep.max_ldt_segment?
 #define LDT_SIZE 8192
 
 #define LDT_FLAGS_DATA      0x13  /* Data segment */
@@ -2231,6 +2254,16 @@ static void ldt_set_entry( WORD sel, LDT_ENTRY entry )
 
 #if defined(__APPLE__)
     if (i386_set_ldt(index, (union ldt_entry *)&entry, 1) < 0) perror("i386_set_ldt");
+#elif defined(__FreeBSD__)
+  	struct i386_ldt_args p;
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
@@ -2299,6 +2332,7 @@ NTSTATUS signal_alloc_thread( TEB *teb )
             server_leave_uninterrupted_section( &ldt_mutex, &sigset );
             if (idx == LDT_SIZE) return STATUS_TOO_MANY_THREADS;
             thread_data->fs = (idx << 3) | 7;
+            //~ fs32_sel = thread_data->fs; // ?
         }
         else thread_data->fs = fs32_sel;
     }
@@ -2378,7 +2412,6 @@ static void *mac_thread_gsbase(void)
 }
 #endif
 
-
 /**********************************************************************
  *		signal_init_process
  */
@@ -2414,7 +2447,7 @@ void signal_init_process(void)
         }
         else ERR_(seh)( "failed to allocate %%fs selector\n" );
     }
-#elif defined(__APPLE__)
+#elif defined(__APPLE__) || defined(__FreeBSD__)
     if (wow_teb)
     {
         LDT_ENTRY cs32_entry, fs32_entry;
@@ -2438,6 +2471,10 @@ void signal_init_process(void)
             ldt_set_entry( amd64_thread_data()->fs, fs32_entry );
             break;
         }
+#ifdef __FreeBSD__
+        //~ fs32_sel = amd64_thread_data()->fs;
+        syscall_flags |= SYSCALL_HAVE_PTHREAD_TEB;
+#endif
     }
 #endif
 
@@ -2484,8 +2521,16 @@ void call_init_thunk( LPTHREAD_START_ROUTINE entry, vo
     arch_prctl( ARCH_SET_GS, teb );
     arch_prctl( ARCH_GET_FS, &thread_data->pthread_teb );
     if (fs32_sel) alloc_fs_sel( fs32_sel >> 3, get_wow_teb( teb ));
-#elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
-    amd64_set_gsbase( teb );
+#elif defined(__FreeBSD__)
+    amd64_set_gsbase(teb);
+# ifdef USE_FS
+    USHORT fs;
+    __asm__ volatile ("movw %%fs,%0" : "=r" (fs));
+    thread_data->unix_fs = fs;
+# endif
+# ifdef USE_FSBASE
+    amd64_get_fsbase(&thread_data->pthread_teb);
+# endif
 #elif defined(__NetBSD__)
     sysarch( X86_64_SET_GSBASE, &teb );
 #elif defined (__APPLE__)
@@ -2588,7 +2633,6 @@ __ASM_GLOBAL_FUNC( signal_start_thread,
                    "1:\tmovq %r8,%rsp\n\t"
                    "call " __ASM_NAME("call_init_thunk"))
 
-
 /***********************************************************************
  *           __wine_syscall_dispatcher
  */
@@ -2632,7 +2676,11 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                    __ASM_CFI_REG_IS_AT2(rbp, rcx, 0x98, 0x01)
                    /* Legends of Runeterra hooks the first system call return instruction, and
                     * depends on us returning to it. Adjust the return address accordingly. */
+#ifndef __FreeBSD__
                    "subq $0xb,0x70(%rcx)\n\t"
+#else
+                   "subq $0xe,0x70(%rcx)\n\t" // "jmp 1f" = e9 01 00 00 00
+#endif
                    "movl 0xb0(%rcx),%r14d\n\t"     /* frame->syscall_flags */
                    "testl $3,%r14d\n\t"            /* SYSCALL_HAVE_XSAVE | SYSCALL_HAVE_XSAVEC */
                    "jz 2f\n\t"
@@ -2696,6 +2744,27 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                    "leaq -0x98(%rbp),%rcx\n"
                    "2:\n\t"
 #endif
+#ifdef __FreeBSD__
+                   "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 2f\n\t"
+
+# ifdef USE_FS
+                   "movw %gs:0x33c,%fs\n\t"        /* amd64_thread_data()->unix_fs */
+# endif
+# ifdef USE_FSBASE
+#  if USE_AMD64_SET_FSBASE_FUNC
+                   "pushq %rcx\n\t"
+                   "movq %gs:0x320,%rdi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "callq amd64_set_fsbase\n\t"
+                   "popq %rcx\n\t"
+
+#  else
+                   "movq %gs:0x320,%rsi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "wrfsbase %rsi\n\t"
+#  endif
+# endif
+                   "2:\n\t"
+#endif
                    "movq 0x00(%rcx),%rax\n\t"
                    "movq 0x18(%rcx),%r11\n\t"      /* 2nd argument */
                    "movl %eax,%ebx\n\t"
@@ -2768,7 +2837,7 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                    "movq 0x20(%rcx),%rsi\n\t"
                    "movq 0x08(%rcx),%rbx\n\t"
                    "leaq 0x70(%rcx),%rsp\n\t"      /* %rsp > frame means no longer inside syscall */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
@@ -2902,6 +2971,23 @@ __ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                    "syscall\n\t"
                    "2:\n\t"
 #endif
+#ifdef __FreeBSD__
+                   "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 2f\n\t"
+# ifdef USE_FS
+                   "movw %gs:0x33c,%fs\n\t"        /* amd64_thread_data()->unix_fs */
+# endif
+# ifdef USE_FSBASE
+#  if USE_AMD64_SET_FSBASE_FUNC
+                   "movq %gs:0x320,%rdi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "callq amd64_set_fsbase\n\t"
+#  else
+                   "movq %gs:0x320,%rsi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "wrfsbase %rsi\n\t"
+#  endif
+# endif
+                   "2:\n\t"
+#endif
                    "movq %r8,%rdi\n\t"             /* args */
                    "callq *(%r10,%rdx,8)\n\t"
                    "movq %rsp,%rcx\n\t"
@@ -2920,7 +3006,7 @@ __ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                    /* switch to user stack */
                    "movq 0x88(%rcx),%rsp\n\t"
                    __ASM_CFI(".cfi_restore_state\n\t")
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
