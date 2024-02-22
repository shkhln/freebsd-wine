--- dlls/ntdll/unix/signal_x86_64.c.orig	2024-01-27 01:56:23.000000000 +0300
+++ dlls/ntdll/unix/signal_x86_64.c	2024-02-22 23:31:46.856586000 +0300
@@ -144,6 +144,8 @@ __ASM_GLOBAL_FUNC( alloc_fs_sel,
 
 #elif defined(__FreeBSD__) || defined (__FreeBSD_kernel__)
 
+#include <machine/cpufunc.h>
+#include <machine/segments.h>
 #include <machine/trap.h>
 
 #define RAX_sig(context)     ((context)->uc_mcontext.mc_rax)
@@ -454,7 +456,7 @@ static inline struct amd64_thread_data *amd64_thread_d
     return (struct amd64_thread_data *)ntdll_get_thread_data()->cpu_data;
 }
 
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
 static inline TEB *get_current_teb(void)
 {
     unsigned long rsp;
@@ -824,6 +826,25 @@ static inline ucontext_t *init_handler( void *sigconte
         struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&get_current_teb()->GdiTebBatch;
         arch_prctl( ARCH_SET_FS, ((struct amd64_thread_data *)thread_data->cpu_data)->pthread_teb );
     }
+#elif defined(__FreeBSD__)
+  struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&get_current_teb()->GdiTebBatch;
+  USHORT fs = ((struct amd64_thread_data *)thread_data->cpu_data)->fs;
+  assert(fs != GSEL(GUFS32_SEL, SEL_UPL));
+  if (fs != 0)
+  {
+      load_fs(GSEL(GUFS32_SEL, SEL_UPL));
+      amd64_set_fsbase(((struct amd64_thread_data *)thread_data->cpu_data)->pthread_teb);
+  }
+  else
+  {
+      uint64_t fsbase = rdfsbase();
+      uint64_t pthread_teb = ((struct amd64_thread_data *)thread_data->cpu_data)->pthread_teb;
+      if (fsbase != pthread_teb)
+      {
+          fprintf(stderr, "fs: %#x, fsbase: %#lx, pthread_teb: %#lx\n", fs, fsbase, pthread_teb);
+          abort();
+      }
+  }
 #endif
     return sigcontext;
 }
@@ -837,6 +858,13 @@ static inline void leave_handler( ucontext_t *sigconte
 #ifdef __linux__
     if (fs32_sel && !is_inside_signal_stack( (void *)RSP_sig(sigcontext )) && !is_inside_syscall(sigcontext))
         __asm__ volatile( "movw %0,%%fs" :: "r" (fs32_sel) );
+#elif defined(__FreeBSD__)
+    struct ntdll_thread_data *thread_data = (struct ntdll_thread_data *)&get_current_teb()->GdiTebBatch;
+    USHORT fs = ((struct amd64_thread_data *)thread_data->cpu_data)->fs;
+    if (fs != 0 && !is_inside_signal_stack((void *)RSP_sig(sigcontext)) && !is_inside_syscall(sigcontext))
+    {
+        load_fs(fs);
+    }
 #endif
 #ifdef DS_sig
     DS_sig(sigcontext) = ds64_sel;
@@ -1598,7 +1626,7 @@ __ASM_GLOBAL_FUNC( call_user_mode_callback,
                    "movq %rsp,0x328(%r8)\n\t"  /* amd64_thread_data()->syscall_frame */
                    /* switch to user stack */
                    "movq %rdi,%rsp\n\t"        /* user_rsp */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"       /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw 0x338(%r8),%fs\n"     /* amd64_thread_data()->fs */
@@ -2174,6 +2202,7 @@ static void usr1_handler( int signal, siginfo_t *sigin
  *           LDT support
  */
 
+//TODO: machdep.max_ldt_segment?
 #define LDT_SIZE 8192
 
 #define LDT_FLAGS_DATA      0x13  /* Data segment */
@@ -2231,6 +2260,16 @@ static void ldt_set_entry( WORD sel, LDT_ENTRY entry )
 
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
@@ -2378,7 +2417,6 @@ static void *mac_thread_gsbase(void)
 }
 #endif
 
-
 /**********************************************************************
  *		signal_init_process
  */
@@ -2439,6 +2477,18 @@ void signal_init_process(void)
             break;
         }
     }
+#elif defined(__FreeBSD__)
+    if (wow_teb)
+    {
+        LDT_ENTRY fs32_entry = ldt_make_entry(wow_teb, page_size - 1, LDT_FLAGS_DATA | LDT_FLAGS_32BIT);
+
+        cs32_sel = GSEL(GUCODE32_SEL, SEL_UPL);
+
+        amd64_thread_data()->fs = (first_ldt_entry << 3) | 7;
+        ldt_set_entry(amd64_thread_data()->fs, fs32_entry);
+
+        syscall_flags |= SYSCALL_HAVE_PTHREAD_TEB;
+    }
 #endif
 
     sig_act.sa_mask = server_block_set;
@@ -2484,8 +2534,9 @@ void call_init_thunk( LPTHREAD_START_ROUTINE entry, vo
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
@@ -2588,7 +2639,6 @@ __ASM_GLOBAL_FUNC( signal_start_thread,
                    "1:\tmovq %r8,%rsp\n\t"
                    "call " __ASM_NAME("call_init_thunk"))
 
-
 /***********************************************************************
  *           __wine_syscall_dispatcher
  */
@@ -2632,7 +2682,11 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
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
@@ -2696,6 +2750,23 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                    "leaq -0x98(%rbp),%rcx\n"
                    "2:\n\t"
 #endif
+#ifdef __FreeBSD__
+                   "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 2f\n\t"
+                   "movq $0x13,%rsi\n\t"           /* GSEL(GUFS32_SEL, SEL_UPL) */
+                   "movq %rsi,%fs\n\t"
+# if USE_AMD64_SET_FSBASE_FUNC
+                   "pushq %rcx\n\t"
+                   "movq %gs:0x320,%rdi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "callq amd64_set_fsbase\n\t"
+                   "popq %rcx\n\t"
+
+# else
+                   "movq %gs:0x320,%rsi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "wrfsbase %rsi\n\t"
+# endif
+                   "2:\n\t"
+#endif
                    "movq 0x00(%rcx),%rax\n\t"
                    "movq 0x18(%rcx),%r11\n\t"      /* 2nd argument */
                    "movl %eax,%ebx\n\t"
@@ -2768,7 +2839,7 @@ __ASM_GLOBAL_FUNC( __wine_syscall_dispatcher,
                    "movq 0x20(%rcx),%rsi\n\t"
                    "movq 0x08(%rcx),%rbx\n\t"
                    "leaq 0x70(%rcx),%rsp\n\t"      /* %rsp > frame means no longer inside syscall */
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
@@ -2902,6 +2973,20 @@ __ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                    "syscall\n\t"
                    "2:\n\t"
 #endif
+#ifdef __FreeBSD__
+                   "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
+                   "jz 2f\n\t"
+                   "movq $0x13,%rsi\n\t"           /* GSEL(GUFS32_SEL, SEL_UPL) */
+                   "movq %rsi,%fs\n\t"
+# if USE_AMD64_SET_FSBASE_FUNC
+                   "movq %gs:0x320,%rdi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "callq amd64_set_fsbase\n\t"
+# else
+                   "movq %gs:0x320,%rsi\n\t"       /* amd64_thread_data()->pthread_teb */
+                   "wrfsbase %rsi\n\t"
+# endif
+                   "2:\n\t"
+#endif
                    "movq %r8,%rdi\n\t"             /* args */
                    "callq *(%r10,%rdx,8)\n\t"
                    "movq %rsp,%rcx\n\t"
@@ -2920,7 +3005,7 @@ __ASM_GLOBAL_FUNC( __wine_unix_call_dispatcher,
                    /* switch to user stack */
                    "movq 0x88(%rcx),%rsp\n\t"
                    __ASM_CFI(".cfi_restore_state\n\t")
-#ifdef __linux__
+#if defined(__linux__) || defined(__FreeBSD__)
                    "testl $12,%r14d\n\t"           /* SYSCALL_HAVE_PTHREAD_TEB | SYSCALL_HAVE_WRFSGSBASE */
                    "jz 1f\n\t"
                    "movw %gs:0x338,%fs\n"          /* amd64_thread_data()->fs */
