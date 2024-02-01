--- dlls/wow64cpu/cpu.c.orig	2024-01-25 16:39:19.964476000 +0300
+++ dlls/wow64cpu/cpu.c	2024-02-01 22:55:09.329013000 +0300
@@ -207,6 +207,10 @@ __ASM_GLOBAL_FUNC( syscall_32to64,
                    "movl %edx,4(%rsp)\n\t"
                    "movl 0xc4(%r13),%r14d\n\t"  /* context->Esp */
                    "xchgq %r14,%rsp\n\t"
+                   /* weird FreeBSD stuff */
+                   "movl $0x3b,%edx\n\t"        /* GSEL(GUDATA_SEL, SEL_UPL) */
+                   "movl %edx,%ss\n\t"
+                   /* ******************* */
                    "ljmp *(%r14)\n"
                    ".Lsyscall_32to64_return:\n\t"
                    "movq %rsp,%r14\n\t"
@@ -261,6 +265,10 @@ __ASM_GLOBAL_FUNC( unix_call_32to64,
                    "movl %edx,4(%rsp)\n\t"
                    "movl 0xc4(%r13),%r14d\n\t"  /* context->Esp */
                    "xchgq %r14,%rsp\n\t"
+                   /* weird FreeBSD stuff */
+                   "movl $0x3b,%edx\n\t"        /* GSEL(GUDATA_SEL, SEL_UPL) */
+                   "movl %edx,%ss\n\t"
+                   /* ******************* */
                    "ljmp *(%r14)" )
 
 
