--- dlls/ntdll/unix/virtual.c.orig	2024-02-26 16:56:44.811724000 +0300
+++ dlls/ntdll/unix/virtual.c	2024-02-26 16:57:06.081740000 +0300
@@ -1954,6 +1954,12 @@ failed:
     {
         ERR( "out of memory for %p-%p\n", base, (char *)base + size );
         status = STATUS_NO_MEMORY;
+        if ((uintptr_t)base == 0x400000)
+        {
+            char buf[100];
+            snprintf(buf, sizeof(buf), "procstat -v %d", getpid());
+            system(buf);
+        }
     }
     else if (errno == EEXIST) status = STATUS_CONFLICTING_ADDRESSES;
     else
