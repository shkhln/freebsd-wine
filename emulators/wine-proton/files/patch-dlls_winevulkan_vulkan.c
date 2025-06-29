--- dlls/winevulkan/vulkan.c.orig
+++ dlls/winevulkan/vulkan.c
@@ -29,6 +29,7 @@
 #include <stdio.h>
 #include <assert.h>
 #include <limits.h>
+#include <pthread_np.h>
 #ifdef HAVE_SYS_SYSCALL_H
 # include <sys/syscall.h>
 #endif
@@ -3547,11 +3547,7 @@
 
 void *signaller_worker(void *arg)
 {
-#ifdef HAVE_SYS_SYSCALL_H
-    int unix_tid = syscall( __NR_gettid );
-#else
-    int unix_tid = -1;
-#endif
+    int unix_tid = pthread_getthreadid_np();
     struct vulkan_device *device = arg;
     struct wine_semaphore *sem;
     VkSemaphoreWaitInfo wait_info = { 0 };
