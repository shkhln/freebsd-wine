--- dlls/winepulse.drv/pulse.c.orig	2025-11-06 09:54:15 UTC
+++ dlls/winepulse.drv/pulse.c
@@ -896,7 +896,7 @@ static NTSTATUS pulse_test_connect(void *args)
 
     pulse_unlock();
 
-    params->priority = Priority_Preferred;
+    params->priority = Priority_Neutral;
     return STATUS_SUCCESS;
 
 fail:
