#ifndef __DRIVER_LOADER_H__
#define __DRIVER_LOADER_H__

#include <wdm.h>

#ifndef __WXP
#define __WXP
#endif

extern PDRIVER_OBJECT MainDriverObject;

typedef NTSTATUS (__stdcall *PDEVICE_DISPATCH_ROUTINE)(__in PDEVICE_OBJECT DeviceObject,
													   __in PIRP Irp);

NTSTATUS RegisterDeviceDispatchRoutine(__in PDEVICE_OBJECT DeviceObject,
									   __in PDEVICE_DISPATCH_ROUTINE DispatchFunction);

//
//	If you want to unregister device dispatch routine,must clean resource about 
//	the device yourself.
//
VOID UnregisterDeviceDispatchRoutine(__in PDEVICE_OBJECT DeviceObject);


#endif // __DRIVER_LOADER_H__