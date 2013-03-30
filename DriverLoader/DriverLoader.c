#include <ntifs.h>
#include <wdm.h>
#include <fltKernel.h>
#include "DriverLoader.h"
#include "Loader.h"

FLT_OPERATION_REGISTRATION FilterOpRegistrration[] = {{ IRP_MJ_OPERATION_END }};

FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	FilterOpRegistrration,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject,__in PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status;
	PFLT_FILTER FltFilter;
	UNICODE_STRING FilePath;
	
	//
	//	Just Load FltMgr.
	//
	Status = FltRegisterFilter(DriverObject,&FilterRegistration,&FltFilter);
	if (NT_SUCCESS(Status))
	{
		FltUnregisterFilter(FltFilter);
	}

	RtlInitUnicodeString(&FilePath,L"\\??\\C:\\vtio.sys");
	Status = LoadDriver(&FilePath,RegistryPath);
	return Status;
}