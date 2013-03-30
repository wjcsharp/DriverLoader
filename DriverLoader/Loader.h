#ifndef __LOADER_H__
#define __LOADER_H__

#include <wdm.h>
#include "ntimage.h"

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

extern NTSTATUS ZwQuerySystemInformation (__in ULONG SystemInformationClass,
										  __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
										  __in ULONG SystemInformationLength,
										  __out_opt PULONG ReturnLength);

extern PIMAGE_NT_HEADERS RtlImageNtHeader(__in PVOID Base);

extern NTSTATUS ObInsertObject (__in PVOID Object,
								__in PACCESS_STATE PassedAccessState OPTIONAL,
								__in ACCESS_MASK DesiredAccess,
								__in ULONG AdditionalReferences,
								__out PVOID *ReferencedObject OPTIONAL,
								__out PHANDLE Handle);

extern NTSTATUS ObCreateObject (__in KPROCESSOR_MODE ObjectAttributesAccessMode OPTIONAL,
								__in POBJECT_TYPE ObjectType,
								__in POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
								__in KPROCESSOR_MODE AccessMode,
								__in PVOID Reserved,
								__in ULONG ObjectSizeToAllocate,
								__in ULONG PagedPoolCharge OPTIONAL,
								__in ULONG NonPagedPoolCharge OPTIONAL,
								__out PVOID *Object);

extern POBJECT_TYPE *IoDriverObjectType;

extern PVOID RtlImageDirectoryEntryToData(__in PVOID BaseOfImage,
										  __in BOOLEAN MappedAsImage,
										  __in USHORT DirectoryEntry,
										  __in PULONG Size);

//
//	Call LoadDriver must in the context of system process.
//	And if the driver that is loaded import other Module,like FltMgr,
//	You must import FltMgr in the loader driver.Because FltMgr maybe unload.
//  So that will cause BSOD!
//
NTSTATUS LoadDriver(__in PUNICODE_STRING FilePath,
					__in PUNICODE_STRING ServiceKeyPath);

#endif // __LOADER_H__