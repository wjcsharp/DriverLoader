#include <wdm.h>
#include "DriverLoader.h"
#include "Loader.h"
#include "ldrreloc.h"

#ifndef DRVO_INITIALIZED
#define DRVO_INITIALIZED                0x00000010
#endif

NTSTATUS GetModuleBaseByName( __in char *Name,__out PVOID *ModuleBase )
{
	NTSTATUS Status;
	ULONG index = 0;
	BOOLEAN IsFind = FALSE;
	ULONG Length = PAGE_SIZE;
	UNICODE_STRING ModuleName;
	PRTL_PROCESS_MODULES Modules = NULL;
	PRTL_PROCESS_MODULE_INFORMATION ModuleInfo = NULL;

__retry:
	Modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool,Length);
	if (Modules == NULL)
	{
		return STATUS_NO_MEMORY;
	}

	RtlZeroMemory(Modules,PAGE_SIZE);
	Status = ZwQuerySystemInformation(SystemModuleInformation,Modules,Length,&Length);
	if (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		ExFreePool(Modules);
		goto __retry;
	}

	if (NT_SUCCESS(Status))
	{
		for (ModuleInfo = &Modules->Modules[0];index < Modules->NumberOfModules;index++,ModuleInfo++)
		{
			if (_stricmp(ModuleInfo->FullPathName + ModuleInfo->OffsetToFileName,Name) == 0)
			{
				IsFind = TRUE;
				*ModuleBase = ModuleInfo->ImageBase;
				break;
			}
		}
	}

	ExFreePool(Modules);
	if (!IsFind)
	{
		Status = STATUS_NOT_FOUND;
	}

	return Status;
}

unsigned short ChkSum(unsigned int CheckSum, void *FileBase, int Length)
{
	int *Data;
	int sum;

	if ( Length && FileBase != NULL)
	{
		Data = (int *)FileBase;
		do
		{
			sum = *(unsigned short *)Data + CheckSum;
			Data = (int *)((char *)Data + 2);
			CheckSum = (unsigned short)sum + (sum >> 16);
		}
		while ( --Length );
	}

	return CheckSum + (CheckSum >> 16);
}

unsigned int PECheckSum(void *FileBase, unsigned int FileSize)
{
	void *RemainData;
	int RemainDataSize;
	unsigned int PeHeaderSize;
	unsigned int HeaderCheckSum;	
	unsigned int PeHeaderCheckSum;
	unsigned int FileCheckSum;
	PIMAGE_NT_HEADERS NtHeaders;

	NtHeaders = RtlImageNtHeader(FileBase);
	if ( NtHeaders )
	{
		HeaderCheckSum = NtHeaders->OptionalHeader.CheckSum;
		PeHeaderSize = (unsigned int)NtHeaders - (unsigned int)FileBase + 
			((unsigned int)&NtHeaders->OptionalHeader.CheckSum - (unsigned int)NtHeaders);
		RemainDataSize = (FileSize - PeHeaderSize - 4) >> 1;
		RemainData = &NtHeaders->OptionalHeader.Subsystem;
		PeHeaderCheckSum = ChkSum(0, FileBase, PeHeaderSize >> 1);
		FileCheckSum = ChkSum(PeHeaderCheckSum,RemainData, RemainDataSize);

		if ( FileSize & 1 )
		{
			FileCheckSum += (unsigned short)*((char *)FileBase + FileSize - 1);
		}
	}
	else
	{
		FileCheckSum = 0;
	}

	return (FileSize + FileCheckSum);
}


BOOLEAN VerifyFile(__in PVOID ModuleBase,__in ULONG FileSize)
{
	unsigned int CheckSum;
	unsigned int NewCheckSum;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;

	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	NtHeaders = RtlImageNtHeader(ModuleBase);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	if ((NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) ||
		(NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)) 
	{
			return FALSE;
	}

	CheckSum = NtHeaders->OptionalHeader.CheckSum;
	NewCheckSum = PECheckSum(ModuleBase,FileSize);
	if (NewCheckSum != CheckSum)
	{
		return FALSE;
	}

	return TRUE;
}

PVOID GetProcAddressByName( __in PVOID ModuleBase,__in char *FunctionName )
{
	PVOID Func;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	PULONG Addr;
	ULONG ExportSize;
	LONG Low;
	LONG Middle;
	LONG High;
	LONG Result;
	USHORT OrdinalNumber;


	Func = NULL;

	//
	// Locate the DLL's export directory.
	//

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) RtlImageDirectoryEntryToData (ModuleBase,
																			  TRUE,
																			  IMAGE_DIRECTORY_ENTRY_EXPORT,
																			  &ExportSize);

	if (ExportDirectory) {

		NameTableBase =  (PULONG)((PCHAR)ModuleBase + (ULONG)ExportDirectory->AddressOfNames);
		NameOrdinalTableBase = (PUSHORT)((PCHAR)ModuleBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

		//
		// Look in the export name table for the specified function name.
		//

		Low = 0;
		Middle = 0;
		High = ExportDirectory->NumberOfNames - 1;

		while (High >= Low) {

			//
			// Compute the next probe index and compare the export name entry
			// with the specified function name.
			//

			Middle = (Low + High) >> 1;
			Result = strcmp(FunctionName,(PCHAR)((PCHAR)ModuleBase + NameTableBase[Middle]));

			if (Result < 0) {
				High = Middle - 1;
			}
			else if (Result > 0) {
				Low = Middle + 1;
			}
			else {
				break;
			}
		}

		//
		// If the high index is less than the low index, then a matching table
		// entry was not found.  Otherwise, get the ordinal number from the
		// ordinal table and location the function address.
		//

		if (High >= Low) {

			OrdinalNumber = NameOrdinalTableBase[Middle];
			Addr = (PULONG)((PCHAR)ModuleBase + (ULONG)ExportDirectory->AddressOfFunctions);
			Func = (PVOID)((ULONG_PTR)ModuleBase + Addr[OrdinalNumber]);

			//
			// If the function address is w/in range of the export directory,
			// then the function is forwarded, which is not allowed, so ignore
			// it.
			//

			if ((ULONG_PTR)Func > (ULONG_PTR)ExportDirectory &&
				(ULONG_PTR)Func < ((ULONG_PTR)ExportDirectory + ExportSize)) {
					Func = NULL;
			}
		}
	}

	return Func;
}

NTSTATUS FixImportTable( __in PVOID Base )
{
	NTSTATUS Status;
	char *ModuleName;
	ULONG *FunctionNameList;
	ULONG *FunctionAddressList;
	char *FunctionName;
	PVOID Function;
	PVOID ImportModuleBase;
	ULONG ImportDescriptorSize;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RtlImageDirectoryEntryToData(Base,
																									   TRUE,
																									   IMAGE_DIRECTORY_ENTRY_IMPORT,
																									   &ImportDescriptorSize);
	if (ImportDescriptor == NULL)
	{
		return STATUS_INVALID_IMAGE_FORMAT;;
	}

	while (ImportDescriptor->Name != 0)
	{
		ModuleName = (char *)Base + ImportDescriptor->Name;
		if (_stricmp(ModuleName,"ntoskrnl.exe") == 0)
		{
			Status = GetModuleBaseByName("wrkx86.exe",&ImportModuleBase);
		}
		else
		{
			Status = GetModuleBaseByName(ModuleName,&ImportModuleBase);
		}
		
		if (!NT_SUCCESS(Status))
		{
			return Status;
			break;
		}

		FunctionAddressList = (ULONG *)((char *)Base + ImportDescriptor->FirstThunk);

		if (ImportDescriptor->OriginalFirstThunk != NULL)
		{
			FunctionNameList = (ULONG *)((char *)Base + ImportDescriptor->OriginalFirstThunk);
		}
		else
		{
			FunctionNameList = (ULONG *)((char *)Base + ImportDescriptor->FirstThunk);
		}

		while (*FunctionNameList != 0)
		{
			//
			//	Check if if ORDINAL type,if true,stop process.
			//
			if (*FunctionNameList & IMAGE_ORDINAL_FLAG)
			{
				return STATUS_INVALID_IMAGE_FORMAT;
				break;
			}

			FunctionName = (char *)((char *)Base + *FunctionNameList + 2);
			Function = GetProcAddressByName(ImportModuleBase,FunctionName);
			if (Function == NULL)
			{
				return STATUS_INVALID_IMAGE_FORMAT;
				break;
			}

			*FunctionAddressList = (ULONG)Function;

			FunctionAddressList++;
			FunctionNameList++;
		}		

		ImportDescriptor++;
	}

	return STATUS_SUCCESS;
}

VOID IopReadyDeviceObject(__in PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

	DriverObject->Flags |= DRVO_INITIALIZED;

	while (DeviceObject != NULL)
	{
		DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
		DeviceObject = DeviceObject->NextDevice;
	}
}

NTSTATUS IopInvalidDeviceRequest(__in PDEVICE_OBJECT DeviceObject,__in PIRP Irp)
{
#ifdef __WXP

	if ((IoGetCurrentIrpStackLocation(Irp))->MajorFunction == IRP_MJ_POWER) {
		PoStartNextPowerIrp(Irp);
	}

#endif

	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS CreateDriverObject(__in PUNICODE_STRING ServiceKeyName,
							__in PVOID ImageBase)
{
	ULONG i;
    NTSTATUS Status;
	ULONG ObjectSize;
	HANDLE DriverHandle;
    PDRIVER_OBJECT DriverObject;    
	PIMAGE_NT_HEADERS NtHeaders;
	PDRIVER_INITIALIZE DriverInitRoutine;
	OBJECT_ATTRIBUTES objectAttributes;


    //
    // Attempt to create the driver object
    //

    InitializeObjectAttributes( &objectAttributes,
                                NULL,
                                OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                                NULL,
                                NULL );

    ObjectSize = sizeof( DRIVER_OBJECT ) + sizeof( DRIVER_EXTENSION );
    Status = ObCreateObject( KernelMode,
                             *IoDriverObjectType,
                             &objectAttributes,
                             KernelMode,
                             NULL,
                             ObjectSize,
                             0,
                             0,
                             &DriverObject );

    if( !NT_SUCCESS( Status )){

        //
        // Driver object creation failed
        //

        return Status;
    }

    //
    // We've created a driver object, initialize it.
    //

    RtlZeroMemory( DriverObject, ObjectSize );
    DriverObject->DriverExtension = (PDRIVER_EXTENSION)(DriverObject + 1);
    DriverObject->DriverExtension->DriverObject = DriverObject;
    DriverObject->Type = IO_TYPE_DRIVER;
    DriverObject->Size = sizeof( DRIVER_OBJECT );
    
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)IopInvalidDeviceRequest;
        
	//
	//	Get Start Entry point.
	//
	NtHeaders = RtlImageNtHeader(ImageBase);
	DriverInitRoutine = (PDRIVER_INITIALIZE)(NtHeaders->OptionalHeader.AddressOfEntryPoint + (char *)ImageBase);
    DriverObject->DriverInit = DriverInitRoutine;

	//
	//	The DriverSection will be Delete when unload driver.
	//	So,not fill the field.
	//
    //driverObject->DriverSection = DriverImageBase;
	//

    DriverObject->DriverStart = ImageBase;
    DriverObject->DriverSize = NtHeaders->OptionalHeader.SizeOfImage;

    //
    // Insert it into the object table.
    //

    Status = ObInsertObject( DriverObject,
                             NULL,
                             FILE_READ_DATA,
                             OBJ_KERNEL_HANDLE,
                             NULL,
                             &DriverHandle );

    if( !NT_SUCCESS( Status )){

        //
        // Couldn't insert the driver object into the table.
        // The object got dereferenced by the object manager. Just exit
        //

        goto errorReturn;
    }
    
    //
    // Reference the handle and obtain a pointer to the driver object so that
    // the handle can be deleted without the object going away.
    //

    Status = ObReferenceObjectByHandle( DriverHandle,
                                        0,
                                        *IoDriverObjectType,
                                        KernelMode,
                                        (PVOID *) &DriverObject,
                                        (POBJECT_HANDLE_INFORMATION) NULL );
    if( !NT_SUCCESS( Status )) {

       ZwClose( DriverHandle ); // Close the handle.
       goto errorReturn;
    }

    ZwClose( DriverHandle );

    //
    // Call the driver initialization routine
    //
	Status = DriverInitRoutine(DriverObject,ServiceKeyName);

	if (NT_SUCCESS(Status))
	{
		//
		//	Clear Driver object initialize flag and 
		//	device object initialize flag.
		//

		IopReadyDeviceObject(DriverObject);
	}
    
    if( !NT_SUCCESS( Status )){

errorFreeDriverObject:

        //
        // If we were unsuccessful, we need to get rid of the driverObject
        // that we created.
        //

        ObDereferenceObject( DriverObject );
    }
errorReturn:
    return Status;
}

NTSTATUS LoadImage(__in PUNICODE_STRING FilePath,__out PVOID *ImageBase)
{
	ULONG i;
	NTSTATUS Status;
	HANDLE FileHandle;
	PVOID NewModuleBase;
	IO_STATUS_BLOCK IoStatus;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_OPTIONAL_HEADER OptionalHeader;
	PIMAGE_SECTION_HEADER SectionHeader;
	FILE_STANDARD_INFORMATION FileStandardInfo;


	FileHandle = NULL;
	NewModuleBase = NULL;
	Status = STATUS_SUCCESS;

	__try
	{

		InitializeObjectAttributes(&ObjectAttributes,FilePath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);
		Status = ZwCreateFile(&FileHandle,
			GENERIC_ALL,
			&ObjectAttributes,
			&IoStatus,
			NULL,
			0,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		Status = ZwQueryInformationFile(FileHandle,&IoStatus,&FileStandardInfo,
			sizeof(FILE_STANDARD_INFORMATION),FileStandardInformation);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		NewModuleBase = ExAllocatePool(NonPagedPool,FileStandardInfo.EndOfFile.LowPart);
		if (NewModuleBase == NULL)
		{
			Status = STATUS_NO_MEMORY;
			__leave;
		}

		RtlZeroMemory(NewModuleBase,FileStandardInfo.EndOfFile.LowPart);
		Status = ZwReadFile(FileHandle,NULL,NULL,NULL,&IoStatus,
			NewModuleBase,FileStandardInfo.EndOfFile.LowPart,NULL,NULL);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		if (!VerifyFile(NewModuleBase,FileStandardInfo.EndOfFile.LowPart))
		{
			Status = STATUS_INVALID_IMAGE_FORMAT;
			__leave;
		}

		//
		//	Relocate section.
		//
		NtHeaders = RtlImageNtHeader(NewModuleBase);
		OptionalHeader = &NtHeaders->OptionalHeader;
		SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
		for (i = 0;i < NtHeaders->FileHeader.NumberOfSections;i++)
		{   
			//  Copy current section into current offset of virtual section
			if ( SectionHeader[i].Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA) )
			{                        
				RtlCopyMemory(SectionHeader[i].VirtualAddress   + (char *)NewModuleBase,
					SectionHeader[i].PointerToRawData + (char *)NewModuleBase,
					SectionHeader[i].Misc.VirtualSize > SectionHeader[i].SizeOfRawData ? 
					SectionHeader[i].SizeOfRawData    : SectionHeader[i].Misc.VirtualSize );
			}
			else
			{
				RtlZeroMemory(SectionHeader[i].VirtualAddress + (char *)NewModuleBase, SectionHeader[i].Misc.VirtualSize );             
			}
		}

		//
		//	Relocate instruction
		//

		Status = LdrRelocateImage(NewModuleBase,"HYDRA",STATUS_SUCCESS,
			STATUS_CONFLICTING_ADDRESSES,STATUS_INVALID_IMAGE_FORMAT);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		//
		//	Fix IAT
		//
		Status = FixImportTable(NewModuleBase);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		*ImageBase = NewModuleBase;

	} __finally {

		if (FileHandle != NULL)
		{
			ZwClose(FileHandle);
		}

		if (!NT_SUCCESS(Status))
		{
			if (NewModuleBase != NULL)
			{
				ExFreePool(NewModuleBase);
			}
		}
	}

	return Status;
}

NTSTATUS LoadDriver( __in PUNICODE_STRING FilePath,
					 __in PUNICODE_STRING ServiceKeyPath)
{
	NTSTATUS Status;
	PVOID DriverImageBase;


	//
	//	Load Driver File to memory
	//

	Status = LoadImage(FilePath,&DriverImageBase);
	if (NT_SUCCESS(Status))
	{
		Status = CreateDriverObject(ServiceKeyPath,DriverImageBase);
		if (!NT_SUCCESS(Status))
		{
			ExFreePool(DriverImageBase);		
		}
	}

	return Status;
}
