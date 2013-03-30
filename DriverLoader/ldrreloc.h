#ifndef __LDRRELOC_H__
#define __LDRRELOC_H__

#include <wdm.h>
#include "ntimage.h"

NTSTATUS LdrRelocateImage(__in PVOID NewBase,
						  __in PCSTR LoaderName,
						  __in NTSTATUS Success,
						  __in NTSTATUS Conflict,
						  __in NTSTATUS Invalid);

#endif // __LDRRELOC_H__