#pragma once
#include <ntifs.h>

EXTERN_C
VOID
_sgdt(
    _Out_ PVOID Descriptor
);
