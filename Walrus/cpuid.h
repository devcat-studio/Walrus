#ifndef _CPUID_H_
#define _CPUID_H_

/* shim for GCC __get_cpuid* intrinsics */
#ifdef _MSC_VER
#include <intrin.h>

__inline int __get_cpuid(unsigned int leaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	unsigned int info[4] = { 0 };

	__cpuid((int*) info, leaf & 0x80000000);
	if (info[0] == 0 || info[0] < leaf) return 0;

	__cpuid((int*)info, leaf);
	*eax = info[0];
	*ebx = info[1];
	*ecx = info[2];
	*edx = info[3];
	return 1;
}

__inline int __get_cpuid_count(unsigned int leaf, unsigned int subleaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
	unsigned int info[4] = { 0 };

	__cpuid((int*)info, leaf & 0x80000000);
	if (info[0] == 0 || info[0] < leaf) return 0;

	__cpuidex((int*)info, leaf, subleaf);
	*eax = info[0];
	*ebx = info[1];
	*ecx = info[2];
	*edx = info[3];
	return 1;
}

#endif

#endif /* !_CPUID_H_ */