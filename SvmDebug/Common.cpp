#include "Common.h"

//在启用SVM前，软件应通过以下算法检测是否可启用SVM：
//如果 CPUID Fn8000_0001_ECX[SVM] == 0
//则返回 SVM_NOT_AVAIL；
//如果 VM_CR.SVMDIS == 0
//返回 SVM_ALLOWED;
//如果 CPUID Fn8000_000A_EDX[SVML] == 0
//返回 SVM_BIOS_未解锁时禁用
// 用户必须更改平台固件设置以启用SVM，否则返回SVM_DISABLED_WITH_KEY；
// SVMLock可能可解锁；请咨询平台固件或TPM以获取密钥。

//获得cpu型号
void CommGetCPUName(char* vendor, SIZE_T size) {
	int cpuinfo[4] = { 0 };
	char tmp[13] = { 0 };
	__cpuidex(cpuinfo, 0, 0);

	memcpy(tmp, &cpuinfo[1], 4);
	memcpy(tmp + 4, &cpuinfo[3], 4);
	memcpy(tmp + 8, &cpuinfo[2], 4);
	memcpy(vendor, tmp, size);

	return;
}
//检查intel固件开关
BOOLEAN CommCheckIntelBios()
{
	//BIOS 检测：当第 0 位和第 2 位都为 1 时通过
	ULONG64 bios = __readmsr(MSR_IA32_INTEL_FEATURE_CONTROL);
	ULONG64 result = bios & 5;
	return (result == 5);
}
//检查AMD固件开关
BOOLEAN CommCheckAMDLock()
{
	// 1. 读取 AMD 虚拟机控制寄存器 (VM_CR)
	ULONG64 VmCr = __readmsr(SVM_MSR_VM_CR);

	// 2. 检查 SVMDIS (Bit 4)
	// 如果 SVMDIS 为 0，说明 SVM 是完全开启且允许使用的！
	if ((VmCr & (1ULL << 4)) == 0) {
		return TRUE; // 安全，放行！
	}

	// 如果 SVMDIS 为 1，说明 SVM 确实被禁用了。此时才需要去区分是被 BIOS 禁用，还是被 Key 锁定。
	return FALSE;
}

//检查intel cpu硬件是否支持
BOOLEAN CommCheckIntelCpuid()
{
	//Intel CPUID 检测
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, 1, 0);
	ULONG64 result = (cpuinfo[2] >> 5) & 1;
	return (result == 1);
}

//检查amd cpu硬件是否支持
BOOLEAN CommCheckAMDCpuid()
{
	int CPUinfo[4] = { 0 };
	//检测 CPUID Fn8000_0001_ECX[SVM] == 0
	__cpuidex(CPUinfo, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX, 0);
	BOOLEAN bCpu = (CPUinfo[2] >> 2) & 1;
	return bCpu;
}

//检查系统是否支持
BOOLEAN CommCheckCr4()
{
	ULONG64 cr4 = __readcr4();
	cr4 = cr4 >> 13;

	return !(cr4 & 1);
}
//检查AMD是否锁住SVM
BOOLEAN CommCheckAMDBios()
{
	int CPUinfo[4] = { 0 };
	//检测 CPUID Fn8000_000A_EDX[SVML] == 0
	__cpuidex(CPUinfo, CPUID_SVM_FEATURES, 0);
	//SVM锁定。表示支持SVM锁定。参见“启用SVM”。
	BOOLEAN bBios = (CPUinfo[3] >> 2) & 1;
	//如果等于0的话说明svm没有锁定，取反的原因就是要统一返回true;
	return !bBios;
}

BOOLEAN CommCheckAMDSvmlFeature()
{
	int CPUinfo[4] = { 0 };
	__cpuidex(CPUinfo, CPUID_SVM_FEATURES, 0);
	return (CPUinfo[3] >> 2) & 1; // 直接返回真实的 SVML 位的值，不需要取反
}

BOOLEAN CommCheckIntelsupport()
{
	char vendor[13] = { 0 };
	BOOLEAN bBios = 0;
	BOOLEAN bCpuid = 0;
	BOOLEAN bCr4 = 0;
	CommGetCPUName(vendor, sizeof(vendor));
	bBios = CommCheckIntelBios();
	bCpuid = CommCheckIntelCpuid();
	bCr4 = CommCheckCr4();
	DbgPrint("current cpu number:%d, cpu name :%s,bBios:%d,bCpuid:%d,bCr4:%d \n"
		, KeGetCurrentProcessorNumber(), vendor, bBios, bCpuid, bCr4);
	return (bBios && bCpuid && bCr4);
}
BOOLEAN CommCheckAMDsupport()
{
	// 1. 检查 CPU 硬件是否支持 SVM
	if (!CommCheckAMDCpuid()) {
		//DbgPrint("SVM is not supported by this CPU.\n");
		return FALSE; // 修改：返回 FALSE
	}

	// 2. 检查 VM_CR 寄存器
	if (CommCheckAMDLock()) {
		// VM_CR.SVMDIS == 0，说明 SVM 畅通无阻，直接返回可用！
		//DbgPrint("SVM is enabled and ready to use.\n");
		return TRUE;  // 修改：完美通过，必须返回 TRUE！
	}

	// 3. 只有走到这里，才说明 SVM 被禁用了 (VM_CR.SVMDIS == 1)。
	BOOLEAN bSvml = CommCheckAMDSvmlFeature();

	if (bSvml == 0) {
		//DbgPrint("SVM disabled by BIOS. User must change firmware settings.\n");
		return FALSE; // 修改：返回 FALSE
	}
	else {
		//DbgPrint("SVM disabled with key. May be unlockable via SKINIT/TPM.\n");
		return FALSE; // 修改：返回 FALSE
	}
}




