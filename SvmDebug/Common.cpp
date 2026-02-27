#include "Common.h"

//在启用SVM前，软件应通过以下算法检测是否可启用SVM：
//if (CPUID Fn8000_0001_ECX[SVM] == 0)
//return SVM_NOT_AVAIL;
//if (VM_CR.SVMDIS == 0)
//返回 SVM_ALLOWED;
//if (CPUID Fn8000_000A_EDX[SVML] == 0)
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
	//BIOS检测，0位和2位为1的时候
	ULONG64 bios = __readmsr(MSR_IA32_INTEL_FEATURE_CONTROL);
	ULONG64 result = bios & 5;
	return (result == 5);
}
//检查AMD固件开关
BOOLEAN CommCheckAMDLock()
{
	//VM_CR.SVMDIS == 0，VM_CR MSR (C001_0114h)
	ULONG64 VM_CR = __readmsr(SVM_MSR_VM_CR);

	return !((VM_CR >> 4) & 1);
}

//检查intel cpu硬件是否支持
BOOLEAN CommCheckIntelCpuid()
{
	//IntelcpuId检测， 
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, 1, 0);
	ULONG64 result = (cpuinfo[2] >> 5) & 1;
	return (result == 1);
}

//检查amd cpu硬件是否支持
BOOLEAN CommCheckAMDCpuid()
{
	int CPUinfo[4] = { 0 };
	//CPUID Fn8000_0001_ECX[SVM] == 0
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
	//CPUID Fn8000_000A_EDX[SVML] == 0
	__cpuidex(CPUinfo, CPUID_SVM_FEATURES, 0);
	//SVM锁定。表示支持SVM锁定。参见“启用SVM”。
	BOOLEAN bBios = (CPUinfo[3] >> 2) & 1;
	//如果等于0的话说明svm没有锁定，取反的原因就是要统一返回true;
	return bBios;
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

	BOOLEAN bBios = CommCheckAMDBios();
	BOOLEAN bCpuid = CommCheckAMDCpuid();
	BOOLEAN VM_CR = CommCheckAMDLock();


	return bBios & bCpuid & VM_CR;
}




