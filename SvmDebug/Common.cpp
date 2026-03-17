/**
 * @file Common.cpp
 * @brief CPU硬件支持检测实现 - AMD/Intel虚拟化能力检查
 * @author yewilliam
 * @date 2026/03/16
 *
 * 实现CPU厂商检测、BIOS开关检查、SVM/VMX硬件支持验证等功能。
 * 在启用SVM前，软件应按AMD APM规定的算法检测SVM可用性。
 */

#include "Common.h"

/* ========================================================================
 *  SVM 可用性检测算法 (AMD APM Vol.2 Section 15.4):
 *    1. CPUID Fn8000_0001_ECX[SVM] == 0  -> SVM_NOT_AVAIL
 *    2. VM_CR.SVMDIS == 0                -> SVM_ALLOWED
 *    3. CPUID Fn8000_000A_EDX[SVML] == 0 -> SVM_DISABLED_BY_BIOS
 *    4. else                              -> SVM_DISABLED_WITH_KEY
 * ======================================================================== */

/**
 * @brief 获取CPU厂商名称字符串 - 通过CPUID leaf 0读取12字节Vendor ID
 * @author yewilliam
 * @date 2026/03/16
 * @param [out] vendor - 输出厂商名称缓冲区 (如"AuthenticAMD"或"GenuineIntel")
 * @param [in]  size   - 缓冲区大小(建议>=13字节)
 */
void CommGetCPUName(char* vendor, SIZE_T size)
{
	int cpuinfo[4] = { 0 };
	char tmp[13] = { 0 };
	__cpuidex(cpuinfo, 0, 0);

	/* CPUID leaf 0 返回: EBX+EDX+ECX 拼成12字节厂商字符串 */
	memcpy(tmp, &cpuinfo[1], 4);
	memcpy(tmp + 4, &cpuinfo[3], 4);
	memcpy(tmp + 8, &cpuinfo[2], 4);
	memcpy(vendor, tmp, size);
}

/**
 * @brief 检查Intel BIOS是否启用VMX - 读取IA32_FEATURE_CONTROL MSR
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示bit0(Lock)和bit2(VMX outside SMX)均为1, FALSE表示未启用
 */
BOOLEAN CommCheckIntelBios()
{
	ULONG64 bios = __readmsr(MSR_IA32_INTEL_FEATURE_CONTROL);
	ULONG64 result = bios & 5;  /* 检查 bit0(Lock) + bit2(VMXON) */
	return (result == 5);
}

/**
 * @brief 检查AMD VM_CR.SVMDIS位 - 判断SVM是否被固件禁用
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示SVMDIS=0(SVM可用), FALSE表示SVMDIS=1(SVM被禁用)
 */
BOOLEAN CommCheckAMDLock()
{
	ULONG64 VmCr = __readmsr(SVM_MSR_VM_CR);

	/* SVMDIS = bit4, 为0表示SVM未被禁用 */
	if ((VmCr & (1ULL << 4)) == 0) {
		return TRUE;
	}

	/* SVMDIS=1, SVM被禁用, 需进一步区分是BIOS禁用还是Key锁定 */
	return FALSE;
}

/**
 * @brief 检查Intel CPU硬件VMX支持 - 读取CPUID.1:ECX[5]
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示CPU支持VMX, FALSE表示不支持
 */
BOOLEAN CommCheckIntelCpuid()
{
	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, 1, 0);
	ULONG64 result = (cpuinfo[2] >> 5) & 1;
	return (result == 1);
}

/**
 * @brief 检查AMD CPU硬件SVM支持 - 读取CPUID Fn8000_0001_ECX[SVM] (bit2)
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示CPU支持SVM, FALSE表示不支持
 */
BOOLEAN CommCheckAMDCpuid()
{
	int CPUinfo[4] = { 0 };
	__cpuidex(CPUinfo, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX, 0);
	BOOLEAN bCpu = (CPUinfo[2] >> 2) & 1;
	return bCpu;
}

/**
 * @brief 检查CR4.VMXE位 - 确认系统未被其他Hypervisor占用
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示CR4.VMXE(bit13)未置位(可用), FALSE表示已被占用
 */
BOOLEAN CommCheckCr4()
{
	ULONG64 cr4 = __readcr4();
	cr4 = cr4 >> 13;
	return !(cr4 & 1);
}

/**
 * @brief 检查AMD SVM锁定状态 - 读取CPUID Fn8000_000A_EDX[SVML] (bit2)
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示SVM未被BIOS锁定, FALSE表示已锁定
 * @note SVML=0表示不支持SVM锁定(即未被锁), 取反后返回TRUE统一接口语义
 */
BOOLEAN CommCheckAMDBios()
{
	int CPUinfo[4] = { 0 };
	__cpuidex(CPUinfo, CPUID_SVM_FEATURES, 0);
	BOOLEAN bBios = (CPUinfo[3] >> 2) & 1;
	return !bBios;  /* 取反: SVML=0 -> 未锁定 -> 返回TRUE */
}

/**
 * @brief 获取AMD SVML特征位原始值 - 不做取反, 返回硬件实际值
 * @author yewilliam
 * @date 2026/03/16
 * @return 1表示支持SVM锁定特征, 0表示不支持
 */
BOOLEAN CommCheckAMDSvmlFeature()
{
	int CPUinfo[4] = { 0 };
	__cpuidex(CPUinfo, CPUID_SVM_FEATURES, 0);
	return (CPUinfo[3] >> 2) & 1;
}

/**
 * @brief Intel平台综合虚拟化支持检查 - BIOS + CPUID + CR4 三重验证
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示Intel平台完全支持虚拟化, FALSE表示任一检查未通过
 */
BOOLEAN CommCheckIntelsupport()
{
	char vendor[13] = { 0 };
	BOOLEAN bBios  = 0;
	BOOLEAN bCpuid = 0;
	BOOLEAN bCr4   = 0;

	CommGetCPUName(vendor, sizeof(vendor));
	bBios  = CommCheckIntelBios();
	bCpuid = CommCheckIntelCpuid();
	bCr4   = CommCheckCr4();

	DbgPrint("current cpu number:%d, cpu name:%s, bBios:%d, bCpuid:%d, bCr4:%d\n",
		KeGetCurrentProcessorNumber(), vendor, bBios, bCpuid, bCr4);
	return (bBios && bCpuid && bCr4);
}

/**
 * @brief AMD平台综合SVM支持检查 - 按AMD APM规定算法逐步验证
 * @author yewilliam
 * @date 2026/03/16
 * @return TRUE表示AMD SVM完全可用, FALSE表示不支持或被禁用
 * @note 检查顺序: CPUID硬件支持 -> VM_CR.SVMDIS -> SVML锁定特征
 */
BOOLEAN CommCheckAMDsupport()
{
	/* Step 1: 检查CPU硬件是否支持SVM */
	if (!CommCheckAMDCpuid()) {
		return FALSE;
	}

	/* Step 2: 检查VM_CR.SVMDIS, 为0则SVM畅通无阻 */
	if (CommCheckAMDLock()) {
		return TRUE;
	}

	/* Step 3: SVMDIS=1, 区分BIOS禁用 vs Key锁定 */
	BOOLEAN bSvml = CommCheckAMDSvmlFeature();
	if (bSvml == 0) {
		return FALSE;  /* SVML=0: 被BIOS禁用, 需用户修改固件设置 */
	}
	else {
		return FALSE;  /* SVML=1: 被Key锁定, 可能需SKINIT/TPM解锁 */
	}
}
