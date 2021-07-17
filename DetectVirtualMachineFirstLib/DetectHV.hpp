#pragma once
#include "ntdll.h"
#include <intrin.h>
#include "AlterApi.h"
#include <iostream>




EXTERN_C void BEShit();
EXTERN_C __int16 LazyCheckHyperv();


namespace DetectHyp {



	inline bool RdtscpSupport() {
		INT cpuid[4] = { -1 };
		__cpuid(cpuid, 0x80000001);
		return ((cpuid[3] >> 27) & 1);// chekc 27 bit EDX
	}


	inline bool CpuidIsHyperv()
	{// Check 31 bit  in ECX 
		INT cpuinf[4] = { 0 };
		__cpuid(cpuinf, 1);
		return ((cpuinf[2] >> 31) & 1);
	}

	

	inline  bool   RdtscCpu()
	{
		DWORD tsc1 = 0;
		DWORD tsc2 = 0;
		DWORD avg = 0;
		INT cpuInfo[4] = {};
		for (INT i = 0; i < 10; i++)
		{
				tsc1 = __rdtsc();
				__cpuid(cpuInfo, 0);
				tsc2 = __rdtsc();
				avg += (tsc2 - tsc1);
		}
			avg = avg / 10;
			return (avg < 500 && avg > 25) ? FALSE : TRUE;
	}

	inline bool Rdtscp() {
		
		unsigned int  blabla = 0;
		DWORD tscp1 = 0;
		DWORD tscp2 = 0;
		DWORD avg = 0;
		INT cpuid[4] = {};

		if (DetectHyp::RdtscpSupport()) {
			for (INT j = 0; j < 10; j++)
			{
				tscp1 = __rdtscp(&blabla);
				//call 3 cpuid for normal detect
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				tscp2 = __rdtscp(&blabla);
				avg += tscp2 - tscp1;
				if (avg < 500 && avg > 25)
					return false;
				else
					avg = 0;
			}
			return true;
		}
		else 
			return false; //rdtscp dont support
		
		

	}
		

	

	
	inline bool  RdtscHeap()
	{
		ULONGLONG tsc1 = 0;
		ULONGLONG tsc2 = 0;
		ULONGLONG tsc3 = 0;

		for (DWORD i = 0; i < 10; i++)
		{
			tsc1 = __rdtsc();

			GetProcessHeap();

			tsc2 = __rdtsc();

			CloseHandle(0);

			tsc3 = __rdtsc();
			
			if ((tsc3 - tsc2) / (tsc2 - tsc1) >= 10)
				return FALSE;
		}

		return TRUE;
	}
	inline bool UmpIsSystemVirtualized() {
		// We just compare cpuid list & if its eaqual,thene we  in hypervisor

		DWORD invalid_leaf = 0x13371337;
		DWORD valid_leaf = 0x40000000;
		INT  InvalidLeafResponse[4] = {  -1};
		INT ValidLeafResponse[4] = { -1 };

		__cpuid(InvalidLeafResponse, invalid_leaf);
		__cpuid(ValidLeafResponse, valid_leaf);

		if ((InvalidLeafResponse[0] != ValidLeafResponse[0]) ||
			(InvalidLeafResponse[1] != ValidLeafResponse[1]) ||
			(InvalidLeafResponse[2] != ValidLeafResponse[2]) ||
			(InvalidLeafResponse[3] != ValidLeafResponse[3]))
			return true;

		return false;
		

	}


	inline int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep, BOOL& bDetected, int& singleStepCount)
	{
		if (code != EXCEPTION_SINGLE_STEP)
		{
			bDetected = true;
			return EXCEPTION_CONTINUE_SEARCH;
		}

		singleStepCount++;
		if ((size_t)ep->ExceptionRecord->ExceptionAddress != (size_t)BEShit + 11)
		{
			bDetected = true;
			return EXCEPTION_EXECUTE_HANDLER;
		}

		bool bIsRaisedBySingleStep = ep->ContextRecord->Dr6 & (1 << 14);
		bool bIsRaisedByDr0 = ep->ContextRecord->Dr6 & 1;
		if (!bIsRaisedBySingleStep || !bIsRaisedByDr0)
		{
			bDetected = true;
		}
		return EXCEPTION_EXECUTE_HANDLER;
	}

	inline bool ResCheckTrapFlag() 
	{
		
		BOOL bDetected = FALSE;
		INT singleStepCount = NULL;
		CONTEXT ctx{};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(GetCurrentThread(), &ctx);
		ctx.Dr0 = (size_t)BEShit + 11;
		ctx.Dr7 = 1;
		SetThreadContext(GetCurrentThread(), &ctx);
		__try
		{
			BEShit(); //trap flag work
		}
		__except (filter(GetExceptionCode(), GetExceptionInformation(), bDetected, singleStepCount))

		{
			if (singleStepCount != 1)
			{
				bDetected = 1;

			}

		}
		return bDetected;
		
		
	}

	

	inline bool  CheckKnowHypervisor()
	{
		

		INT CPUInfo[4] = { -1 };
		CHAR szHypervisorVendor[0x40];
		WCHAR* pwszConverted;

		BOOL bResult = FALSE;
		
		
		const TCHAR* szBlacklistedHypervisors[] = {
			(L"KVMKVMKVM\0\0\0"),	/* KVM */
			(L"Microsoft Hv"),		/* Microsoft Hyper-V or Windows Virtual PC */
			(L"VMwareVMware"),		/* VMware */
			(L"XenVMMXenVMM"),		/* Xen */
			(L"prl hyperv  "),		/* Parallels */
			(L"VBoxVBoxVBox"),		/* VirtualBox */
		};

		WORD dwlength = sizeof(szBlacklistedHypervisors) / sizeof(szBlacklistedHypervisors[0]);

		// __cpuid with an InfoType argument of 0 returns the number of
		// valid Ids in CPUInfo[0] and the CPU identification string in
		// the other three array elements. The CPU identification string is
		// not in linear order. The code below arranges the information 
		// in a human readable form.
		__cpuid(CPUInfo, 0x40000000);
		memset(szHypervisorVendor, 0, sizeof(szHypervisorVendor));
		memcpy(szHypervisorVendor, CPUInfo + 1, 12);

		for (int i = 0; i < dwlength; i++)
		{
			pwszConverted = alternat_api::CharToWChar_T(szHypervisorVendor);
			if (pwszConverted) {

				bResult = (wcscmp(pwszConverted, szBlacklistedHypervisors[i]) == 0); // compare name

				free(pwszConverted);
				 
				if (bResult) 
					return TRUE;
			}
		}
		
			
		return FALSE;
	}
	inline bool LazyCheckHypervisor() {
		/*
		 EAC use this meme & code wase manual deobfuscation 
		 see this meme detect https://pastebin.com/2gv72r7d 
		 EAC code:
		xor ecx,ecx 
		mov eax,1 
		cpuid
		mov     edi, ecx   ; its just  test ecx,80000000h
		test    edi, 80000000h
		setnz   al

		*/
		if (LazyCheckHyperv())
			return true;
		else
			return false;

	}

	inline bool SystemHypDetailInformation(){
		//	SYSTEM_HYPERVISOR_DETAIL_INFORMATION -> https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/hypervisor_detail.htm

		SYSTEM_HYPERVISOR_DETAIL_INFORMATION systHypervDetailInf{0};
		ULONG retLenth = NULL;

			NtQuerySystemInformation(
			SystemHypervisorDetailInformation,
			&systHypervDetailInf,
			sizeof(SYSTEM_HYPERVISOR_DETAIL_INFORMATION), //0x70
			&retLenth
			);
		 if (systHypervDetailInf.ImplementationLimits.Data[0] != 0
				 || systHypervDetailInf.HypervisorInterface.Data[0] != 0
				 || systHypervDetailInf.EnlightenmentInfo.Data[0] != 0
				 || systHypervDetailInf.HvVendorAndMaxFunction.Data[0] != 0
				 || systHypervDetailInf.HvVendorAndMaxFunction.Data[1] != 0)
				 return true;
			 else
				 return false;
		 /*
		 NtQuerySystemInformation with SystemHypervisorDetailInformation call:
		 HviGetHypervisorVendorAndMaxFunction -> HviIsAnyHypervisorPresent & call cpuid with eax =  40000000h & set result in  registry
		 HviGetHypervisorInterface -> HviIsAnyHypervisorPresent & call cpuid with eax =  40000001h & set result in  registry
		 HviGetHypervisorVersion -> HviIsHypervisorMicrosoftCompatible
		 HviGetHypervisorFeatures -> HviIsHypervisorMicrosoftCompatible &  call cpuid with eax = 40000003h & set result in  registry
		 HviGetHardwareFeatures -> HviGetHypervisorVendorAndMaxFunction & call cpuid with eax = 40000006h & set result in  registry
		 HviGetEnlightenmentInformation -> HviIsHypervisorMicrosoftCompatible & call cpuid eax = 40000004h & set result in  registry
		 HviGetImplementationLimits -> HviIsHypervisorMicrosoftCompatible & call cpuid with eax = 40000005h & set result in  registry
		 after this its set value in you stuct & return result in  NtQuerySystemInformation
		 

		 HviIsAnyHypervisorPresent :
		 call cpuid with eax = 40000001h
		 if(rax != 766E6258h)
		  bdetectHyp = true

		  HviIsHypervisorMicrosoftCompatible:
		  int v1[4]
		  call HviGetHypervisorInterface
		  return v1[0] == 31237648h

		  HviGetHypervisorInterface:
		  call HviIsAnyHypervisorPresent
		  call cpuid with eax =  40000001h & set result in registry

		 */
	
	}
		inline bool  RdtscpCorrupt() {

			/*
			maybe undafe 	?
			If we many call rdtscp & cpuid we have a big value (1000-50000)
			 if rdtscp return all time one value(like : 100) or value change,  after call cpuid
			(like rdtsp+=80),then we cane try trap this 
			P.S Yes,this stupid,but why not?
			*/





			unsigned int  blabla = 0;
			DWORD tscp1 = 0;
			DWORD tscp2 = 0;
			DWORD avg = 0;
			INT cpuid[4] = {};
			if (DetectHyp::RdtscpSupport()) {
				for (INT j = 0; j < 0x13337; j++)
				{
					tscp1 = __rdtscp(&blabla);
					__cpuid(cpuid, 0);


					tscp2 = __rdtscp(&blabla);
					avg += tscp2 - tscp1;
					if (avg > 3000 && avg < 150000)
					{
						return false;
					}
					else
						avg = 0;
				}
				return true;
			}
			else
				return false;
		}

	
}
