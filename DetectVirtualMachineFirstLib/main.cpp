#include "DetectHV.hpp"




int main() {
	
	

	std::cout << "Rdtscp support ? ->\t" << DetectHyp::RdtscpSupport() << '\n';
	std::cout << "Time attack with rdtsc ->\t" << DetectHyp::RdtscCpu() << '\n';
	std::cout << "Time attack with rdtscp ->\t" << DetectHyp::Rdtscp() << '\n';
	std::cout << "Time attack with rdtsc  using GetHeap & CloseHandle ->\t" << DetectHyp::RdtscHeap() << '\n';
	std::cout << "SYSTEM_HYPERVISOR_DETAIL_INFORMATION ->\t" << DetectHyp::SystemHypDetailInformation() << '\n'; 
	std::cout << "Detect know hyp by cpuid & name ->\t" << DetectHyp::CheckKnowHypervisor() << '\n';
	std::cout << "Cpuid is hyperv ->\t" << DetectHyp::CpuidIsHyperv() << '\n';
	std::cout << "Lazy check Hypervisor ->\t" << DetectHyp::LazyCheckHypervisor() << '\n';
	std::cout << "TF check  execute code ->\t" << DetectHyp::ResCheckTrapFlag() << '\n';
	std::cout << "Compare cpuid list ->\t" << DetectHyp::UmpIsSystemVirtualized() << '\n';
	std::cout << "Rdtscp corrupt ?\t->\t" << DetectHyp::RdtscpCorrupt() << '\n';//can have big value,then you compile code
		 



	std::cin.get();
	system("pause");
}

