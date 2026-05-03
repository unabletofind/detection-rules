/*
   ============================================================
   YARA Rule: STX RAT CPUID Anti-VM Detection
   Author:   Swetha Devi (@unabletofind)
   Date:     April 2026
   MITRE:    T1497.001 (System Checks)
   Family:   STX RAT
   ============================================================
   Description:
   Detects the STX RAT family by matching the unique CPUID
   instruction pattern used to evade sandbox detonation,
   combined with VM-detection strings (VBoxService, vmtoolsd).

   Reference:
   See full analysis at:
   https://unabletofind.github.io/CPUID.html

   Usage:
   yara stx-rat-cpuid-antivm.yar /path/to/sample.exe
   ============================================================
*/

rule STX_RAT_CPUID_AntiVM
{
    meta:
        author      = "Swetha Devi"
        description = "Detects STX RAT CPUID-based anti-analysis"
        date        = "2026-04"
        severity    = "medium"
        family      = "STX RAT"
        reference   = "https://unabletofind.github.io/CPUID.html"
        mitre_attck = "T1497.001"

    strings:
        // CPUID instruction with hypervisor bit check
        $cpuid_check = { 0F A2 81 FB ?? ?? ?? ?? }

        // Common VM artifact strings
        $vbox_service = "VBoxService" ascii wide
        $vmware_tools = "vmtoolsd" ascii wide
        $vm_check_1   = "vmware" nocase ascii wide
        $vm_check_2   = "virtualbox" nocase ascii wide

    condition:
        // PE file
        uint16(0) == 0x5A4D
        and
        // CPUID check pattern present
        $cpuid_check
        and
        // At least one VM artifact string
        any of ($vbox_service, $vmware_tools, $vm_check_1, $vm_check_2)
}
