import "pe"


rule self_inject : suspicious feature dll injection windows
{
meta:
        description = "Self Injecting code - like code packers"
        link = ""

strings:
        // Allocate new memory
	$self01 = "VirtualAlloc"
        // Change the executable bit of te new memory
	$self02 = "VirtualProtect"
        // Create new process
        $self03 = "CreateProcessInternal"

condition:
	// MZ at the beginning of file
        uint16be(0) == 0x4d5a and
        all of them
}


// http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html
// Detect capabilities needed for the DLL injection
// ProcessA -> OpenProcess(); -> ProcessB
// ProcessA -> VirtualAlloc(); -> ProcessB
// ProcessA -> WriteProcessMemory(); -> ProcessB
// LoadLibraryExA()
// Get..Offset()
// CreateRemoteThread();
// NtCreateThreadEx();
// RtlCreateUserThread;

rule dll_injection_thread : suspicious feature dll injection windows
{
meta:
	description = "Injection using kernel32.dll:VirtualAllocEx"
	link = "http://blog.opensecurityresearch.com/2013/01/windows-dll-injection-basics.html"

strings:
	$load_01 = "LoadLibraryA"

	$remote_01 = "NtCreateThreadEx"

condition:
	// MZ at the beginning of file
        uint16be(0) == 0x4d5a and

	// Access other process
	//(
	//	pe.imports("kernel32.dll","OpenProcess")
	//) and

	// Allocate memory in remote process
	(
		pe.imports("kernel32.dll","VirtualAllocEx")
	)and

	// Write code section to the remote process
	(
		pe.imports("kernel32.dll","WriteProcessMemory") or
		pe.imports("kernel32.dll","LoadLibraryExA") or
		pe.imports("kernel32.dll","LoadLibraryExW") or
		(
			pe.imports("kernel32.dll","GetProcAddress") and
			( pe.imports("kernel32.dll","GetModuleHandleA") or pe.imports("kernel32.dll","GetModuleHandleA") ) and
			$load_01
		)
	) and

	//Execute
	(
		pe.imports("kernel32.dll","CreateRemoteThread") or
		pe.imports("ntdll.dll","NtCreateThreadEx") or
		(
			pe.imports("kernel32.dll","GetProcAddress") and
			( pe.imports("kernel32.dll","GetModuleHandleA") or pe.imports("kernel32.dll","GetModuleHandleA") ) and
			$remote_01
		)
	)

}


rule dll_injection_hook : suspicious feature dll injection windows
{
meta:
	description = "Injection using User32.dll:VirtualAllocEx"


condition:
	// MZ at the beginning of file
        uint16(0) == 0x5a4d and

	(
		pe.imports("user32.dll","SetWindowsHookExA") or
		pe.imports("user32.dll","SetWindowsHookExW")
	)
}

