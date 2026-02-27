using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace EasyInject;

public static class Injector
{

    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint MEM_COMMIT = 0x00001000;
    private const uint MEM_RESERVE = 0x00002000;
    private const uint MEM_RELEASE = 0x00008000;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint INFINITE = 0xFFFFFFFF;
    private const uint WAIT_TIMEOUT = 0x00000102;
    private const uint STILL_ACTIVE = 0x00000103;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualAllocEx(nint hProcess, nint lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(nint hProcess, nint lpAddress,
        uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress,
        byte[] lpBuffer, uint nSize, out nint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint GetProcAddress(nint hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern nint GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes,
        uint dwStackSize, nint lpStartAddress, nint lpParameter,
        uint dwCreationFlags, nint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeThread(nint hThread, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(nint hProcess, nint lpAddress,
        uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(nint hProcess, out bool wow64Process);

    public static InjectionResult Inject(int processId, string dllPath)
    {
        if (!File.Exists(dllPath))
            return InjectionResult.Fail("DLL file not found.");

        string fullPath = Path.GetFullPath(dllPath);
        byte[] pathBytes = Encoding.ASCII.GetBytes(fullPath + "\0");

        nint hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
        if (hProcess == nint.Zero)
            return InjectionResult.Fail($"OpenProcess failed (error {GetLastError()}). Run as Administrator.");

        try
        {
            nint alloc = VirtualAllocEx(hProcess, nint.Zero,
                (uint)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (alloc == nint.Zero)
                return InjectionResult.Fail($"VirtualAllocEx failed (error {GetLastError()}).");

            try
            {
                if (!WriteProcessMemory(hProcess, alloc, pathBytes, (uint)pathBytes.Length, out _))
                    return InjectionResult.Fail($"WriteProcessMemory failed (error {GetLastError()}).");

                nint kernel32 = GetModuleHandle("kernel32.dll");
                nint loadLibAddr = GetProcAddress(kernel32, "LoadLibraryA");
                if (loadLibAddr == nint.Zero)
                    return InjectionResult.Fail("Could not resolve LoadLibraryA.");

                nint hThread = CreateRemoteThread(hProcess, nint.Zero, 0,
                    loadLibAddr, alloc, 0, nint.Zero);
                if (hThread == nint.Zero)
                    return InjectionResult.Fail($"CreateRemoteThread failed (error {GetLastError()}).");

                WaitForSingleObject(hThread, 8000);
                GetExitCodeThread(hThread, out uint exitCode);
                CloseHandle(hThread);

                if (exitCode == 0)
                    return InjectionResult.Fail("LoadLibraryA returned NULL — DLL load failed (bad export / wrong arch?).");

                return InjectionResult.Success($"DLL injected into PID {processId}.");
            }
            finally { VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE); }
        }
        finally { CloseHandle(hProcess); }
    }

    public static InjectionResult InjectShellcode(int processId, byte[] shellcode)
    {
        if (shellcode is null || shellcode.Length == 0)
            return InjectionResult.Fail("Shellcode buffer is empty.");

        nint hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
        if (hProcess == nint.Zero)
            return InjectionResult.Fail($"OpenProcess failed (error {GetLastError()}). Run as Administrator.");

        nint alloc = nint.Zero;
        try
        {

            alloc = VirtualAllocEx(hProcess, nint.Zero,
                (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (alloc == nint.Zero)
                return InjectionResult.Fail($"VirtualAllocEx failed (error {GetLastError()}).");

            if (!WriteProcessMemory(hProcess, alloc, shellcode, (uint)shellcode.Length, out _))
            {
                VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
                return InjectionResult.Fail($"WriteProcessMemory failed (error {GetLastError()}).");
            }

            if (!VirtualProtectEx(hProcess, alloc, (uint)shellcode.Length,
                    PAGE_EXECUTE_READ, out _))
            {
                VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
                return InjectionResult.Fail($"VirtualProtectEx failed (error {GetLastError()}).");
            }

            nint hThread = CreateRemoteThread(hProcess, nint.Zero, 0,
                alloc, nint.Zero, 0, nint.Zero);
            if (hThread == nint.Zero)
            {
                VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
                return InjectionResult.Fail($"CreateRemoteThread failed (error {GetLastError()}).");
            }

            uint waitResult = WaitForSingleObject(hThread, 15000);
            GetExitCodeThread(hThread, out uint exitCode);
            CloseHandle(hThread);

            return DiagnoseShellcodeResult(waitResult, exitCode, shellcode.Length, processId);
        }
        finally
        {

            CloseHandle(hProcess);
        }
    }

    private static InjectionResult DiagnoseShellcodeResult(
        uint waitResult, uint exitCode, int byteCount, int pid)
    {

        if (waitResult == WAIT_TIMEOUT || exitCode == STILL_ACTIVE)
            return InjectionResult.Success(
                $"{byteCount} bytes injected into PID {pid}. Thread still running (OK for loops/GUI).");

        if (exitCode == 0 || exitCode == 1)
            return InjectionResult.Success(
                $"{byteCount} bytes injected into PID {pid}. Thread exited cleanly (code: 0x{exitCode:X}).");

        string crashReason = exitCode switch
        {
            0xC0000005 => "Access Violation — شيلت من/لعنوان محمي أو NULL",
            0xC000001D => "Illegal Instruction — opcode غلط أو غير مدعوم",
            0xC0000094 => "Integer Divide by Zero",
            0xC00000FD => "Stack Overflow — stack ما في مكان كافي",
            0xC0000096 => "Privileged Instruction — استخدمت instruction تحتاج ring 0",
            0xC000001C => "Invalid Disposition",
            0xC0000025 => "Non-Continuable Exception",
            0xC0000135 => "DLL Not Found",
            0xC0000139 => "Entry Point Not Found",
            0xC0000142 => "DLL Init Failed",
            0x40010005 => "Control-C / DBG_CONTROL_C",
            _ => $"Unknown exception"
        };

        return InjectionResult.Fail(
            $"Thread crashed with 0x{exitCode:X8} — {crashReason}\n" +
            $"الأسباب الشائعة:\n" +
            $"  • Stack غير محاذي على 16 bytes قبل CALL\n" +
            $"  • عنوان خاطئ في الـ shellcode\n" +
            $"  • الـ shellcode مكتوب لـ arch مختلف (x86 vs x64)\n" +
            $"  • DEP / Antivirus أوقف التنفيذ");
    }

    public static string GetProcessArchitecture(int processId)
    {
        try
        {
            nint h = OpenProcess(0x0400, false, processId);
            if (h == nint.Zero) return "?";
            IsWow64Process(h, out bool isWow64);
            CloseHandle(h);
            return isWow64 ? "x86" : "x64";
        }
        catch { return "?"; }
    }

    public static string GetDllArchitecture(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
            using var br = new BinaryReader(fs);
            if (br.ReadUInt16() != 0x5A4D) return "Unknown";
            fs.Seek(60, SeekOrigin.Begin);
            uint peOffset = br.ReadUInt32();
            fs.Seek(peOffset, SeekOrigin.Begin);
            if (br.ReadUInt32() != 0x00004550) return "Unknown";
            ushort machine = br.ReadUInt16();
            return machine switch
            {
                0x014C => "x86",
                0x8664 => "x64",
                0xAA64 => "ARM64",
                _ => $"0x{machine:X4}"
            };
        }
        catch { return "Unknown"; }
    }
}

public readonly struct InjectionResult
{
    public bool IsSuccess { get; init; }
    public string Message { get; init; }

    public static InjectionResult Success(string msg) => new() { IsSuccess = true, Message = msg };
    public static InjectionResult Fail(string msg) => new() { IsSuccess = false, Message = msg };
}