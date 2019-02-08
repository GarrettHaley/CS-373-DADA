using System.Diagnostics;
using System;
using System.Threading;
using System.Runtime.InteropServices;
using System.Text;
namespace assignment1
{
    class assignment 
    {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(int hProcess, Int64 lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)] 
    public struct MEMORY_BASIC_INFORMATION64 
    { 
        public ulong BaseAddress; 
        public ulong AllocationBase; 
        public int AllocationProtect; 
        public int __alignment1; 
        public ulong RegionSize; 
        public int State; 
        public int Protect; 
        public int Type; 
        public int __alignment2; 
    }

    

        static void Main() 
        {
            Process[] processes = Process.GetProcesses();
            string menuResponse;
            while(true){
                Console.WriteLine("Choose a number: Enumerate running processes(1), enumerate running threads(2), enumerate modules(3), enumerate pages(4), get memory from a process(5), or quit(10)");
                menuResponse = Console.ReadLine();
                switch(menuResponse){
                    case "1":
                        EnumerateProcesses(processes);
                        break;
                    case "2":
                        EnumerateThreads(processes);
                        break;
                    case "3":
                        EnumerateModules(processes);
                        break;
                    case "4":
                        EnumerateMemoryPages(processes);
                        break;
                    case "5": 
                        GetBytesFromMemory();
                        break;
                    case "10":
                        System.Environment.Exit(1);
                        break;
                    default:
                        Console.Write("Invalid response, try again.\n");
                        break;
                }
            }
           

        }
        static void EnumerateMemoryPages(Process[] processes)
        {
            const int PAGE_EXECUTE = 0x10;
            const int PAGE_EXECUTE_READ = 0x20;
            const int PAGE_EXECUTE_READWRITE = 0x40;
            const int PAGE_EXECUTE_WRITECOPY = 0x80;
            foreach (Process process in processes)
            {
                try{
                    IntPtr startOffset = process.MainModule.BaseAddress; 
                    IntPtr endOffset = IntPtr.Add(startOffset ,process.MainModule.ModuleMemorySize);
                    do
                    {
                        MEMORY_BASIC_INFORMATION64 m;
                        int result = VirtualQueryEx(process.Handle, startOffset, out m, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64)));
                        if(m.AllocationProtect == PAGE_EXECUTE || m.AllocationProtect == PAGE_EXECUTE_READ || m.AllocationProtect == PAGE_EXECUTE_READWRITE || m.AllocationProtect == PAGE_EXECUTE_WRITECOPY)
                            Console.WriteLine("Process {0} executable page location: 0x{1:x}-0x{2:x} : {3} bytes", process.ProcessName, m.BaseAddress, (uint)m.BaseAddress + (uint)m.RegionSize - 1, m.RegionSize);
                        if ((long)startOffset == (long)m.BaseAddress + (long)m.RegionSize)
                            break;
                        startOffset = new IntPtr((long)m.BaseAddress + (long)m.RegionSize);
                    } 
                    while ((long)startOffset <= (long)endOffset);
                }
                catch(Exception e){}
            }
        }

        static void EnumerateProcesses(Process[] processes)
        {
            foreach (Process process in processes)
            {
                try{
                    ProcessModuleCollection currentProcessModules = process.Modules;
                    Console.WriteLine("Process: {0} ID: {1}", process.ProcessName, process.Id);
                }
                catch(Exception e){}                 
            }
        }

        static void EnumerateThreads(Process[] processes)
        {
            foreach (Process process in processes)
            {
                try{
                    ProcessThreadCollection currentThreads = process.Threads;
                    foreach (ProcessThread thread in currentThreads){
                        Console.WriteLine("{0} Thread: {1}", process.ProcessName, thread.Id);
                    }
                }
                catch(Exception e){}             
            }
        }

        static void EnumerateModules(Process[] processes)
        {

            foreach (Process process in processes)
            {
                try{
                    ProcessModuleCollection currentProcessModules = process.Modules;
                    foreach (ProcessModule module in currentProcessModules ){
                        Console.WriteLine("{0} Module: {1}", process.ProcessName, module.ModuleName);
                    }
                }
                catch(Exception e){}
            }
        }

        
        static void GetBytesFromMemory()
        {
            while(true){
                string processName, tryAgain ="";
                long memoryAddress;
                Process process;
                IntPtr processHandle = new IntPtr(0);
                const int PROCESS_WM_READ = 0x0010;
                int bytesRead = 0;
                byte[] buffer = new byte[24];

                Console.Write("Enter a VALID process name: ");
                processName = Console.ReadLine();

                try{
                    process = Process.GetProcessesByName(processName)[0];
                    processHandle = OpenProcess(PROCESS_WM_READ, false, process.Id);
                }

                catch(Exception e){
                    Console.Write("Invalid process name, try again? (yes or no): ");
                    tryAgain = Console.ReadLine().ToUpper();
                    if (tryAgain == "N" || tryAgain == "NO"){
                        Main();
                    }
                }

                if (tryAgain == "Y" || tryAgain == "YES"){
                    continue;
                }

                Console.Write("Enter a VALID memory location in that process: ");
                try{
                    memoryAddress = Convert.ToInt64(Console.ReadLine(),16);
                    ReadProcessMemory((int)processHandle,memoryAddress, buffer, buffer.Length, ref bytesRead);
                }

                catch(Exception e){
                    Console.Write("Invalid memory location, try again? (yes or no): ");
                    tryAgain = Console.ReadLine().ToUpper();
                    if (tryAgain == "N" || tryAgain == "NO"){
                        Main();
                    }
                }

                if (tryAgain == "Y" || tryAgain == "YES"){
                    continue;
                }

               Console.WriteLine(System.Text.Encoding.UTF8.GetString(buffer) + " (" + bytesRead.ToString() + "bytes)");

                Console.Write("Would you like to get memory from another process? (yes or no) ");
                tryAgain = Console.ReadLine().ToUpper();
                if (tryAgain == "N" || tryAgain == "NO"){
                    Main();
                    }  
            }


        }
    }
}