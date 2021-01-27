using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace exec
{
    class Program
    {
        static void error()
        {
            var error = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            Console.WriteLine(error);
        }

        static void exec(string cmdline)
        {
            win32.SECURITY_ATTRIBUTES sa = new win32.SECURITY_ATTRIBUTES();
            win32.STARTUPINFO si = new win32.STARTUPINFO();
            win32.PROCESS_INFORMATION pi = new win32.PROCESS_INFORMATION();

            sa.nLength = Marshal.SizeOf(sa);
            sa.lpSecurityDescriptor = IntPtr.Zero;
            sa.bInheritHandle = true;

            IntPtr hRead = IntPtr.Zero;
            IntPtr hWrite = IntPtr.Zero;
            if (!win32.CreatePipe(out hRead, out hWrite, ref sa, 0))
                return;

            si.cb = Marshal.SizeOf(si);
            si.hStdError = hWrite;
            si.hStdOutput = hWrite;
            si.wShowWindow = win32.SW_HIDE;
            si.dwFlags = win32.STARTF_USESHOWWINDOW | win32.STARTF_USESTDHANDLES;

            var hToken = WindowsIdentity.GetCurrent().Token;
            var hDupedToken = IntPtr.Zero;

            if (!win32.DuplicateTokenEx(
                                   hToken,
                                  win32.GENERIC_ALL_ACCESS,
                                   ref sa,
                                   (int)win32.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                                   (int)win32.TOKEN_TYPE.TokenPrimary,
                                   ref hDupedToken
                               ))
            {
                error();
                return;
            }

            if (!win32.CreateProcessAsUser(
                                                    hDupedToken,
                                                    null,
                                                    cmdline,
                                                    ref sa, ref sa,
                                                    true,
                                                    win32.NORMAL_PRIORITY_CLASS | win32.CREATE_NO_WINDOW,
                                                    IntPtr.Zero,
                                                    null, ref si, ref pi
                                            ))
            {
                error();
                return;
            }

            win32.CloseHandle(hWrite);

            while (true)
            {
                uint BytesRead = 0;
                byte[] buf = new byte[10240];
                if (!win32.ReadFile(hRead, buf, (uint)buf.Length, out BytesRead, IntPtr.Zero))
                    break;
                string str = Encoding.UTF8.GetString(buf, 0, (int)BytesRead);
                Console.Write(str);
                Thread.Sleep(100);
            }

            win32.CloseHandle(hRead);
            win32.CloseHandle(pi.hProcess);
            win32.CloseHandle(pi.hThread);
        }

        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 1)
                    exec(args[0]);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}