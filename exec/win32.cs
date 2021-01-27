using System;
using System.Runtime.InteropServices;

namespace exec
{
    class win32
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            /// <summary>
            /// The buffer receives a TOKEN_USER structure that contains the user account of the token.
            /// </summary>
            TokenUser = 1,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the group accounts associated with the token.
            /// </summary>
            TokenGroups,

            /// <summary>
            /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
            /// </summary>
            TokenPrivileges,

            /// <summary>
            /// The buffer receives a TOKEN_OWNER structure that contains the default owner security identifier (SID) for newly created objects.
            /// </summary>
            TokenOwner,

            /// <summary>
            /// The buffer receives a TOKEN_PRIMARY_GROUP structure that contains the default primary group SID for newly created objects.
            /// </summary>
            TokenPrimaryGroup,

            /// <summary>
            /// The buffer receives a TOKEN_DEFAULT_DACL structure that contains the default DACL for newly created objects.
            /// </summary>
            TokenDefaultDacl,

            /// <summary>
            /// The buffer receives a TOKEN_SOURCE structure that contains the source of the token. TOKEN_QUERY_SOURCE access is needed to retrieve this information.
            /// </summary>
            TokenSource,

            /// <summary>
            /// The buffer receives a TOKEN_TYPE value that indicates whether the token is a primary or impersonation token.
            /// </summary>
            TokenType,

            /// <summary>
            /// The buffer receives a SECURITY_IMPERSONATION_LEVEL value that indicates the impersonation level of the token. If the access token is not an impersonation token, the function fails.
            /// </summary>
            TokenImpersonationLevel,

            /// <summary>
            /// The buffer receives a TOKEN_STATISTICS structure that contains various token statistics.
            /// </summary>
            TokenStatistics,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS structure that contains the list of restricting SIDs in a restricted token.
            /// </summary>
            TokenRestrictedSids,

            /// <summary>
            /// The buffer receives a DWORD value that indicates the Terminal Services session identifier that is associated with the token.
            /// </summary>
            TokenSessionId,

            /// <summary>
            /// The buffer receives a TOKEN_GROUPS_AND_PRIVILEGES structure that contains the user SID, the group accounts, the restricted SIDs, and the authentication ID associated with the token.
            /// </summary>
            TokenGroupsAndPrivileges,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenSessionReference,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token includes the SANDBOX_INERT flag.
            /// </summary>
            TokenSandBoxInert,

            /// <summary>
            /// Reserved.
            /// </summary>
            TokenAuditPolicy,

            /// <summary>
            /// The buffer receives a TOKEN_ORIGIN value.
            /// </summary>
            TokenOrigin,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION_TYPE value that specifies the elevation level of the token.
            /// </summary>
            TokenElevationType,

            /// <summary>
            /// The buffer receives a TOKEN_LINKED_TOKEN structure that contains a handle to another token that is linked to this token.
            /// </summary>
            TokenLinkedToken,

            /// <summary>
            /// The buffer receives a TOKEN_ELEVATION structure that specifies whether the token is elevated.
            /// </summary>
            TokenElevation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has ever been filtered.
            /// </summary>
            TokenHasRestrictions,

            /// <summary>
            /// The buffer receives a TOKEN_ACCESS_INFORMATION structure that specifies security information contained in the token.
            /// </summary>
            TokenAccessInformation,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is allowed for the token.
            /// </summary>
            TokenVirtualizationAllowed,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if virtualization is enabled for the token.
            /// </summary>
            TokenVirtualizationEnabled,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.
            /// </summary>
            TokenIntegrityLevel,

            /// <summary>
            /// The buffer receives a DWORD value that is nonzero if the token has the UIAccess flag set.
            /// </summary>
            TokenUIAccess,

            /// <summary>
            /// The buffer receives a TOKEN_MANDATORY_POLICY structure that specifies the token's mandatory integrity policy.
            /// </summary>
            TokenMandatoryPolicy,

            /// <summary>
            /// The buffer receives the token's logon security identifier (SID).
            /// </summary>
            TokenLogonSid,

            /// <summary>
            /// The maximum value for this enumeration
            /// </summary>
            MaxTokenInfoClass
        }

        [DllImport("advapi32.dll",
              EntryPoint = "CreateProcessAsUser", SetLastError = true,
              CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
        public static extern bool
          CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine,
                              ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes,
                              bool bInheritHandle, UInt32 dwCreationFlags, IntPtr lpEnvrionment,
                              string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
                              ref PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll")]
        public static extern void CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", BestFitMapping = true, CharSet = CharSet.Ansi)]
        public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
    IntPtr hExistingToken,
    uint dwDesiredAccess,
    ref SECURITY_ATTRIBUTES lpThreadAttributes,
    Int32 ImpersonationLevel,
    Int32 dwTokenType,
    ref IntPtr phNewToken);

        public const int SW_HIDE = 0;
        public const int STARTF_USESHOWWINDOW = 0x00000001;
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const int CREATE_NEW_CONSOLE = 0x00000010;
        public const uint CREATE_NO_WINDOW = 0x08000000;

        public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        public const uint GENERIC_ALL_ACCESS = 0x10000000;
    }
}
