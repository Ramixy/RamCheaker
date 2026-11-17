using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace InjectHunter
{
    enum SigState { NotChecked, Embedded, Catalog, Unsigned, Invalid }

    class SigInfo
    {
        public SigState State;
        public string Signer;
        public bool Trusted { get { return State == SigState.Embedded || State == SigState.Catalog; } }
        public bool IsMicrosoft
        {
            get
            {
                if (State == SigState.Catalog) return true;
                return State == SigState.Embedded && Signer != null && Signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
            }
        }
        public override string ToString()
        {
            switch (State)
            {
                case SigState.Embedded: return "Подписан: " + (Signer ?? "?");
                case SigState.Catalog: return "Подписан через каталог Windows";
                case SigState.Unsigned: return "НЕТ цифровой подписи";
                case SigState.Invalid: return "Подпись НЕДЕЙСТВИТЕЛЬНА" + (Signer != null ? " (" + Signer + ")" : "");
                default: return "не проверялась";
            }
        }
    }

    static class Native
    {
        // ---------------- WinVerifyTrust ----------------
        static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfo;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, IntPtr data);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        const uint WTD_UI_NONE = 2;
        const uint WTD_REVOKE_NONE = 0;
        const uint WTD_CHOICE_FILE = 1;
        const uint WTD_CHOICE_CATALOG = 2;
        const uint WTD_STATEACTION_VERIFY = 1;
        const uint WTD_STATEACTION_CLOSE = 2;
        const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;
        const uint WTD_REVOCATION_CHECK_NONE = 0x10;
        const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);

        static int VerifyWith(uint unionChoice, IntPtr info)
        {
            WINTRUST_DATA d = new WINTRUST_DATA();
            d.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            d.dwUIChoice = WTD_UI_NONE;
            d.fdwRevocationChecks = WTD_REVOKE_NONE;
            d.dwUnionChoice = unionChoice;
            d.pInfo = info;
            d.dwStateAction = WTD_STATEACTION_VERIFY;
            d.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
            IntPtr pd = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
            try
            {
                Marshal.StructureToPtr(d, pd, false);
                Guid g = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int r = WinVerifyTrust(new IntPtr(-1), ref g, pd);
                d = (WINTRUST_DATA)Marshal.PtrToStructure(pd, typeof(WINTRUST_DATA));
                d.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(d, pd, true);
                WinVerifyTrust(new IntPtr(-1), ref g, pd);
                return r;
            }
            finally { Marshal.FreeHGlobal(pd); }
        }

        static int VerifyEmbedded(string path)
        {
            IntPtr pPath = Marshal.StringToHGlobalUni(path);
            WINTRUST_FILE_INFO fi = new WINTRUST_FILE_INFO();
            fi.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fi.pcwszFilePath = pPath;
            IntPtr pfi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            try
            {
                Marshal.StructureToPtr(fi, pfi, false);
                return VerifyWith(WTD_CHOICE_FILE, pfi);
            }
            finally { Marshal.FreeHGlobal(pfi); Marshal.FreeHGlobal(pPath); }
        }

        static bool VerifyCatalog(string path, string algo)
        {
            IntPtr hAdmin;
            if (!CryptCATAdminAcquireContext2(out hAdmin, IntPtr.Zero, algo, IntPtr.Zero, 0)) return false;
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();
                    uint cb = 0;
                    CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, ref cb, null, 0);
                    if (cb == 0 || cb > 256) return false;
                    byte[] hash = new byte[cb];
                    if (!CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, ref cb, hash, 0)) return false;
                    IntPtr hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, cb, 0, IntPtr.Zero);
                    if (hCat == IntPtr.Zero) return false;
                    try
                    {
                        CATALOG_INFO ci = new CATALOG_INFO();
                        ci.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));
                        if (!CryptCATCatalogInfoFromContext(hCat, ref ci, 0)) return false;
                        StringBuilder tag = new StringBuilder();
                        foreach (byte b in hash) tag.Append(b.ToString("X2"));
                        IntPtr pCat = Marshal.StringToHGlobalUni(ci.wszCatalogFile);
                        IntPtr pTag = Marshal.StringToHGlobalUni(tag.ToString());
                        IntPtr pMem = Marshal.StringToHGlobalUni(path);
                        IntPtr pHash = Marshal.AllocHGlobal(hash.Length);
                        Marshal.Copy(hash, 0, pHash, hash.Length);
                        WINTRUST_CATALOG_INFO wci = new WINTRUST_CATALOG_INFO();
                        wci.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO));
                        wci.pcwszCatalogFilePath = pCat;
                        wci.pcwszMemberTag = pTag;
                        wci.pcwszMemberFilePath = pMem;
                        wci.hMemberFile = hFile;
                        wci.pbCalculatedFileHash = pHash;
                        wci.cbCalculatedFileHash = cb;
                        wci.hCatAdmin = hAdmin;
                        IntPtr pw = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                        try
                        {
                            Marshal.StructureToPtr(wci, pw, false);
                            return VerifyWith(WTD_CHOICE_CATALOG, pw) == 0;
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(pw); Marshal.FreeHGlobal(pCat); Marshal.FreeHGlobal(pTag);
                            Marshal.FreeHGlobal(pMem); Marshal.FreeHGlobal(pHash);
                        }
                    }
                    finally { CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0); }
                }
            }
            catch { return false; }
            finally { CryptCATAdminReleaseContext(hAdmin, 0); }
        }

        public static SigInfo CheckSignature(string path)
        {
            SigInfo s = new SigInfo();
            try
            {
                int r = VerifyEmbedded(path);
                if (r == 0)
                {
                    s.State = SigState.Embedded;
                    s.Signer = GetSigner(path);
                    return s;
                }
                bool noSig = r == TRUST_E_NOSIGNATURE || r == TRUST_E_SUBJECT_FORM_UNKNOWN || r == TRUST_E_PROVIDER_UNKNOWN;
                if (VerifyCatalog(path, "SHA256") || VerifyCatalog(path, null))
                {
                    s.State = SigState.Catalog;
                    return s;
                }
                if (noSig) s.State = SigState.Unsigned;
                else { s.State = SigState.Invalid; s.Signer = GetSigner(path); }
            }
            catch { s.State = SigState.Unsigned; }
            return s;
        }

        static string GetSigner(string path)
        {
            try
            {
                X509Certificate c = X509Certificate.CreateFromSignedFile(path);
                string subj = c.Subject;
                foreach (string part in subj.Split(','))
                {
                    string p = part.Trim();
                    if (p.StartsWith("CN=")) return p.Substring(3).Trim('"');
                }
                return subj;
            }
            catch { return null; }
        }

        // ---------------- Process memory ----------------
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_PRIVATE = 0x20000;
        public const uint MEM_IMAGE = 0x1000000;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_EXECUTE = 0x10, PAGE_EXECUTE_READ = 0x20, PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi, IntPtr length);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr read);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetMappedFileName(IntPtr hProcess, IntPtr address, StringBuilder name, uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint QueryDosDevice(string device, StringBuilder target, int max);

        static Dictionary<string, string> devMap;
        public static string DevicePathToDos(string dev)
        {
            if (devMap == null)
            {
                Dictionary<string, string> m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (string d in Environment.GetLogicalDrives())
                {
                    string letter = d.Substring(0, 2);
                    StringBuilder sb = new StringBuilder(512);
                    if (QueryDosDevice(letter, sb, 512) != 0) m[sb.ToString()] = letter;
                }
                devMap = m;
            }
            foreach (KeyValuePair<string, string> kv in devMap)
                if (dev.StartsWith(kv.Key + "\\", StringComparison.OrdinalIgnoreCase))
                    return kv.Value + dev.Substring(kv.Key.Length);
            return dev;
        }

        // ---------------- UI ----------------
        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        public static void DarkTitleBar(IntPtr hwnd)
        {
            try
            {
                int on = 1;
                if (DwmSetWindowAttribute(hwnd, 20, ref on, 4) != 0) DwmSetWindowAttribute(hwnd, 19, ref on, 4);
                int color = 0x00171111; // COLORREF BGR -> #111117
                DwmSetWindowAttribute(hwnd, 35, ref color, 4);
            }
            catch { }
        }

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        public static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);
    }
}
