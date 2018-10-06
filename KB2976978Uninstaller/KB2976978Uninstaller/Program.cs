using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace KB2976978Uninstaller
{
    class Program
    {
        // コード参考元: https://dobon.net/vb/dotnet/system/shutdown.html
        // The MIT License (MIT)
        // 
        // Copyright(c) 2016 DOBON! <http://dobon.net>
        //
        // Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
        // The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
        // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true,
            CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern bool LookupPrivilegeValue(string lpSystemName,
            string lpName,
            out long lpLuid);

        [System.Runtime.InteropServices.StructLayout(
           System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 1)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public long Luid;
            public int Attributes;
        }

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            int BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        //所有者変更のためのセキュリティ特権を有効にする
        public static void AdjustToken()
        {
            const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
            const uint TOKEN_QUERY = 0x8;
            const int SE_PRIVILEGE_ENABLED = 0x2;
            const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                return;

            IntPtr procHandle = GetCurrentProcess();

            //トークンを取得する
            IntPtr tokenHandle;
            OpenProcessToken(procHandle,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle);
            //LUIDを取得する
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.Attributes = SE_PRIVILEGE_ENABLED;
            tp.PrivilegeCount = 1;
            LookupPrivilegeValue(null, SE_TAKE_OWNERSHIP_NAME, out tp.Luid);
            //特権を有効にする
            AdjustTokenPrivileges(
                tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);

            //閉じる
            CloseHandle(tokenHandle);
        }
        static void Main(string[] args)
        {
            AdjustToken();

            List<String> KB2976978List = new List<string>();
            using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"))
            {
                foreach (string subkeyname in registryKey.GetSubKeyNames())
                {
                    if (subkeyname.StartsWith("Package_for_KB2976978~"))
                    {
                        Console.WriteLine("subkeyname");
                        KB2976978List.Add(subkeyname);
                        using (RegistryKey registryKey2 = registryKey.OpenSubKey(subkeyname + "\\Owners"))
                        {
                            if ((int)registryKey2.GetValue(subkeyname) == 0x20080)
                            {
                                IdentityReference CurUser = WindowsIdentity.GetCurrent().User;

                                // 所有者の変更
                                using (RegistryKey registryKey3 = registryKey.OpenSubKey(subkeyname + "\\Owners", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership | RegistryRights.ReadKey | RegistryRights.ReadPermissions))
                                {
                                    RegistrySecurity nSubKeySec = registryKey3.GetAccessControl(AccessControlSections.Owner);
                                    nSubKeySec.SetOwner(CurUser);
                                    registryKey3.SetAccessControl(nSubKeySec);
                                }

                                // アクセス許可の変更
                                using (RegistryKey registryKey3 = registryKey.OpenSubKey(subkeyname + "\\Owners", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadKey | RegistryRights.ChangePermissions | RegistryRights.ReadPermissions))
                                {
                                    RegistrySecurity nSubKeySec = registryKey3.GetAccessControl(AccessControlSections.Access);
                                    RegistryAccessRule nAccRule = new RegistryAccessRule(CurUser, RegistryRights.FullControl, AccessControlType.Allow);
                                    nSubKeySec.AddAccessRule(nAccRule);
                                    registryKey3.SetAccessControl(nSubKeySec);
                                    nSubKeySec.SetOwner(CurUser);
                                    registryKey3.SetAccessControl(nSubKeySec);
                                }

                                // 値の変更
                                using (RegistryKey registryKey3 = registryKey.OpenSubKey(subkeyname + "\\Owners", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadKey | RegistryRights.SetValue))
                                {
                                    registryKey3.SetValue(subkeyname, 0x20070);
                                }
                            }
                        }
                    }
                }
            }

            StringBuilder sb = new StringBuilder();
            if (KB2976978List.Count > 0)
            {
                foreach (string pn in KB2976978List)
                {
                    sb.Append(" /PackageName:");
                    sb.Append(pn);
                }
            }

            if (sb.Length > 0)
            {
                Console.WriteLine();
                using (Process p = new Process())
                {
                    p.StartInfo.FileName = "DISM";
                    p.StartInfo.Arguments = "/Online /NoRestart /Remove-Package" + sb.ToString();
                    p.StartInfo.CreateNoWindow = true;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardError = true;

                    //Console.WriteLine("DISM command: " + p.StartInfo.FileName + " " + p.StartInfo.Arguments);

                    p.OutputDataReceived += new DataReceivedEventHandler(delegate (object sender, DataReceivedEventArgs e)
                    {
                        Console.WriteLine(e.Data);
                    });
                    p.ErrorDataReceived += new DataReceivedEventHandler(delegate (object sender, DataReceivedEventArgs e)
                    {
                        Console.WriteLine(e.Data);
                    });

                    p.Start();
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();

                    p.WaitForExit();

                    p.CancelOutputRead();
                    p.CancelErrorRead();
                }
            }
            KB2976978List.Clear();
            sb.Clear();

            System.Environment.Exit(0);
        }
    }
}
