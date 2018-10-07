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
        #region DOBON!'s code
        // コード参考元: https://dobon.net/vb/dotnet/system/shutdown.html
        // The MIT License (MIT)
        // 
        // Copyright(c) 2016 DOBON! <http://dobon.net>
        //
        // Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
        // The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
        // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        //[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        //private static extern IntPtr GetCurrentProcess();

        #region Windows API
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
        #endregion // Windows API

        #region method
        //所有者変更のためのセキュリティ特権を有効にする
        public static bool AdjustToken()
        {
            const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
            const uint TOKEN_QUERY = 0x8;
            const int SE_PRIVILEGE_ENABLED = 0x2;
            const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

            IntPtr procHandle = Process.GetCurrentProcess().Handle;

            //トークンを取得する
            IntPtr tokenHandle;
            if (!OpenProcessToken(procHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tokenHandle) ||
                Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine("Error: 0x" + Marshal.GetLastWin32Error().ToString("X8"));
                return false;
            }

            //LUIDを取得する
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.Attributes = SE_PRIVILEGE_ENABLED;
            tp.PrivilegeCount = 1;
            if (!LookupPrivilegeValue(null, SE_TAKE_OWNERSHIP_NAME, out tp.Luid) ||
                Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine("Error: 0x" + Marshal.GetLastWin32Error().ToString("X8"));
                if (!CloseHandle(tokenHandle) ||
                    Marshal.GetLastWin32Error() != 0)
                {
                    Console.WriteLine("Error: 0x" + Marshal.GetLastWin32Error().ToString("X8"));
                }
                return false;
            }

            //特権を有効にする
            if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) ||
                Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine("Error: 0x" + Marshal.GetLastWin32Error().ToString("X8"));
                if (!CloseHandle(tokenHandle) ||
                    Marshal.GetLastWin32Error() != 0)
                {
                    Console.WriteLine("Error: 0x" + Marshal.GetLastWin32Error().ToString("X8"));
                }
                return false;
            }

            //閉じる
            if (!CloseHandle(tokenHandle) ||
                Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine("Error: 0x" + Marshal.GetLastWin32Error().ToString("X8"));
                return false;
            }
            return true;
        }
        #endregion // method
        #endregion // DOBON!'s code

        #region method
        private static void ChangeRegKeyOwner(RegistryKey registryKey, IdentityReference identity)
        {
            RegistrySecurity nSubKeySec = registryKey.GetAccessControl(AccessControlSections.Owner);
            nSubKeySec.SetOwner(identity);
            registryKey.SetAccessControl(nSubKeySec);
        }

        private static void ChangeRegKeyFullControl(RegistryKey registryKey, IdentityReference identity)
        {
            RegistrySecurity nSubKeySec = registryKey.GetAccessControl(AccessControlSections.Access);
            RegistryAccessRule nAccRule = new RegistryAccessRule(identity, RegistryRights.FullControl, AccessControlType.Allow);
            nSubKeySec.AddAccessRule(nAccRule);
            registryKey.SetAccessControl(nSubKeySec);
            nSubKeySec.SetOwner(identity);
            registryKey.SetAccessControl(nSubKeySec);
        }

        private static string DismPackageNames(List<string> uninstallPackages)
        {
            StringBuilder dismPackageNames = new StringBuilder();
            foreach (string pn in uninstallPackages)
            {
                dismPackageNames.Append(" /PackageName:");
                dismPackageNames.Append(pn);
            }
            return dismPackageNames.ToString();
        }

        private static void UninstallPackages(List<string> uninstallPackages)
        {
            string dismPackageNames = DismPackageNames(uninstallPackages);

            Console.WriteLine();
            using (Process p = new Process())
            {
                p.StartInfo.FileName = "DISM";
                p.StartInfo.Arguments = "/Online /NoRestart /Remove-Package" + dismPackageNames;
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
        #endregion

        static void Main(string[] args)
        {
            // 所有者変更の特権を有効にする
            if (!AdjustToken())
                System.Environment.Exit(1);

            List<String> uninstallPackages = new List<string>();

            // パッケージの一覧があるレジストリキーを開く
            using (RegistryKey baseRegKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"))
            {
                foreach (string packageName in baseRegKey.GetSubKeyNames())
                {
                    if (packageName.StartsWith("Package_for_KB2976978~"))
                    {
                        Console.WriteLine(packageName);
                        uninstallPackages.Add(packageName);

                        // 目的のパッケージ名と一致するパッケージのOwnersキーを開く
                        const string ownersSubKey = "\\Owners";
                        using (RegistryKey ownersSubRegKey = baseRegKey.OpenSubKey(packageName + ownersSubKey))
                        {
                            // 目的のパッケージがアンインストール不可能になっているか
                            if ((int)ownersSubRegKey.GetValue(packageName) == 0x20080)
                            {
                                IdentityReference CurUser = WindowsIdentity.GetCurrent().User;

                                // 所有者の変更
                                using (RegistryKey rk = baseRegKey.OpenSubKey(packageName + ownersSubKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership | RegistryRights.ReadKey | RegistryRights.ReadPermissions))
                                    ChangeRegKeyOwner(rk, CurUser);

                                // アクセス許可の変更
                                using (RegistryKey rk = baseRegKey.OpenSubKey(packageName + ownersSubKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadKey | RegistryRights.ChangePermissions | RegistryRights.ReadPermissions))
                                    ChangeRegKeyFullControl(rk, CurUser);

                                // アンインストール可能な値に変更
                                using (RegistryKey rk = baseRegKey.OpenSubKey(packageName + ownersSubKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadKey | RegistryRights.SetValue))
                                    rk.SetValue(packageName, 0x20070);
                            }
                        }
                    }
                }
            }

            if (uninstallPackages.Count > 0)
                UninstallPackages(uninstallPackages);

            uninstallPackages.Clear();

            System.Environment.Exit(0);
        }
    }
}
