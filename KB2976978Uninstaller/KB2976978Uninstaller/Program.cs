using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.Security;

namespace KB2976978Uninstaller
{
    class Program
    {
        static void Main(string[] args)
        {
            var myProcToken = new AccessTokenProcess(Process.GetCurrentProcess().Id, TokenAccessType.TOKEN_ALL_ACCESS | TokenAccessType.TOKEN_ADJUST_PRIVILEGES);
            try
            {
                myProcToken.EnablePrivilege(new TokenPrivilege(TokenPrivilege.SE_TAKE_OWNERSHIP_NAME, true));
            }
            catch (Exception)
            {
                Console.WriteLine("管理者として実行してください。");
                System.Environment.Exit(740);
            }

            List<String> KB2976978List = new List<string>();

            using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"))
            {
                foreach (string subkeyname in registryKey.GetSubKeyNames())
                {
                    if (subkeyname.StartsWith("Package_for_KB2976978~"))
                    {
                        Console.WriteLine(subkeyname);
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
