
using System;
using Microsoft.Win32;
using System.Threading;

class Program {
    static void Main() {
        Console.WriteLine("[*] Executing Simulated Trojan Registry Manipulation...");
        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\FedSec_Trojan_Test")) {
            for (int i = 1; i <= 25; i++) {
                key.SetValue("PersistenceHook_" + i, "C:\\Windows\\System32\\cmd.exe");
                Thread.Sleep(50);
            }
        }
        Thread.Sleep(3000);
        Registry.CurrentUser.DeleteSubKeyTree(@"Software\FedSec_Trojan_Test", false);
    }
}
