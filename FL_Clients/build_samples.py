import subprocess
import os

CSC_PATH = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# 1. Simulated Ransomware Source Code (High File Write I/O)
ransom_cs = """
using System;
using System.IO;
using System.Threading;

class Program {
    static void Main() {
        Console.WriteLine("[*] Executing Simulated Ransomware File I/O...");
        for (int i = 1; i <= 35; i++) {
            string fname = "locked_file_" + i + ".tmp";
            File.WriteAllText(fname, "ENCRYPTED_PAYLOAD_SIMULATION_BLOCK_" + i);
            Thread.Sleep(50);
        }
        Thread.Sleep(3000);
        for (int i = 1; i <= 35; i++) {
            string fname = "locked_file_" + i + ".tmp";
            if (File.Exists(fname)) File.Delete(fname);
        }
    }
}
"""

# 2. Simulated Trojan Source Code (High Registry Manipulation)
trojan_cs = """
using System;
using Microsoft.Win32;
using System.Threading;

class Program {
    static void Main() {
        Console.WriteLine("[*] Executing Simulated Trojan Registry Manipulation...");
        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\\FedSec_Trojan_Test")) {
            for (int i = 1; i <= 25; i++) {
                key.SetValue("PersistenceHook_" + i, "C:\\\\Windows\\\\System32\\\\cmd.exe");
                Thread.Sleep(50);
            }
        }
        Thread.Sleep(3000);
        Registry.CurrentUser.DeleteSubKeyTree(@"Software\\FedSec_Trojan_Test", false);
    }
}
"""

with open("ransom_sim.cs", "w") as f:
    f.write(ransom_cs)

with open("trojan_sim.cs", "w") as f:
    f.write(trojan_cs)

print("[*] Compiling ransom_sim.exe and trojan_sim.exe...")
subprocess.run([CSC_PATH, "/out:ransom_sim.exe", "ransom_sim.cs"])
subprocess.run([CSC_PATH, "/out:trojan_sim.exe", "trojan_sim.cs"])

print("[+] Done! You now have real PE binaries: ransom_sim.exe and trojan_sim.exe")