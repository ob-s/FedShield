
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
