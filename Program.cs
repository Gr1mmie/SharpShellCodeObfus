using System;
using System.Linq;
using System.Threading;
using static System.Console;

namespace SharpShellcodeObfus
{
    class Program
    {
        public static int rot_index;
        public static int bytes_index;
        public static string rot = "";
        public static string bytes = "";
        public static bool original = false;

        public static void shellcode_encode(string shifts, string shellcode){

            shifts = rot;
            shellcode = bytes;

            String[] decArray = bytes.Split(',');
            byte[] decToHex = decArray.Select(s => byte.Parse(s)).ToArray();
            int decToHex_len = decToHex.Length;
            byte[] shiftedDec = new byte[decToHex_len];
            String[] plain = new string[decToHex_len];
            String[] HexArray = new string[decToHex_len];
            string nextVal;

            for (int bID = 0; bID < decToHex.Length; bID++){
                if (decToHex[bID].ToString().Length == 1){
                    nextVal = "0x0" + decToHex[bID].ToString("X").ToLower();
                    plain[bID] = nextVal;
                }else{
                    nextVal = "0x" + decToHex[bID].ToString("X").ToLower();
                    plain[bID] = nextVal;
                }
            }

            int.TryParse(rot, out int rotations);

            for (int bID = 0; bID < decToHex_len; bID++) { shiftedDec[bID] = (byte)((int)decToHex[bID] + rotations); }

            for (int bID = 0; bID < shiftedDec.Length; bID++){
                if (shiftedDec[bID].ToString().Length == 1){
                    nextVal = "0x0" + shiftedDec[bID].ToString("X").ToLower();
                    HexArray[bID] = nextVal;
                }else{
                    nextVal = "0x" + shiftedDec[bID].ToString("X").ToLower();
                    HexArray[bID] = nextVal;
                }
            }

            Thread.Sleep(100);
            WriteLine("Shifting bytes by {0} rotations...\n", rotations);
            Thread.Sleep(1500);
            WriteLine("Encoded Shellcode:\nbyte[] buf = new byte[{0}] {{ {1} }};\n", HexArray.Length, string.Join(", ", HexArray));

            WriteLine("Revert to original shellcode:\n" +
                "SharpShellcodeObfus.exe -o -r {1} -s {0}\n"
                , string.Join(",", HexArray), shifts);

            WriteLine("Decoding routine:\nbyte[] buf = new byte[{0}] {{ {1} }};\n" +
                "for (int bID = 0; bID < buf.Length; bID++){{ buf[bID] = (byte)(((uint)buf[bID] - ({2})) & 0xFF); }}",
                HexArray.Length, string.Join(", ", HexArray), rotations.ToString(""));
        }

        public static void shellcode_decode(string shifts, string shellcode)
        {
            shifts = rot;
            shellcode = bytes;

            String[] decArray = bytes.Split(',');
            byte[] decToHex = decArray.Select(s => byte.Parse(s)).ToArray();
            int decToHex_len = decToHex.Length;
            byte[] shiftedDec = new byte[decToHex_len];
            String[] plain = new string[decToHex_len];
            String[] Decoded = new string[decToHex_len];
            string nextVal;

            for (int bID = 0; bID < decToHex.Length; bID++){
                if (decToHex[bID].ToString().Length == 1){
                    nextVal = "0x0" + decToHex[bID].ToString("X").ToLower();
                    plain[bID] = nextVal;
                }else{
                    nextVal = "0x" + decToHex[bID].ToString("X").ToLower();
                    plain[bID] = nextVal;
                }
            }

            int.TryParse(rot, out int rotations);

            rotations *= -1;
            
            for (int bID = 0; bID < decToHex_len; bID++) { shiftedDec[bID] = (byte)((int)decToHex[bID] + (rotations)); }

            for (int bID = 0; bID < shiftedDec.Length; bID++){
                if (shiftedDec[bID].ToString().Length == 1){
                    nextVal = "0x0" + shiftedDec[bID].ToString("X").ToLower();
                    Decoded[bID] = nextVal;
                }else{
                    nextVal = "0x" + shiftedDec[bID].ToString("X").ToLower();
                    Decoded[bID] = nextVal;
                }
            }

            Thread.Sleep(100);
            WriteLine("Reverting shellcode by {0} rotations...\n", shifts);
            Thread.Sleep(1500);
            WriteLine("Reverted shellcode:\nbyte[] buf = new byte[{0}] {{ {1} }}", Decoded.Length, string.Join(", ", Decoded));

        }

        public static void convert(string dec){
            long con;
            long.TryParse(dec, out con);

            long con_count = con;
            int remainder_count = 0;
            int hex_index = 0;

            while (con_count % 16 != 0 || con_count != 0) { con_count /= 16; remainder_count++; }
            String[] hex = new string[remainder_count];

            while (con % 16 != 0 || con != 0) { long remainder = con % 16; hex[hex_index] = remainder.ToString("X"); hex_index++; con /= 16; }

            Thread.Sleep(1500);
            Array.Reverse(hex);
            Write("Dec: {0}\nHex: 0x{1}", dec, string.Join("", hex));

        }

        public static void Banner() {
            WriteLine("   ______                 ______       ____            __    ____  __   ___       ");
            WriteLine("  / __/ /  ___ ________  / __/ /  ___ / / /______  ___/ /__ / __ \\/ /  / _/_ _____");
            WriteLine(" _\\ \\/ _ \\/ _ `/ __/ _ \\_\\ \\/ _ \\/ -_) / / __/ _ \\/ _  / -_) /_/ / _ \\/ _/ // (_-<");
            WriteLine("/___/_//_/\\_,_/_/ / .__/___/_//_/\\__/_/_/\\__/\\___/\\_,_/\\__/\\____/_.__/_/ \\_,_/___/");
            WriteLine("                 /_/                                                              ");
        }
        [STAThread]
        static void Main(string[] args)
        {

            if (args.Length == 0){
                WriteLine("No arguemnts supplied, use SharpShellcodeObfus.exe -h for help");
                System.Environment.Exit(0);
            }else if (args.Length == 4){
                if (args.Contains("-r") && args.Contains("-s")){
                    rot_index = Array.IndexOf(args, "-r");
                    rot = args[rot_index + 1];
                    bytes_index = Array.IndexOf(args, "-s");
                    bytes = args[bytes_index + 1];
                }else{
                    WriteLine("Incorrect syntax, use SharpShellcodeObfus.exe -h for help");
                    System.Environment.Exit(0);
                }
            }else if (args.Length == 5){
                if (args.Contains("-r") && args.Contains("-s") && args.Contains("-o")){
                    rot_index = Array.IndexOf(args, "-r");
                    rot = args[rot_index + 1];
                    bytes_index = Array.IndexOf(args, "-s");
                    bytes = args[bytes_index + 1];
                    original = true;
                }else{
                    WriteLine("Incorrect syntax, use SharpShellcodeObfus.exe -h for help");
                    System.Environment.Exit(0);
                }
            }else if (args.Length == 1){
                if (args.Contains("-h")){
                    Banner();
                    WriteLine("\nUsage: SharpShellcodeObfus.exe [-o] { -r rotations} { -s shellcode}" +
                        "\nRequired arguments:\n\t-r, rotations\tDetermines number of rotations used to encrypt shellcode" +
                        "\n\t-s, shellcode\tShellcode to encrypt in bytes" +
                        "\nOptional arguments:\n\t-o, original\t Revert shellcode to original state" + 
                        "\n\t-c, convert\t convert a decimal value to hex");
                    System.Environment.Exit(0);
                }
            }else if (args.Length == 2){
                if (args.Contains("-c")){
                    convert(args[1]);
                    System.Environment.Exit(0);
                }
                else {
                    System.Environment.Exit(0);
                }
            }else{
                WriteLine("Incorrect syntax, use SharpShellcodeObfus.exe -h for help");
                System.Environment.Exit(0);
            }

            if (!original){ 
                shellcode_encode(rot, bytes);
            }else{
                shellcode_decode(rot, bytes);
            }

        }
    }
}
