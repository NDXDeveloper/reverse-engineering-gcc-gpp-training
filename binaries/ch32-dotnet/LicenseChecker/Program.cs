using System;

namespace LicenseChecker
{
    /// <summary>
    /// Entry point — License verification application.
    /// Training target for Chapter 32 (dynamic .NET analysis).
    ///
    /// Expected key format: XXXX-XXXX-XXXX-XXXX (hexadecimal characters)
    /// Validation combines C# checks and P/Invoke calls
    /// to libnative_check.so (compiled with GCC).
    /// </summary>
    class Program
    {
        private const string Banner = @"
    ╔══════════════════════════════════════════╗
    ║   LicenseChecker v3.2.1 — Ch.32 RE Lab  ║
    ║   © 2025 RE Training GCC/G++           ║
    ╚══════════════════════════════════════════╝";

        static int Main(string[] args)
        {
            Console.WriteLine(Banner);
            Console.WriteLine();

            string username;
            string licenseKey;

            if (args.Length >= 2)
            {
                username   = args[0];
                licenseKey = args[1];
            }
            else
            {
                Console.Write("  Username: ");
                username = Console.ReadLine() ?? "";

                Console.Write("  License key       : ");
                licenseKey = Console.ReadLine() ?? "";
            }

            Console.WriteLine();

            if (string.IsNullOrWhiteSpace(username))
            {
                Console.WriteLine("  [!] Username cannot be empty.");
                return 1;
            }

            var validator = new LicenseValidator();
            var result    = validator.Validate(username, licenseKey);

            if (result.IsValid)
            {
                Console.WriteLine("  ╔═══════════════════════════════════╗");
                Console.WriteLine("  ║  ✅  Valid license! Welcome. ║");
                Console.WriteLine("  ╚═══════════════════════════════════╝");
                Console.WriteLine();
                Console.WriteLine($"  User: {username}");
                Console.WriteLine($"  Level:       {result.LicenseLevel}");
                Console.WriteLine($"  Expiration:  {result.ExpirationInfo}");
                return 0;
            }
            else
            {
                Console.WriteLine("  ╔═══════════════════════════════════════╗");
                Console.WriteLine("  ║  ❌  Invalid license.               ║");
                Console.WriteLine("  ╚═══════════════════════════════════════╝");
                Console.WriteLine();
                Console.WriteLine($"  Reason: {result.FailureReason}");
                return 1;
            }
        }
    }
}
