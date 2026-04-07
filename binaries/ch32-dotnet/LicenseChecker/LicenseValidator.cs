using System;
using System.Linq;
using System.Text;

namespace LicenseChecker
{
    /// <summary>
    /// License validation result.
    /// </summary>
    public class ValidationResult
    {
        public bool   IsValid        { get; set; }
        public string FailureReason  { get; set; } = "";
        public string LicenseLevel   { get; set; } = "Standard";
        public string ExpirationInfo { get; set; } = "Perpetual";
    }

    /// <summary>
    /// License validation engine.
    ///
    /// Key scheme: AAAA-BBBB-CCCC-DDDD
    ///
    ///   Segment AAAA: derived from username (FNV-1a hash, pure C#)
    ///   Segment BBBB: validated via P/Invoke (libnative_check.so)
    ///   Segment CCCC: cross XOR of segments A and B with rotation + mixing
    ///   Segment DDDD: final checksum combining managed and native parts
    ///
    /// RE points of interest:
    ///   - §32.1 : breakpoint on Validate(), follow the flow step by step
    ///   - §32.2 : hook ComputeUserHash / ComputeCrossXor with Frida CLR
    ///   - §32.3 : intercept P/Invoke calls to libnative_check.so
    ///   - §32.4 : patch conditional jumps in Validate()
    /// </summary>
    public class LicenseValidator
    {
        // ── Internal constants (discoverable via strings / decompilation) ──

        private static readonly byte[] MagicSalt =
            { 0x52, 0x45, 0x56, 0x33, 0x52, 0x53, 0x45, 0x21 };
        // ASCII : "REV3RSE!"

        private const uint HashSeed  = 0x811C9DC5;  // FNV-1a offset basis (32-bit)
        private const uint HashPrime = 0x01000193;   // FNV-1a prime

        // ══════════════════════════════════════════════════════════════
        //  Main entry point
        // ══════════════════════════════════════════════════════════════

        public ValidationResult Validate(string username, string licenseKey)
        {
            var result = new ValidationResult();

            // ── Step 1 — Format verification ──
            if (!ValidateStructure(licenseKey, out string[] segments))
            {
                result.IsValid       = false;
                result.FailureReason = "Invalid format. Expected: XXXX-XXXX-XXXX-XXXX (hex)";
                return result;
            }

            // ── Step 2 — Segment A: username hash (pure C#) ──
            uint expectedA = ComputeUserHash(username);
            uint actualA   = Convert.ToUInt32(segments[0], 16);

            if (actualA != expectedA)
            {
                result.IsValid       = false;
                result.FailureReason = "Invalid segment 1 (related to username).";
                return result;
            }

            // ── Step 3 — Segment B: native verification (P/Invoke) ──
            uint actualB   = Convert.ToUInt32(segments[1], 16);
            bool segBValid = CheckSegmentB(username, actualB);

            if (!segBValid)
            {
                result.IsValid       = false;
                result.FailureReason = "Invalid segment 2 (native verification).";
                return result;
            }

            // ── Step 4 — Segment C: cross XOR (pure C#) ──
            uint expectedC = ComputeCrossXor(actualA, actualB);
            uint actualC   = Convert.ToUInt32(segments[2], 16);

            if (actualC != expectedC)
            {
                result.IsValid       = false;
                result.FailureReason = "Invalid segment 3 (cross check).";
                return result;
            }

            // ── Step 5 — Segment D: final checksum (native + managed) ──
            uint expectedD = ComputeFinalChecksum(actualA, actualB, actualC, username);
            uint actualD   = Convert.ToUInt32(segments[3], 16);

            if (actualD != expectedD)
            {
                result.IsValid       = false;
                result.FailureReason = "Invalid segment 4 (final checksum).";
                return result;
            }

            // ── Success ──
            result.IsValid        = true;
            result.LicenseLevel   = DeriveLicenseLevel(actualA);
            result.ExpirationInfo = "Perpetual";
            return result;
        }

        // ══════════════════════════════════════════════════════════════
        //  Internal methods
        // ══════════════════════════════════════════════════════════════

        /// <summary>
        /// Checks that the key has the format XXXX-XXXX-XXXX-XXXX (hex).
        /// IL patching target: invert the return to bypass the format check.
        /// </summary>
        private bool ValidateStructure(string key, out string[] segments)
        {
            segments = Array.Empty<string>();

            if (string.IsNullOrWhiteSpace(key))
                return false;

            string[] parts = key.Trim().ToUpperInvariant().Split('-');

            if (parts.Length != 4)
                return false;

            foreach (string part in parts)
            {
                if (part.Length != 4)
                    return false;

                if (!part.All(c => "0123456789ABCDEF".Contains(c)))
                    return false;
            }

            segments = parts;
            return true;
        }

        /// <summary>
        /// FNV-1a hash of username salted with MagicSalt, folded to 16 bits.
        /// Produces the expected segment A of the key.
        /// </summary>
        private uint ComputeUserHash(string username)
        {
            byte[] usernameBytes = Encoding.UTF8.GetBytes(
                username.ToLowerInvariant());

            // Concatenate username + salt
            byte[] salted = new byte[usernameBytes.Length + MagicSalt.Length];
            Array.Copy(usernameBytes, 0, salted, 0, usernameBytes.Length);
            Array.Copy(MagicSalt, 0, salted, usernameBytes.Length, MagicSalt.Length);

            // FNV-1a 32-bit
            uint hash = HashSeed;
            for (int i = 0; i < salted.Length; i++)
            {
                hash ^= salted[i];
                hash *= HashPrime;
            }

            // Fold-XOR 32→16 bits
            uint folded = (hash >> 16) ^ (hash & 0xFFFF);
            return folded & 0xFFFF;
        }

        /// <summary>
        /// Validates segment B via the native library (P/Invoke).
        /// The hash is computed C-side with a different salt ("NATIVERE").
        /// </summary>
        private bool CheckSegmentB(string username, uint segmentB)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(
                    username.ToLowerInvariant());
                uint expected = NativeBridge.ComputeNativeHash(data, data.Length);
                expected = expected & 0xFFFF;
                return segmentB == expected;
            }
            catch (DllNotFoundException)
            {
                Console.WriteLine(
                    "  [!] libnative_check.so not found. "
                  + "Check LD_LIBRARY_PATH.");
                return false;
            }
            catch (EntryPointNotFoundException ex)
            {
                Console.WriteLine(
                    $"  [!] Native function not found : {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Computes segment C via cross XOR with rotation and mixing.
        /// Algorithm:
        ///   1. Left rotation of segA (5 bits, on 16 bits)
        ///   2. XOR with segB
        ///   3. Multiplication by 0x9E37, masked to 16 bits
        ///   4. XOR final with 0xA5A5
        /// </summary>
        private uint ComputeCrossXor(uint segA, uint segB)
        {
            // Left rotation of 5 bits on 16 bits
            uint rotA   = ((segA << 5) | (segA >> 11)) & 0xFFFF;
            uint result = rotA ^ segB;

            // Multiplicative mixing
            result = (result * 0x9E37) & 0xFFFF;
            result ^= 0xA5A5;

            return result & 0xFFFF;
        }

        /// <summary>
        /// Computes segment D: final checksum combining managed part
        /// (sum of the 3 segments) and native part (compute_checksum via P/Invoke).
        /// The result is the XOR of both parts, on 16 bits.
        /// </summary>
        private uint ComputeFinalChecksum(
            uint segA, uint segB, uint segC, string username)
        {
            // Managed part: sum of the three segments
            uint managed = (segA + segB + segC) & 0xFFFF;

            // Native part: checksum via P/Invoke
            try
            {
                uint nativePart = NativeBridge.ComputeChecksum(segA, segB, segC);
                nativePart = nativePart & 0xFFFF;

                // Final combination
                return (managed ^ nativePart) & 0xFFFF;
            }
            catch
            {
                return 0xDEAD;
            }
        }

        /// <summary>
        /// Determines the license level (cosmetic) from segment A.
        /// </summary>
        private string DeriveLicenseLevel(uint segA)
        {
            return (segA % 3) switch
            {
                0 => "Professional",
                1 => "Enterprise",
                _ => "Standard"
            };
        }
    }
} 
