using System;
using System.Runtime.InteropServices;

namespace LicenseChecker
{
    /// <summary>
    /// P/Invoke bridge to libnative_check.so (compiled with GCC).
    ///
    /// RE points of interest:
    ///   - §32.3 : these calls cross the managed → native boundary.
    ///     Interceptable with Frida on the native side (Interceptor.attach)
    ///     or by hooking the C# wrappers on the CLR side (frida-clr).
    ///   - The library is lazily loaded on the first call.
    ///   - LD_LIBRARY_PATH must point to the .so directory.
    /// </summary>
    internal static class NativeBridge
    {
        private const string LibName = "libnative_check.so";

        /// <summary>
        /// Computes a salted FNV-1a hash on a buffer (username UTF-8).
        /// Used to validate segment B.
        /// </summary>
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl,
                   EntryPoint = "compute_native_hash")]
        public static extern uint ComputeNativeHash(byte[] data, int length);

        /// <summary>
        /// Computes a combinatorial checksum from segments A, B, C.
        /// Used for the native part of segment D.
        /// </summary>
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl,
                   EntryPoint = "compute_checksum")]
        public static extern uint ComputeChecksum(uint segA, uint segB, uint segC);

        /// <summary>
        /// Complete integrity check on the native side.
        /// Not used in the main flow — present as a target
        /// exercise for Frida hooking (§32.2 / §32.3).
        /// </summary>
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl,
                   EntryPoint = "verify_integrity")]
        public static extern int VerifyIntegrity(
            [MarshalAs(UnmanagedType.LPStr)] string username,
            uint segA, uint segB, uint segC, uint segD);
    }
}
