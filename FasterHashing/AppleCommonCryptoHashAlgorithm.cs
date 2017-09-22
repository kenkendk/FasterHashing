using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FasterHashing
{
    /// <summary>
    /// The digest algorithm numbers
    /// </summary>
    internal enum AppleCCDigest : uint
    {
        /// <summary>
        /// No algorithm
        /// </summary>
		None = 0,
        /// <summary>
        /// The MD5 algorithm
        /// </summary>
		MD5 = 3,
        /// <summary>
        /// The SHA1 algorithm
        /// </summary>
		SHA1 = 8,
		/// <summary>
		/// The SHA224 algorithm
		/// </summary>
		SHA224 = 9,
		/// <summary>
		/// The SHA256 algorithm
		/// </summary>
		SHA256 = 10,
		/// <summary>
		/// The SHA384 algorithm
		/// </summary>
		SHA384 = 11,
		/// <summary>
		/// The SHA512 algorithm
		/// </summary>
		SHA512 = 12    
    }

    /// <summary>
    /// Apple common crypto hash algorithm interface.
    /// </summary>
    public static class AppleCommonCryptoHashAlgorithm
    {
		/// <summary>
		/// P/Invoke signatures for Apple CommonCrypto library
		/// </summary>
		private static class Interop
        {
			/// <summary>
			/// The library implementing Apple's CommonCrypto
			/// </summary>
			private const string DLLNAME = "System.dylib";

            /// <summary>
            /// Gets the digest size for a given algoritm
            /// </summary>
            /// <returns>The igest get output size.</returns>
            /// <param name="algorithm">Algorithm.</param>
			[DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern IntPtr CCDigestGetOutputSize(AppleCCDigest algorithm);
        }

        /// <summary>
        /// Gets the digest size in bytes for the given algorithm
        /// </summary>
        /// <returns>The digest size.</returns>
        /// <param name="algorithm">The algorithm to get the size for.</param>
        internal static int GetDigestSize(AppleCCDigest algorithm)
        {
            return (int)Interop.CCDigestGetOutputSize(AppleCCDigest.SHA256).ToInt64();
        }

        /// <summary>
        /// Gets a value indicating if CommonCrypto is supported on this system
        /// </summary>
        /// <value><c>true</c> if is supported; otherwise, <c>false</c>.</value>
        public static bool IsSupported
        {
            get
            {
                try { return GetDigestSize(AppleCCDigest.SHA256) == 32; }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine($"Failed to load CommonCrypto: {ex}"); }

                return false;
            }
        }

		/// <summary>
		/// Create the specified hash algorithm with the CNG implementation.
		/// </summary>
		/// <returns>The created algorithm, or null if it could not be created.</returns>
		/// <param name="name">The name of the algorithm to create.</param>
		public static HashAlgorithm Create(string name)
		{
			if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new AppleCommonCryptoMD5();
			if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new AppleCommonCryptoSHA1();
			if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
				return new AppleCommonCryptoSHA256();
			if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new AppleCommonCryptoSHA384();
			if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new AppleCommonCryptoSHA512();

			return null;
		}

    }
}
