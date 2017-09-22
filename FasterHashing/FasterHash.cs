using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FasterHashing
{
    /// <summary>
    /// The known hash algorithm implementations
    /// </summary>
    public enum HashImplementation
    {
        /// <summary>
        /// Denotes any implementation
        /// </summary>
        Any,
        /// <summary>
        /// Specifies using OpenSSL 1.0
        /// </summary>
        OpenSSL10,
        /// <summary>
        /// Specifies using OpenSSL 1.1
        /// </summary>
        OpenSSL11,
        /// <summary>
        /// Specifies using CNG
        /// </summary>
        CNG,
        /// <summary>
        /// Specifies Apple's CommonCrypto library
        /// </summary>
        AppleCommonCrypto,
        /// <summary>
        /// Specifies using the managed version
        /// </summary>
        Managed
    }

    /// <summary>
    /// Helper methods for using FasterHashing
    /// </summary>
    public static class FasterHash
    {
        /// <summary>
        /// The best implementation found
        /// </summary>
        private static HashImplementation _implementation = HashImplementation.Any;

        /// <summary>
        /// Gets the prefered hash implementation
        /// </summary>
        public static HashImplementation PreferedImplementation
        {
            get
            {
                if (_implementation == HashImplementation.Any)
                    _implementation = ProbeForImplementations();

                return _implementation;
            }
        }

        /// <summary>
        /// Dictionary with know implementation types
        /// </summary>
        private static readonly Dictionary<string, Type> _knowntypes = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Create the specified hashing algorithm.
        /// </summary>
        /// <returns>The created algorithm.</returns>
        /// <param name="algorithm">The name of the hash algorithm to create.</param>
        /// <param name="allowfallback">If set to <c>true</c>, the `<seealso cref="System.Security.Cryptography.HashAlgorithm.Create()"/> method is called if not implementation could be loaded</param>
        /// <param name="implementation">The hash implementation toy use</param>
        public static HashAlgorithm Create(string algorithm, bool allowfallback = true, HashImplementation implementation = HashImplementation.Any)
        {
            HashAlgorithm result = null;

            // If we are not asked for a particular version, pick the best we found
            if (implementation == HashImplementation.Any)
                implementation = PreferedImplementation;

            switch (implementation)
            {
                case HashImplementation.OpenSSL10:
                    result = OpenSSL10HashAlgorithm.Create(algorithm);
                    break;
                case HashImplementation.OpenSSL11:
                    result = OpenSSL10HashAlgorithm.Create(algorithm);
                    break;
                case HashImplementation.CNG:
                    result = CNGHashAlgorithm.Create(algorithm, false);
                    break;
                case HashImplementation.AppleCommonCrypto:
                    result = AppleCommonCryptoHashAlgorithm.Create(algorithm);
                    break;
                case HashImplementation.Managed:
                    result = HashAlgorithm.Create(algorithm);
                    break;
            }

            if (allowfallback)
                result = result ?? HashAlgorithm.Create(algorithm);

            return result;
        }

        /// <summary>
        /// Probes for existing libraries
        /// </summary>
        /// <returns>The for implementations.</returns>
        private static HashImplementation ProbeForImplementations()
        {
            System.Diagnostics.Trace.WriteLine("Probing for hashing libraries");

            if (ShouldUseCNG)
            {
                if (string.Equals(Environment.GetEnvironmentVariable("FH_DISABLE_CNG"), "1", StringComparison.OrdinalIgnoreCase))
                {
                    System.Diagnostics.Trace.WriteLine("CNG use is disableds");
                }
                else
                {
                    return HashImplementation.CNG;
                }
			}

            if (string.Equals(Environment.GetEnvironmentVariable("FH_DISABLE_APPLECC"), "1", StringComparison.OrdinalIgnoreCase))
            {
				System.Diagnostics.Trace.WriteLine("Apple CommonCrypto disabled, not probing");
			}
            else
            {
                if (AppleCommonCryptoHashAlgorithm.IsSupported)
                {
                    System.Diagnostics.Trace.WriteLine($"Found Apple CommonCrypto");
                    return HashImplementation.AppleCommonCrypto;
                }
            }

			string version = null;
			if (string.Equals(Environment.GetEnvironmentVariable("FH_DISABLE_OPENSSL11"), "1", StringComparison.OrdinalIgnoreCase))
			{
				System.Diagnostics.Trace.WriteLine("OpenSSL 1.1 disabled, not probing");
			}
			else
			{
				version = OpenSSL11Version;
				if (version != null)
				{
					System.Diagnostics.Trace.WriteLine($"Found OpenSSL 1.1 library with version string: {version}");
					return HashImplementation.OpenSSL11;
				}
			}

            if (string.Equals(Environment.GetEnvironmentVariable("FH_DISABLE_OPENSSL10"), "1", StringComparison.OrdinalIgnoreCase))
            {
				System.Diagnostics.Trace.WriteLine("OpenSSL 1.0 disabled, not probing");
			}
            else
            {
				version = OpenSSL10Version;
				if (version != null)
                {
                    System.Diagnostics.Trace.WriteLine($"Found OpenSSL 1.0 library with version string: {version}");
					return HashImplementation.OpenSSL10;
				}
            }

            return HashImplementation.Managed;
		}

        /// <summary>
        /// Gets the version string from the installed OpenSSL 1.0 library, or null if no such library is found
        /// </summary>
        public static string OpenSSL10Version
        {
            get
            {
                try { return Marshal.PtrToStringAuto(InteropOpenSSL10.SSLeay_version()); }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL10: {ex}"); }

                return null;
			}
        }

		/// <summary>
		/// Gets the version string from the installed OpenSSL 1.1 library, or null if no such library is found
		/// </summary>
		public static string OpenSSL11Version
		{
			get
			{
				try { return Marshal.PtrToStringAuto(InteropOpenSSL11.OpenSSL_version()); }
				catch (Exception ex) { System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL11: {ex}"); }

				return null;
			}
		}

        /// <summary>
        /// Gets a value indicating if the CNG version is likely to yield a speedup
        /// </summary>
        public static bool ShouldUseCNG
        {
            get
            {
                return Environment.OSVersion.Platform != PlatformID.Unix && Environment.OSVersion.Platform != PlatformID.MacOSX;
            }
        }

        /// <summary>
        /// Returns a value indicating if the specific implementation is supported on this system
        /// </summary>
        /// <returns><c>true</c>, if implementation was supportsed, <c>false</c> otherwise.</returns>
        /// <param name="implementation">The implementation to test for.</param>
        public static bool SupportsImplementation(HashImplementation implementation)
        {
			switch (implementation)
			{
				case HashImplementation.OpenSSL10:
                    return OpenSSL10Version != null;
				case HashImplementation.OpenSSL11:
					return OpenSSL11Version != null;
                case HashImplementation.AppleCommonCrypto:
                    return AppleCommonCryptoHashAlgorithm.IsSupported;
				case HashImplementation.CNG:
				case HashImplementation.Managed:
                case HashImplementation.Any:
                    return true;
			}

            return false;
		}

	}
}
