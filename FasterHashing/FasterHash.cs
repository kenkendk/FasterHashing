using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Channels;
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
        /// Specifies using OpenSSL 3
        /// </summary>
        OpenSSL3,
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
            set
            {
                if (value == HashImplementation.Any)
                    throw new ArgumentException($"Cannot set {nameof(PreferedImplementation)} to {nameof(HashImplementation.Any)}");
                _implementation = value;
            }
        }

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
                    result = OpenSSL11HashAlgorithm.Create(algorithm);
                    break;
                case HashImplementation.OpenSSL3:
                    result = OpenSSL3HashAlgorithm.Create(algorithm);
                    break;
                case HashImplementation.CNG:
                    result = CNGHashAlgorithm.Create(algorithm, false);
                    break;
                case HashImplementation.AppleCommonCrypto:
                    result = AppleCommonCryptoHashAlgorithm.Create(algorithm);
                    break;
                //case HashImplementation.Managed:
                default:
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

            var env = Environment.GetEnvironmentVariable("FH_LIBRARY") ?? string.Empty;

            // First try fully named versions
            HashImplementation impl;
            if (Enum.TryParse(env, true, out impl) && impl != HashImplementation.Any)
                return impl;

            // Then try common names for AppleCommonCrypto
            if (new[] { "apple", "applecc", "osx", "macos" }.Any(x => string.Equals(x, env)))
            {
                if (SupportsImplementation(HashImplementation.AppleCommonCrypto))
                    return HashImplementation.AppleCommonCrypto;
            }

            // Then try common names for OpenSSL
            if (new[] { "openssl", "ssleay", "ssl" }.Any(x => string.Equals(x, env)))
            {
                if (SupportsImplementation(HashImplementation.OpenSSL3))
                    return HashImplementation.OpenSSL3;
                if (SupportsImplementation(HashImplementation.OpenSSL11))
                    return HashImplementation.OpenSSL11;
                if (SupportsImplementation(HashImplementation.OpenSSL10))
                    return HashImplementation.OpenSSL10;
                if (SupportsImplementation(HashImplementation.AppleCommonCrypto))
                    return HashImplementation.AppleCommonCrypto;
            }

            // Then test if CNG is an option
            if (ShouldUseCNG)
            {
                if (string.Equals(Environment.GetEnvironmentVariable("FH_DISABLE_CNG"), "1", StringComparison.OrdinalIgnoreCase))
                {
                    System.Diagnostics.Trace.WriteLine("CNG use is disabled");
                }
                else
                {
                    return HashImplementation.CNG;
                }
            }

            // Or if we should use AppleCommonCrypto
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

            // Finally test for OpenSSL versions, newest first
            string version = null;
            if (string.Equals(Environment.GetEnvironmentVariable("FH_DISABLE_OPENSSL3"), "1", StringComparison.OrdinalIgnoreCase))
            {
                System.Diagnostics.Trace.WriteLine("OpenSSL 3 disabled, not probing");
            }
            else
            {
                version = OpenSSL3Version;
                if (version != null)
                {
                    System.Diagnostics.Trace.WriteLine($"Found OpenSSL 3 library with version string: {version}");
                    return HashImplementation.OpenSSL3;
                }
            }

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

            // Finally, fall back to the managed version
            return HashImplementation.Managed;
        }

        /// <summary>
        /// Gets the version string from the installed OpenSSL 1.0 library, or null if no such library is found
        /// </summary>
        public static string OpenSSL10Version
        {
            get
            {
                try { return OpenSSL10HashAlgorithm.SSLeay_version(); }
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
                // assume LibreSSL API-compatibility with OpenSSL 1.1
                try {
                    string version;
                    if ((version = OpenSSL11HashAlgorithm.OpenSSL_version()).Contains("OpenSSL 1.1.") ||
                         version.Contains("LibreSSL") )
                        return version;
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL11/ LibreSSL: {ex}"); }

                return null;
            }
        }

        /// <summary>
        /// Gets the version string from the installed OpenSSL 1.1 library, or null if no such library is found
        /// </summary>
        public static string OpenSSL3Version
        {
            get
            {
                try
                {
                    string version;
                    if ( (version = OpenSSL3HashAlgorithm.OpenSSL_version()).Contains("OpenSSL 3."))
                        return version;
                }
                catch (Exception ex) { System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL3: {ex}"); }

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
        /// Gets all supported hash implementations
        /// </summary>
        /// <value>The supported implementations.</value>
        public static IEnumerable<HashImplementation> SupportedImplementations
        {
            get
            {
                return Enum.GetValues(typeof(HashImplementation))
                    .OfType<HashImplementation>()
                    .Where(x => x != HashImplementation.Any)
                    .Where(x => SupportsImplementation(x));

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
                case HashImplementation.OpenSSL3:
                    return OpenSSL3Version != null;
                case HashImplementation.AppleCommonCrypto:
                    return AppleCommonCryptoHashAlgorithm.IsSupported;
                //case HashImplementation.CNG:
                //case HashImplementation.Managed:
                //case HashImplementation.Any:
                default:
                    return true;
            }
        }

        /// <summary>
        /// Performs a measurement for the number of hashes pr second for the given algorithm and implementation
        /// </summary>
        /// <returns>The number of hashes pr second.</returns>
        /// <param name="algorithm">The algorithm to test with.</param>
        /// <param name="implementation">The implementation to test.</param>
        /// <param name="blocksize">The size of the blocks being hashed.</param>
        /// <param name="hashesprround">The number of hashes between each time check.</param>
        /// <param name="measureseconds">The number of seconds to measure.</param>
        /// <param name="bufferoffset">The number of bytes to offset the buffer for measuring non-aligned performance</param>
        public static long TestHashesPrSecond(string algorithm = "SHA256", HashImplementation implementation = HashImplementation.Any, int blocksize = 102400, int hashesprround = 1000, float measureseconds = 2f, int bufferoffset = 0)
        {
            using (var alg = Create(algorithm, false, implementation))
            {
                if (alg == null)
                    return 0;

                var st = DateTime.Now;
                var target = st.Ticks + TimeSpan.FromSeconds(measureseconds).Ticks;

                var buffer = new byte[blocksize + bufferoffset];
                var performed = 0L;

                alg.Initialize();
                while (DateTime.Now.Ticks < target)
                {
                    for (var i = 0; i < hashesprround; i++)
                        alg.TransformBlock(buffer, bufferoffset, blocksize, buffer, bufferoffset);
                    performed++;
                }

                alg.TransformFinalBlock(buffer, 0, 0);
                var elapsed = DateTime.Now - st;

                return (long)((performed * hashesprround * (blocksize / 64)) / elapsed.TotalSeconds);
            }
        }

        /// <summary>
        /// Performs a measurement for the number of hashes pr second for the given algorithm and all supported implementations
        /// </summary>
        /// <returns>The number of hashes pr second for each implementation.</returns>
        /// <param name="algorithm">The algorithm to test with.</param>
        /// <param name="blocksize">The size of the blocks being hashed.</param>
        /// <param name="hashesprround">The number of hashes between each time check.</param>
        /// <param name="measureseconds">The number of seconds to measure.</param>
        /// <param name="bufferoffset">The number of bytes to offset the buffer for measuring non-aligned performance</param>
        public static IEnumerable<Tuple<HashImplementation, long>> MeasureImplementations(string algorithm = "SHA256", int blocksize = 102400, int hashesprround = 1000, float measureseconds = 2f, int bufferoffset = 0)
        {
            return
                SupportedImplementations
                    .Select(x => new Tuple<HashImplementation, long>(x, TestHashesPrSecond(algorithm, x, blocksize, hashesprround, measureseconds, bufferoffset)));
        }

        /// <summary>
        /// Measures all supported implementations and picks the fastest
        /// </summary>
        /// <param name="algorithm">The algorithm to test with.</param>
        /// <param name="blocksize">The size of the blocks being hashed.</param>
        /// <param name="hashesprround">The number of hashes between each time check.</param>
        /// <param name="measureseconds">The number of seconds to measure.</param>
        /// <param name="bufferoffset">The number of bytes to offset the buffer for measuring non-aligned performance</param>
        public static void SetDefaultImplementationToFastest(string algorithm = "SHA256", int blocksize = 102400, int hashesprround = 1000, float measureseconds = 2f, int bufferoffset = 0)
        {
            if (SupportedImplementations.Count() == 1)
                PreferedImplementation = SupportedImplementations.First();
            else
                PreferedImplementation =
                    MeasureImplementations(algorithm, blocksize, hashesprround, measureseconds, bufferoffset)
                        .OrderByDescending(x => x.Item2)
                        .Select(x => x.Item1)
                        .First();
        }

    }
}
