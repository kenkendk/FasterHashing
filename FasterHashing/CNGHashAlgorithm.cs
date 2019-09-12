using System;
using System.Security.Cryptography;

namespace FasterHashing
{
    /// <summary>
    /// Wrapper class for creating CNG based hash algorithms
    /// </summary>
    public static class CNGHashAlgorithm
    {
        /// <summary>
        /// Create the specified hash algorithm with the CNG implementation.
        /// </summary>
        /// <returns>The created algorithm, or null if it could not be created.</returns>
        /// <param name="name">The name of the algorithm to create.</param>
        /// <param name="allowfallback">If set to <c>true</c> allow fallback to <seealso cref="HashAlgorithm.Create(string)"/>.</param>
        public static HashAlgorithm Create(string name, bool allowfallback = true)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new MD5Cng();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new SHA1Cng();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new SHA256Cng();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new SHA384Cng();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new SHA512Cng();
            if (allowfallback)
                return HashAlgorithm.Create(name);
            
            return null;
        }
    }
}
