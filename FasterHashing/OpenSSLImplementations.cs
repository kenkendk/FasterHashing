using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FasterHashing
{
    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_HashAlgorithm : HashAlgorithm
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL10_libssl_HashAlgorithm(string algorithm)
        {
            if (_first)
            {
                InteropOpenSSL10_libssl.OpenSSL_add_all_digests();
                _first = false;
            }

            m_digestmethod = InteropOpenSSL10_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL10 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_HashAlgorithmSHA512();
            try { return new OpenSSL10_libssl_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_HashAlgorithm : HashAlgorithm
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL10_libssl_so_1_0_HashAlgorithm(string algorithm)
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0.OpenSSL_add_all_digests();
                _first = false;
            }

            m_digestmethod = InteropOpenSSL10_libssl_so_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL10 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_HashAlgorithmSHA512();
            try { return new OpenSSL10_libssl_so_1_0_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_0_HashAlgorithm : HashAlgorithm
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL10_libssl_so_1_0_0_HashAlgorithm(string algorithm)
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0_0.OpenSSL_add_all_digests();
                _first = false;
            }

            m_digestmethod = InteropOpenSSL10_libssl_so_1_0_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_0_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL10 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_0_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA512();
            try { return new OpenSSL10_libssl_so_1_0_0_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libeay32_dll_HashAlgorithm : HashAlgorithm
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL10_libeay32_dll_HashAlgorithm(string algorithm)
        {
            if (_first)
            {
                InteropOpenSSL10_libeay32_dll.OpenSSL_add_all_digests();
                _first = false;
            }

            m_digestmethod = InteropOpenSSL10_libeay32_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libeay32_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libeay32_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libeay32_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libeay32_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libeay32_dll_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL10 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libeay32_dll_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libeay32_dll_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libeay32_dll_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libeay32_dll_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10_libeay32_dll_HashAlgorithmSHA512();
            try { return new OpenSSL10_libeay32_dll_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_HashAlgorithmMD5 : MD5
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL10_libssl_HashAlgorithmMD5()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL10_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_HashAlgorithmMD5 : MD5
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_HashAlgorithmMD5()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_0_HashAlgorithmMD5 : MD5
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_0_HashAlgorithmMD5()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_0_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libeay32_dll_HashAlgorithmMD5 : MD5
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL10_libeay32_dll_HashAlgorithmMD5()
        {
            if (_first)
            {
                InteropOpenSSL10_libeay32_dll.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL10_libeay32_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libeay32_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libeay32_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libeay32_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libeay32_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libeay32_dll_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_HashAlgorithmSHA1 : SHA1
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL10_libssl_HashAlgorithmSHA1()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL10_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_HashAlgorithmSHA1 : SHA1
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_HashAlgorithmSHA1()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA1 : SHA1
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA1()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libeay32_dll_HashAlgorithmSHA1 : SHA1
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL10_libeay32_dll_HashAlgorithmSHA1()
        {
            if (_first)
            {
                InteropOpenSSL10_libeay32_dll.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL10_libeay32_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libeay32_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libeay32_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libeay32_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libeay32_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libeay32_dll_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_HashAlgorithmSHA256 : SHA256
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL10_libssl_HashAlgorithmSHA256()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL10_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_HashAlgorithmSHA256 : SHA256
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_HashAlgorithmSHA256()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA256 : SHA256
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA256()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libeay32_dll_HashAlgorithmSHA256 : SHA256
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL10_libeay32_dll_HashAlgorithmSHA256()
        {
            if (_first)
            {
                InteropOpenSSL10_libeay32_dll.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL10_libeay32_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libeay32_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libeay32_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libeay32_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libeay32_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libeay32_dll_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_HashAlgorithmSHA384 : SHA384
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL10_libssl_HashAlgorithmSHA384()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL10_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_HashAlgorithmSHA384 : SHA384
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_HashAlgorithmSHA384()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA384 : SHA384
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA384()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libeay32_dll_HashAlgorithmSHA384 : SHA384
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL10_libeay32_dll_HashAlgorithmSHA384()
        {
            if (_first)
            {
                InteropOpenSSL10_libeay32_dll.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL10_libeay32_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libeay32_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libeay32_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libeay32_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libeay32_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libeay32_dll_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_HashAlgorithmSHA512 : SHA512
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL10_libssl_HashAlgorithmSHA512()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL10_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_HashAlgorithmSHA512 : SHA512
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_HashAlgorithmSHA512()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA512 : SHA512
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA512()
        {
            if (_first)
            {
                InteropOpenSSL10_libssl_so_1_0_0.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL10_libssl_so_1_0_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libssl_so_1_0_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libssl_so_1_0_0_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libssl_so_1_0_0.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10_libeay32_dll_HashAlgorithmSHA512 : SHA512
    {
        /// <summary>
        /// Flag to toggle calling &quot;OpenSSL_add_all_digests()&quot;
        /// </summary>
        public static bool _first = true;

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL10_libeay32_dll_HashAlgorithmSHA512()
        {
            if (_first)
            {
                InteropOpenSSL10_libeay32_dll.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL10_libeay32_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10_libeay32_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10_libeay32_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
            m_context = InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_create();

            if (InteropOpenSSL10_libeay32_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10_libeay32_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10_libeay32_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10_libeay32_dll_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL10_libeay32_dll.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL11_libssl_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL11_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL11 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_HashAlgorithmSHA512();
            try { return new OpenSSL11_libssl_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL11_libssl_so_1_1_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL11 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_HashAlgorithmSHA512();
            try { return new OpenSSL11_libssl_so_1_1_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_0_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL11_libssl_so_1_1_0_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_0_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL11 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_0_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA512();
            try { return new OpenSSL11_libssl_so_1_1_0_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_dll_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL11_libcrypto_dll_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL11_libcrypto_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_dll_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL11 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_dll_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_dll_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_dll_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_dll_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_dll_HashAlgorithmSHA512();
            try { return new OpenSSL11_libcrypto_dll_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_dll_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL11_libcrypto_1_1_dll_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_dll_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL11 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_dll_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA512();
            try { return new OpenSSL11_libcrypto_1_1_dll_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL11 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA512();
            try { return new OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_x64_dll_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL11_libcrypto_x64_dll_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL11_libcrypto_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_x64_dll_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL11 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_x64_dll_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA512();
            try { return new OpenSSL11_libcrypto_x64_dll_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL11_libssl_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_0_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_0_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_0_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_dll_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_dll_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11_libcrypto_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_dll_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_dll_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_dll_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_dll_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_x64_dll_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_x64_dll_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11_libcrypto_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_x64_dll_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL11_libssl_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_dll_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_dll_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11_libcrypto_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_dll_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11_libcrypto_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL11_libssl_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_dll_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_dll_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11_libcrypto_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_dll_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11_libcrypto_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL11_libssl_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_dll_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_dll_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11_libcrypto_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_dll_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11_libcrypto_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL11_libssl_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11_libssl_so_1_1_0.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libssl_so_1_1_0.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libssl_so_1_1_0_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libssl_so_1_1_0.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_dll_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_dll_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11_libcrypto_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_dll_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_dll_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_1_1_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.1
    /// </summary>
    public class OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11_libcrypto_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11_libcrypto_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11_libcrypto_x64_dll_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL11_libcrypto_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL3_libssl_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL3_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL3 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_HashAlgorithmSHA512();
            try { return new OpenSSL3_libssl_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_so_3_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL3_libssl_so_3_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL3_libssl_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_so_3_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL3 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_so_3_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_so_3_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_so_3_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_so_3_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libssl_so_3_HashAlgorithmSHA512();
            try { return new OpenSSL3_libssl_so_3_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL3_libcrypto_so_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL3_libcrypto_so.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL3 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_HashAlgorithmSHA512();
            try { return new OpenSSL3_libcrypto_so_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_3_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL3_libcrypto_so_3_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL3_libcrypto_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_3_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL3 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_3_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_3_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_3_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_3_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_so_3_HashAlgorithmSHA512();
            try { return new OpenSSL3_libcrypto_so_3_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_dll_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL3_libcrypto_3_dll_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL3_libcrypto_3_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_dll_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL3 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_dll_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA512();
            try { return new OpenSSL3_libcrypto_3_dll_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_x64_dll_HashAlgorithm : HashAlgorithm
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> class.
        /// </summary>
        /// <param name="algorithm">The name of the hash algorithm to use.</param>
        public OpenSSL3_libcrypto_3_x64_dll_HashAlgorithm(string algorithm)
        {
            m_digestmethod = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_x64_dll_HashAlgorithm()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Creates a new hash algorithm using an OpenSSL3 implementation
        /// </summary>
        /// <param name-"name">The name of the algorithm to create</param>
        public static new HashAlgorithm Create(string name)
        {
            if (string.Equals("MD5", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA512();
            try { return new OpenSSL3_libcrypto_3_x64_dll_HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL3_libssl_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL3_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_so_3_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL3_libssl_so_3_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL3_libssl_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_so_3_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL3_libcrypto_so.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_3_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_3_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL3_libcrypto_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_3_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_dll_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_dll_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_dll_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmMD5 : MD5
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmMD5()
        {
           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmMD5()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL3_libssl_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL3_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_so_3_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL3_libssl_so_3_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL3_libssl_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_so_3_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL3_libcrypto_so.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_3_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_3_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL3_libcrypto_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_3_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA1 : SHA1
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA1()
        {
           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA1()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL3_libssl_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL3_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_so_3_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL3_libssl_so_3_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL3_libssl_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_so_3_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL3_libcrypto_so.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_3_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_3_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL3_libcrypto_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_3_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA256 : SHA256
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA256()
        {
           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA256()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL3_libssl_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL3_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_so_3_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL3_libssl_so_3_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL3_libssl_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_so_3_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL3_libcrypto_so.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_3_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_3_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL3_libcrypto_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_3_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA384 : SHA384
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA384()
        {
           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA384()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL3_libssl_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL3_libssl.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libssl_so_3_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL3_libssl_so_3_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL3_libssl_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libssl_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libssl_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libssl_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libssl_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libssl_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libssl_so_3_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libssl_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL3_libcrypto_so.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_so_3_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_so_3_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL3_libcrypto_so_3.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_so_3.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_so_3.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_so_3.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_so_3.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_so_3_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_so_3.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_dll_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 3
    /// </summary>
    public class OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA512 : SHA512
    {

        /// <summary>
        /// The message digest context
        /// </summary>
        private IntPtr m_context;

        /// <summary>
        /// The size of the message digest
        /// </summary>
        private readonly int m_size;
        /// <summary>
        /// The message digest method
        /// </summary>
        private readonly IntPtr m_digestmethod;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> class.
        /// </summary>
        public OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA512()
        {
           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
            m_context = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_new();

            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        /// <summary>
        /// Performs the core hashing
        /// </summary>
        /// <param name="array">The data to hash.</param>
        /// <param name="ibStart">The index into the array where hashing starts.</param>
        /// <param name="cbSize">The number of bytes to hash.</param>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            // Common case is to use offset=0, and here we can rely on the system marshaller to work
            if (ibStart == 0)
            {
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#if AVOID_PINNING_SMALL_ARRAYS
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
                pa.Free();
                if (res != 1)
                   throw new Win32Exception(Marshal.GetLastWin32Error());
           }
        }

        /// <summary>
        /// Computes the final hash and returns the result
        /// </summary>
        /// <returns>The final messge digest.</returns>
        protected override byte[] HashFinal()
        {
            if (m_context == IntPtr.Zero)
                Initialize();

            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL3_libcrypto_3_x64_dll.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL3HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL3_libcrypto_3_x64_dll_HashAlgorithmSHA512()
        {
            Dispose(false);
        }

        /// <summary>
        /// Dispose the this instance.
        /// </summary>
        /// <param name="disposing">If set to <c>true</c> this is called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (m_context != IntPtr.Zero)
            {
                InteropOpenSSL3_libcrypto_3_x64_dll.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }



}

