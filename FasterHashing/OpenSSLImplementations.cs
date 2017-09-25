﻿using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FasterHashing
{
    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10HashAlgorithm : HashAlgorithm
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
        public OpenSSL10HashAlgorithm(string algorithm)
        {
            if (_first)
            {
                InteropOpenSSL10.OpenSSL_add_all_digests();
                _first = false;
            }

            m_digestmethod = InteropOpenSSL10.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10.EVP_MD_CTX_cleanup(m_context);
            else
                m_context = InteropOpenSSL10.EVP_MD_CTX_create();

            if (InteropOpenSSL10.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10HashAlgorithm()
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
                InteropOpenSSL10.EVP_MD_CTX_destroy(m_context);
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
                return new OpenSSL10HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL10HashAlgorithmSHA512();
            try { return new OpenSSL10HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10HashAlgorithmMD5 : MD5
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
        public OpenSSL10HashAlgorithmMD5()
        {
            if (_first)
            {
                InteropOpenSSL10.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL10.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10.EVP_MD_CTX_cleanup(m_context);
            else
                m_context = InteropOpenSSL10.EVP_MD_CTX_create();

            if (InteropOpenSSL10.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10HashAlgorithmMD5()
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
                InteropOpenSSL10.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10HashAlgorithmSHA1 : SHA1
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
        public OpenSSL10HashAlgorithmSHA1()
        {
            if (_first)
            {
                InteropOpenSSL10.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL10.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10.EVP_MD_CTX_cleanup(m_context);
            else
                m_context = InteropOpenSSL10.EVP_MD_CTX_create();

            if (InteropOpenSSL10.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10HashAlgorithmSHA1()
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
                InteropOpenSSL10.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10HashAlgorithmSHA256 : SHA256
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
        public OpenSSL10HashAlgorithmSHA256()
        {
            if (_first)
            {
                InteropOpenSSL10.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL10.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10.EVP_MD_CTX_cleanup(m_context);
            else
                m_context = InteropOpenSSL10.EVP_MD_CTX_create();

            if (InteropOpenSSL10.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10HashAlgorithmSHA256()
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
                InteropOpenSSL10.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10HashAlgorithmSHA384 : SHA384
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
        public OpenSSL10HashAlgorithmSHA384()
        {
            if (_first)
            {
                InteropOpenSSL10.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL10.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10.EVP_MD_CTX_cleanup(m_context);
            else
                m_context = InteropOpenSSL10.EVP_MD_CTX_create();

            if (InteropOpenSSL10.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10HashAlgorithmSHA384()
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
                InteropOpenSSL10.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL10HashAlgorithmSHA512 : SHA512
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
        public OpenSSL10HashAlgorithmSHA512()
        {
            if (_first)
            {
                InteropOpenSSL10.OpenSSL_add_all_digests();
                _first = false;
            }

           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL10.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL10.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL10.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL10.EVP_MD_CTX_cleanup(m_context);
            else
                m_context = InteropOpenSSL10.EVP_MD_CTX_create();

            if (InteropOpenSSL10.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL10.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL10.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL10.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL10HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL10HashAlgorithmSHA512()
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
                InteropOpenSSL10.EVP_MD_CTX_destroy(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of a hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL11HashAlgorithm : HashAlgorithm
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
        public OpenSSL11HashAlgorithm(string algorithm)
        {

            m_digestmethod = InteropOpenSSL11.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11.EVP_MD_CTX_reset(m_context);
            else
                m_context = InteropOpenSSL11.EVP_MD_CTX_new();

            if (InteropOpenSSL11.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithm"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11HashAlgorithm()
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
                InteropOpenSSL11.EVP_MD_CTX_free(m_context);
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
                return new OpenSSL11HashAlgorithmMD5();
            if (string.Equals("SHA1", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11HashAlgorithmSHA1();
            if (string.Equals("SHA256", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11HashAlgorithmSHA256();
            if (string.Equals("SHA384", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11HashAlgorithmSHA384();
            if (string.Equals("SHA512", name, StringComparison.OrdinalIgnoreCase))
                return new OpenSSL11HashAlgorithmSHA512();
            try { return new OpenSSL11HashAlgorithm(name); }
            catch { }

            return null;
        }
    }


    /// <summary>
    /// Implementation of the MD5 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL11HashAlgorithmMD5 : MD5
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
        public OpenSSL11HashAlgorithmMD5()
        {

           var algorithm = "MD5";
            m_digestmethod = InteropOpenSSL11.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11.EVP_MD_CTX_reset(m_context);
            else
                m_context = InteropOpenSSL11.EVP_MD_CTX_new();

            if (InteropOpenSSL11.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11HashAlgorithmMD5()
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
                InteropOpenSSL11.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL11HashAlgorithmSHA1 : SHA1
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
        public OpenSSL11HashAlgorithmSHA1()
        {

           var algorithm = "SHA1";
            m_digestmethod = InteropOpenSSL11.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11.EVP_MD_CTX_reset(m_context);
            else
                m_context = InteropOpenSSL11.EVP_MD_CTX_new();

            if (InteropOpenSSL11.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11HashAlgorithmSHA1()
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
                InteropOpenSSL11.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL11HashAlgorithmSHA256 : SHA256
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
        public OpenSSL11HashAlgorithmSHA256()
        {

           var algorithm = "SHA256";
            m_digestmethod = InteropOpenSSL11.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11.EVP_MD_CTX_reset(m_context);
            else
                m_context = InteropOpenSSL11.EVP_MD_CTX_new();

            if (InteropOpenSSL11.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11HashAlgorithmSHA256()
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
                InteropOpenSSL11.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL11HashAlgorithmSHA384 : SHA384
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
        public OpenSSL11HashAlgorithmSHA384()
        {

           var algorithm = "SHA384";
            m_digestmethod = InteropOpenSSL11.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11.EVP_MD_CTX_reset(m_context);
            else
                m_context = InteropOpenSSL11.EVP_MD_CTX_new();

            if (InteropOpenSSL11.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11HashAlgorithmSHA384()
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
                InteropOpenSSL11.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }


    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using OpenSSL 1.0
    /// </summary>
    public class OpenSSL11HashAlgorithmSHA512 : SHA512
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
        public OpenSSL11HashAlgorithmSHA512()
        {

           var algorithm = "SHA512";
            m_digestmethod = InteropOpenSSL11.EVP_get_digestbyname(algorithm);
            if (m_digestmethod == IntPtr.Zero)
                throw new ArgumentException($"No such algorithm: {algorithm}");

            m_size = InteropOpenSSL11.EVP_MD_size(m_digestmethod);
        }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int OutputBlockSize { get { return m_size; } }

        /// <summary>
        /// Gets the size of the message digest in bytes
        /// </summary>
        public override int InputBlockSize { get { return InteropOpenSSL11.EVP_MD_block_size(m_digestmethod); } }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                InteropOpenSSL11.EVP_MD_CTX_reset(m_context);
            else
                m_context = InteropOpenSSL11.EVP_MD_CTX_new();

            if (InteropOpenSSL11.EVP_DigestInit_ex(m_context, m_digestmethod, IntPtr.Zero) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, array, (uint)cbSize) != 1)
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
                if (InteropOpenSSL11.EVP_DigestUpdate(m_context, tmp, (uint)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
#endif
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = InteropOpenSSL11.EVP_DigestUpdate(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (uint)cbSize);
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
            var res = new byte[m_size];
            var rs = (uint)m_size;
            if (InteropOpenSSL11.EVP_DigestFinal_ex(m_context, res, ref rs) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.OpenSSL11HashAlgorithmSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~OpenSSL11HashAlgorithmSHA512()
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
                InteropOpenSSL11.EVP_MD_CTX_free(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }
    }



}

