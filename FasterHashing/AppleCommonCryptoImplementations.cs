﻿using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CC_LONG = System.UInt32;
using CC_LONG64 = System.UInt64;

namespace FasterHashing
{
    /// <summary>
    /// Implementation of the MD5 hash algorithm, using Apple's CommonCrypto
    /// </summary>
    public class AppleCommonCryptoMD5 : MD5
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
        /// Initializes a new instance of the <see cref="T:FasterHashing.AppleCommonCryptoMD5"/> class.
        /// </summary>
        public AppleCommonCryptoMD5()
        {
            m_size = AppleCommonCryptoHashAlgorithm.GetDigestSize(AppleCCDigest.MD5);
        }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                Marshal.FreeHGlobal(m_context);

            m_context = Marshal.AllocHGlobal(Interop.STRUCT_SIZE);
            if (Interop.CC_MD5_Init(m_context) != 1)
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
                if (Interop.CC_MD5_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (Interop.CC_MD5_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = Interop.CC_MD5_Update(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (CC_LONG)cbSize);
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
            if (Interop.CC_MD5_Final(res, m_context) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.AppleCommonCryptoMD5"/> is reclaimed by garbage collection.
        /// </summary>
        ~AppleCommonCryptoMD5()
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
                Marshal.FreeHGlobal(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

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
            /// The size of the struct we allocate.
            /// Since we cannot re-link with the library, we use a conservative
            /// estimate, i.e. we allocate more than we need to accomodate
            /// future updates to the structures.
            /// </summary>
            public const int STRUCT_SIZE = 512; /* Max(2+8+16)*8 = 208 bytes */

            /// <summary>
            /// Initializes a context structure
            /// </summary>
            /// <param name="ctx">The context to initialize</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_MD5_Init(IntPtr ctx);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_MD5_Update(IntPtr ctx, byte[] data, CC_LONG len);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_MD5_Update(IntPtr ctx, IntPtr data, CC_LONG len);

            /// <summary>
            /// Computes the final message digest
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_MD5_Final(byte[] buffer, IntPtr ctx);

            /// <summary>
            /// Computes a message digest from the buffer
            /// </summary>
            /// <param name="data">The data to compute the digest for</param>
            /// <param name="len">The length of the data</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern byte[] CC_MD5(byte[] data, CC_LONG len, byte[] md);
        }
    }
    /// <summary>
    /// Implementation of the SHA1 hash algorithm, using Apple's CommonCrypto
    /// </summary>
    public class AppleCommonCryptoSHA1 : SHA1
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
        /// Initializes a new instance of the <see cref="T:FasterHashing.AppleCommonCryptoSHA1"/> class.
        /// </summary>
        public AppleCommonCryptoSHA1()
        {
            m_size = AppleCommonCryptoHashAlgorithm.GetDigestSize(AppleCCDigest.SHA1);
        }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                Marshal.FreeHGlobal(m_context);

            m_context = Marshal.AllocHGlobal(Interop.STRUCT_SIZE);
            if (Interop.CC_SHA1_Init(m_context) != 1)
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
                if (Interop.CC_SHA1_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (Interop.CC_SHA1_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = Interop.CC_SHA1_Update(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (CC_LONG)cbSize);
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
            if (Interop.CC_SHA1_Final(res, m_context) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.AppleCommonCryptoSHA1"/> is reclaimed by garbage collection.
        /// </summary>
        ~AppleCommonCryptoSHA1()
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
                Marshal.FreeHGlobal(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

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
            /// The size of the struct we allocate.
            /// Since we cannot re-link with the library, we use a conservative
            /// estimate, i.e. we allocate more than we need to accomodate
            /// future updates to the structures.
            /// </summary>
            public const int STRUCT_SIZE = 512; /* Max(2+8+16)*8 = 208 bytes */

            /// <summary>
            /// Initializes a context structure
            /// </summary>
            /// <param name="ctx">The context to initialize</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA1_Init(IntPtr ctx);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA1_Update(IntPtr ctx, byte[] data, CC_LONG len);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA1_Update(IntPtr ctx, IntPtr data, CC_LONG len);

            /// <summary>
            /// Computes the final message digest
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA1_Final(byte[] buffer, IntPtr ctx);

            /// <summary>
            /// Computes a message digest from the buffer
            /// </summary>
            /// <param name="data">The data to compute the digest for</param>
            /// <param name="len">The length of the data</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern byte[] CC_SHA1(byte[] data, CC_LONG len, byte[] md);
        }
    }
    /// <summary>
    /// Implementation of the SHA256 hash algorithm, using Apple's CommonCrypto
    /// </summary>
    public class AppleCommonCryptoSHA256 : SHA256
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
        /// Initializes a new instance of the <see cref="T:FasterHashing.AppleCommonCryptoSHA256"/> class.
        /// </summary>
        public AppleCommonCryptoSHA256()
        {
            m_size = AppleCommonCryptoHashAlgorithm.GetDigestSize(AppleCCDigest.SHA256);
        }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                Marshal.FreeHGlobal(m_context);

            m_context = Marshal.AllocHGlobal(Interop.STRUCT_SIZE);
            if (Interop.CC_SHA256_Init(m_context) != 1)
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
                if (Interop.CC_SHA256_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (Interop.CC_SHA256_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = Interop.CC_SHA256_Update(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (CC_LONG)cbSize);
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
            if (Interop.CC_SHA256_Final(res, m_context) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.AppleCommonCryptoSHA256"/> is reclaimed by garbage collection.
        /// </summary>
        ~AppleCommonCryptoSHA256()
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
                Marshal.FreeHGlobal(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

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
            /// The size of the struct we allocate.
            /// Since we cannot re-link with the library, we use a conservative
            /// estimate, i.e. we allocate more than we need to accomodate
            /// future updates to the structures.
            /// </summary>
            public const int STRUCT_SIZE = 512; /* Max(2+8+16)*8 = 208 bytes */

            /// <summary>
            /// Initializes a context structure
            /// </summary>
            /// <param name="ctx">The context to initialize</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA256_Init(IntPtr ctx);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA256_Update(IntPtr ctx, byte[] data, CC_LONG len);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA256_Update(IntPtr ctx, IntPtr data, CC_LONG len);

            /// <summary>
            /// Computes the final message digest
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA256_Final(byte[] buffer, IntPtr ctx);

            /// <summary>
            /// Computes a message digest from the buffer
            /// </summary>
            /// <param name="data">The data to compute the digest for</param>
            /// <param name="len">The length of the data</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern byte[] CC_SHA256(byte[] data, CC_LONG len, byte[] md);
        }
    }
    /// <summary>
    /// Implementation of the SHA384 hash algorithm, using Apple's CommonCrypto
    /// </summary>
    public class AppleCommonCryptoSHA384 : SHA384
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
        /// Initializes a new instance of the <see cref="T:FasterHashing.AppleCommonCryptoSHA384"/> class.
        /// </summary>
        public AppleCommonCryptoSHA384()
        {
            m_size = AppleCommonCryptoHashAlgorithm.GetDigestSize(AppleCCDigest.SHA384);
        }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                Marshal.FreeHGlobal(m_context);

            m_context = Marshal.AllocHGlobal(Interop.STRUCT_SIZE);
            if (Interop.CC_SHA384_Init(m_context) != 1)
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
                if (Interop.CC_SHA384_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (Interop.CC_SHA384_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = Interop.CC_SHA384_Update(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (CC_LONG)cbSize);
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
            if (Interop.CC_SHA384_Final(res, m_context) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.AppleCommonCryptoSHA384"/> is reclaimed by garbage collection.
        /// </summary>
        ~AppleCommonCryptoSHA384()
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
                Marshal.FreeHGlobal(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

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
            /// The size of the struct we allocate.
            /// Since we cannot re-link with the library, we use a conservative
            /// estimate, i.e. we allocate more than we need to accomodate
            /// future updates to the structures.
            /// </summary>
            public const int STRUCT_SIZE = 512; /* Max(2+8+16)*8 = 208 bytes */

            /// <summary>
            /// Initializes a context structure
            /// </summary>
            /// <param name="ctx">The context to initialize</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA384_Init(IntPtr ctx);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA384_Update(IntPtr ctx, byte[] data, CC_LONG len);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA384_Update(IntPtr ctx, IntPtr data, CC_LONG len);

            /// <summary>
            /// Computes the final message digest
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA384_Final(byte[] buffer, IntPtr ctx);

            /// <summary>
            /// Computes a message digest from the buffer
            /// </summary>
            /// <param name="data">The data to compute the digest for</param>
            /// <param name="len">The length of the data</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern byte[] CC_SHA384(byte[] data, CC_LONG len, byte[] md);
        }
    }
    /// <summary>
    /// Implementation of the SHA512 hash algorithm, using Apple's CommonCrypto
    /// </summary>
    public class AppleCommonCryptoSHA512 : SHA512
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
        /// Initializes a new instance of the <see cref="T:FasterHashing.AppleCommonCryptoSHA512"/> class.
        /// </summary>
        public AppleCommonCryptoSHA512()
        {
            m_size = AppleCommonCryptoHashAlgorithm.GetDigestSize(AppleCCDigest.SHA512);
        }

        /// <summary>
        /// Initializes the hashing algorithm
        /// </summary>
        public override void Initialize()
        {
            if (m_context != IntPtr.Zero)
                Marshal.FreeHGlobal(m_context);

            m_context = Marshal.AllocHGlobal(Interop.STRUCT_SIZE);
            if (Interop.CC_SHA512_Init(m_context) != 1)
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
                if (Interop.CC_SHA512_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // For small chunks, we can copy and get mostly the same performance as the managed version
            else if (cbSize < 1024)
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;

                var tmp = new byte[cbSize];
                Array.Copy(array, ibStart, tmp, 0, cbSize);
                if (Interop.CC_SHA512_Update(m_context, array, (CC_LONG)cbSize) != 1)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            // Otherwise, the fastest is obtaining a pinned pointer and adding the offset to that
            else
            {
                System.Diagnostics.Trace.WriteLineIf(!ErrorStateHelper.HasReportedOffsetIssue, "Warning, using arrays with non-zero offset provides significantly slower hashing performance");
                ErrorStateHelper.HasReportedOffsetIssue = true;
                var pa = GCHandle.Alloc(array, GCHandleType.Pinned);
                var res = Interop.CC_SHA512_Update(m_context, Marshal.UnsafeAddrOfPinnedArrayElement(array, ibStart), (CC_LONG)cbSize);
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
            if (Interop.CC_SHA512_Final(res, m_context) != 1)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return res;
        }

        /// <summary>
        /// Releases unmanaged resources and performs other cleanup operations before the
        /// <see cref="T:FasterHashing.AppleCommonCryptoSHA512"/> is reclaimed by garbage collection.
        /// </summary>
        ~AppleCommonCryptoSHA512()
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
                Marshal.FreeHGlobal(m_context);
                m_context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

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
            /// The size of the struct we allocate.
            /// Since we cannot re-link with the library, we use a conservative
            /// estimate, i.e. we allocate more than we need to accomodate
            /// future updates to the structures.
            /// </summary>
            public const int STRUCT_SIZE = 512; /* Max(2+8+16)*8 = 208 bytes */

            /// <summary>
            /// Initializes a context structure
            /// </summary>
            /// <param name="ctx">The context to initialize</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA512_Init(IntPtr ctx);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA512_Update(IntPtr ctx, byte[] data, CC_LONG len);

            /// <summary>
            /// Updates the current digest with more data
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="data">The data to digest</param>
            /// <param name="len">The number of bytes to digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA512_Update(IntPtr ctx, IntPtr data, CC_LONG len);

            /// <summary>
            /// Computes the final message digest
            /// </summary>
            /// <param name="ctx">The context to use</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern int CC_SHA512_Final(byte[] buffer, IntPtr ctx);

            /// <summary>
            /// Computes a message digest from the buffer
            /// </summary>
            /// <param name="data">The data to compute the digest for</param>
            /// <param name="len">The length of the data</param>
            /// <param name="buffer">The buffer that holds the final digest</param>
            [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
            public static extern byte[] CC_SHA512(byte[] data, CC_LONG len, byte[] md);
        }
    }
}
