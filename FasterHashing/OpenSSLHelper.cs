using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace FasterHashing
{
    public static class OpenSSL10HashAlgorithm
    {
        public enum LibraryName
        {
            unknown,
            libssl,
            libssl_so_1_0, 
            libssl_so_1_0_0,
            libeay32_dll
        }

        private static LibraryName _libname = LibraryName.unknown;

        public static LibraryName DefaultLibrary
        {
            get
            {
                if (_libname == LibraryName.unknown)
                    _libname = GetDefaultLibrary();
                return _libname;
            }
            set
            {
                if (value == LibraryName.unknown)
                    throw new ArgumentException("Cannot set library to unknown");
            }
        }

        public static HashAlgorithm Create(string algorithm, LibraryName library = LibraryName.unknown)
        {
            if (library == LibraryName.unknown)
                library = DefaultLibrary;

            switch (library)
            {
                case LibraryName.libssl_so_1_0:
                    return OpenSSL10_libssl_so_1_0_HashAlgorithm.Create(algorithm);
                case LibraryName.libssl_so_1_0_0:
                    return OpenSSL10_libssl_so_1_0_0_HashAlgorithm.Create(algorithm);
                case LibraryName.libeay32_dll:
                    return OpenSSL10_libeay32_dll_HashAlgorithm.Create(algorithm);

                //case LibraryName.libssl3:
                default:
                    return OpenSSL10_libssl_HashAlgorithm.Create(algorithm);
            }
        }

        public static LibraryName GetDefaultLibrary()
        {
            try
            {
                var ptr = InteropOpenSSL10_libssl_so_1_0_0.SSLeay_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libssl_so_1_0_0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.0 from libssl3.so.1.0.0: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL10_libssl_so_1_0.SSLeay_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libssl_so_1_0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.0 from libssl3.so.1.0: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL10_libeay32_dll.SSLeay_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libeay32_dll;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.0 from libeay32.dll: {ex}");
            }

            return LibraryName.libssl;
        }

        public static string SSLeay_version(LibraryName library = LibraryName.unknown)
        {
            if (library == LibraryName.unknown)
                library = DefaultLibrary;

            switch (library)
            {
                case LibraryName.libssl_so_1_0:
                    return Marshal.PtrToStringAuto(InteropOpenSSL10_libssl_so_1_0.SSLeay_version());
                case LibraryName.libssl_so_1_0_0:
                    return Marshal.PtrToStringAuto(InteropOpenSSL10_libssl_so_1_0_0.SSLeay_version());
                case LibraryName.libeay32_dll:
                    return Marshal.PtrToStringAuto(InteropOpenSSL10_libeay32_dll.SSLeay_version());

                //case LibraryName.libssl3:
                default:
                    return Marshal.PtrToStringAuto(InteropOpenSSL10_libssl.SSLeay_version());
            }
        }
    }

    public static class OpenSSL11HashAlgorithm
    {
        public enum LibraryName
        {
            unknown,
            libssl,
            libssl_so_1_1,
            libssl_so_1_1_0,
            libcrypto_dll,
            libcrypto_x64_dll,
            libcrypto_1_1_dll,
            libcrypto_1_1_x64_dll
        }

        private static LibraryName _libname = LibraryName.unknown;

        public static LibraryName DefaultLibrary
        {
            get
            {
                if (_libname == LibraryName.unknown)
                    _libname = GetDefaultLibrary();
                return _libname;
            }
            set
            {
                if (value == LibraryName.unknown)
                    throw new ArgumentException("Cannot set library to unknown");
            }
        }

        public static HashAlgorithm Create(string algorithm, LibraryName library = LibraryName.unknown)
        {
            if (library == LibraryName.unknown)
                library = DefaultLibrary;

            switch (library)
            {
                case LibraryName.libssl_so_1_1:
                    return OpenSSL11_libssl_so_1_1_HashAlgorithm.Create(algorithm);
                case LibraryName.libssl_so_1_1_0:
                    return OpenSSL11_libssl_so_1_1_0_HashAlgorithm.Create(algorithm);
                case LibraryName.libcrypto_dll:
                    return OpenSSL11_libcrypto_dll_HashAlgorithm.Create(algorithm);
                case LibraryName.libcrypto_x64_dll:
                    return OpenSSL11_libcrypto_x64_dll_HashAlgorithm.Create(algorithm);
                case LibraryName.libcrypto_1_1_dll:
                    return OpenSSL11_libcrypto_1_1_dll_HashAlgorithm.Create(algorithm);
                case LibraryName.libcrypto_1_1_x64_dll:
                    return OpenSSL11_libcrypto_1_1_x64_dll_HashAlgorithm.Create(algorithm);

                default:
                    return OpenSSL11_libssl_HashAlgorithm.Create(algorithm);
            }
        }

        public static string OpenSSL_version(LibraryName library = LibraryName.unknown)
        {
            if (library == LibraryName.unknown)
                library = DefaultLibrary;

            switch (library)
            {
                case LibraryName.libssl_so_1_1:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL11_libssl_so_1_1.OpenSSL_version());
                case LibraryName.libssl_so_1_1_0:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL11_libssl_so_1_1_0.OpenSSL_version());
                case LibraryName.libcrypto_dll:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL11_libcrypto_dll.OpenSSL_version());
                case LibraryName.libcrypto_x64_dll:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL11_libcrypto_x64_dll.OpenSSL_version());
                case LibraryName.libcrypto_1_1_dll:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL11_libcrypto_1_1_dll.OpenSSL_version());
                case LibraryName.libcrypto_1_1_x64_dll:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL11_libcrypto_1_1_x64_dll.OpenSSL_version());

                default:
                   return Marshal.PtrToStringAnsi(InteropOpenSSL11_libssl.OpenSSL_version());
            }
        }

        public static LibraryName GetDefaultLibrary()
        {
            try
            {
                var ptr = InteropOpenSSL11_libssl_so_1_1_0.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libssl_so_1_1_0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.1 from libssl3.so.1.1.0: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL11_libssl_so_1_1.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libssl_so_1_1;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.1 from libssl3.so.1.1: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL11_libcrypto_dll.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_dll;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.1 from libcrypto.dll: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL11_libcrypto_x64_dll.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_x64_dll;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.1 from libcrypto_x64.dll: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL11_libcrypto_1_1_dll.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_1_1_dll;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.1 from libcrypto-1-1_dll: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL11_libcrypto_1_1_x64_dll.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_1_1_x64_dll;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL1.1 from libcrypto-1-1-x64_dll.dll: {ex}");
            }


            return LibraryName.libssl;
        }

    }

    public static class OpenSSL3HashAlgorithm
    {
        public enum LibraryName
        {
            unknown,
            libssl,
            libssl_so_3,
            libcrypto_so,
            libcrypto_so_3,
            libcrypto_dll,
            libcrypto_x64_dll,
            libcrypto_3_dll,
            libcrypto_3_x64_dll
        }

        private static LibraryName _libname = LibraryName.unknown;

        public static LibraryName DefaultLibrary
        {
            get
            {
                if (_libname == LibraryName.unknown)
                    _libname = GetDefaultLibrary();
                return _libname;
            }
            set
            {
                if (value == LibraryName.unknown)
                    throw new ArgumentException("Cannot set library to unknown");
            }
        }

        public static HashAlgorithm Create(string algorithm, LibraryName library = LibraryName.unknown)
        {
            if (library == LibraryName.unknown)
                library = DefaultLibrary;

            switch (library)
            {
                case LibraryName.libcrypto_so:
                    return OpenSSL3_libcrypto_so_HashAlgorithm.Create(algorithm);
                case LibraryName.libcrypto_so_3:
                    return OpenSSL3_libcrypto_so_3_HashAlgorithm.Create(algorithm);
                case LibraryName.libcrypto_3_dll:
                    return OpenSSL3_libcrypto_3_dll_HashAlgorithm.Create(algorithm);
                case LibraryName.libcrypto_3_x64_dll:
                    return OpenSSL3_libcrypto_3_x64_dll_HashAlgorithm.Create(algorithm);
                case LibraryName.libssl:
                    return OpenSSL3_libssl_HashAlgorithm.Create(algorithm);

                default:
                    return OpenSSL3_libcrypto_so_HashAlgorithm.Create(algorithm);
            }
        }

        public static string OpenSSL_version(LibraryName library = LibraryName.unknown)
        {
            if (library == LibraryName.unknown)
                library = DefaultLibrary;

            switch (library)
            {
                case LibraryName.libssl_so_3:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL3_libssl_so_3.OpenSSL_version());
                case LibraryName.libcrypto_so:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL3_libcrypto_so.OpenSSL_version());
                case LibraryName.libcrypto_so_3:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL3_libcrypto_so_3.OpenSSL_version());
                case LibraryName.libcrypto_3_dll:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL3_libcrypto_3_dll.OpenSSL_version());
                case LibraryName.libcrypto_3_x64_dll:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL3_libcrypto_3_x64_dll.OpenSSL_version());

                default:
                    return Marshal.PtrToStringAnsi(InteropOpenSSL3_libssl.OpenSSL_version());
            }
        }

        public static LibraryName GetDefaultLibrary()
        {
            try
            {
                var ptr = InteropOpenSSL3_libcrypto_so.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_so;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL3 from libcrypto.so: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL3_libcrypto_3_dll.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_3_dll;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL3 from libcrypto-3.dll: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL3_libcrypto_3_x64_dll.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_3_x64_dll;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL3 from libcrypto-3-x64.dll: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL3_libssl.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libssl;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL3 from libssl.so.3: {ex}");
            }
            
            try
            {
                var ptr = InteropOpenSSL3_libssl_so_3.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libssl_so_3;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL3 from libssl.so.3: {ex}");
            }

            try
            {
                var ptr = InteropOpenSSL3_libcrypto_so_3.OpenSSL_version();
                if (ptr != IntPtr.Zero)
                    return LibraryName.libcrypto_so_3;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine($"Failed to load OpenSSL3 from libcrypto.so.3: {ex}");
            }

            return LibraryName.libssl;
        }

    }
}
