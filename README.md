# FasterHashing
[![Nuget count](https://img.shields.io/nuget/v/FasterHashing.svg)](https://www.nuget.org/packages/FasterHashing/)
[![License](https://img.shields.io/github/license/kenkendk/FasterHashing.svg)](https://github.com/kenkendk/FasterHashing/blob/master/LICENSE)
[![Issues open](https://img.shields.io/github/issues-raw/kenkendk/FasterHashing.svg)](https://github.com/kenkendk/FasterHashing/issues/)

FasterHashing is a wrapper library for using native hashing libraries on Windows, Linux and OSX.

This library addresses a limitation in the current .Net standard profile where [`HashAlgorithm.Create()`](https://msdn.microsoft.com/en-us/library/system.security.cryptography.hashalgorithm.create(v=vs.110).aspx) always returns the managed versions of the algorithm, even if faster versions exist on the system.

The problem with `HashAlgorithm.Create()` has been [fixed with the .Net Core 2 profile](https://blogs.msdn.microsoft.com/dotnet/2017/06/07/performance-improvements-in-net-core/), so if you are using that, you will not benefit from this library. 
Unfortunately, the implementation for .Net Core 2 relies on a Platform Abstraction Layer, which is a glue library that links into the system libraries.
This glue library needs to be complied for the target platform, making it difficult to deploy this with platform independent projects (i.e. using only managed code).

For this reason *FasterHashing* contains only managed code. If you are using the .Net standard profile (v4.5+) you can simply add this library to your project, change the call from `HashAlgorithm.Create("SHA256")` to `FasterHash.Create("SHA256")` and obtain speedups on all supported platforms while falling back to the managed implementation if none are found.

# Installation
The [FasterHashing NuGet package](https://www.nuget.org/packages/FasterHashing) is the recommended way of installing FasterHashing:
```
PM> Install-Package FasterHashing
```

# Supported libraries:
These libraries are probed for at runtime in this order
* Windows Cryptography Next Generation (CNG)
* Apple Common Crypto
* OpenSSL with version 1.1 API
* OpenSSL with version 1.0 API

# Example
The returned item from `FasterHash.Create()` is a normal `HashAlgorithm` object, so you can easily replace existing code that uses such an instance.
```csharp
using FasterHashing;

public static void Main(string[] args) 
{
  using(var sha256 = FasterHash.Create("SHA256"))
    Console.WriteLine(Convert.ToBase64(sha256.ComputeHash(new byte[] { 0, 1, 2, 3 }));
}
```

# Advanced usage
If you want to control which of the library is loaded, you can use some of the utility methods on the static `FasterHash` class:
```csharp
using FasterHashing;

public static void Main(string[] args) 
{
  Console.WriteLine("Optimal implementation is: {0}", FasterHash.PreferedImplementation);
  Console.WriteLine("Is Apple Common Crypto Supported: {0}", 
    FasterHash.SupportsImplementation(HashImplementation.AppleCommonCrypto));
  
  // Manually choose OpenSSL 1.0 version:
  using(var sha256 = FasterHash.Create("SHA256", HashImplementation.OpenSSL10))
  {}
  
  // Or by direct instantiation:
  using(var sha256 = new OpenSSL11HashAlgorithmSHA256())
  {}
  
}

```
