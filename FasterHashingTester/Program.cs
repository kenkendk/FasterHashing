using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace FasterHashingTester
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Optimal implementation is: {0}", FasterHashing.FasterHash.PreferedImplementation);

            if (args == null || args.Length == 0)
            {

                Console.WriteLine("Performing basic tests");
                Test();

                Console.WriteLine("Performing tests with non-zero offsets");
                TestWithOffset();

                Console.WriteLine("Testing performance with 64b block");
                foreach (var n in FasterHashing.FasterHash.MeasureImplementations("SHA256", 64))
                    Console.WriteLine("{0, 20}:  {1} hashes/second", n.Item1, n.Item2);

                Console.WriteLine("Testing performance with 100kb blocks");
                foreach (var n in FasterHashing.FasterHash.MeasureImplementations("SHA256", 102400))
                    Console.WriteLine("{0, 20}:  {1} hashes/second", n.Item1, n.Item2);

				Console.WriteLine("Testing performance with 64b blocks and 5 byte offset");
                foreach (var n in FasterHashing.FasterHash.MeasureImplementations("SHA256", 64, bufferoffset: 5))
					Console.WriteLine("{0, 20}:  {1} hashes/second", n.Item1, n.Item2);

				Console.WriteLine("Testing performance with 100kb blocks and 5 byte offset");
                foreach (var n in FasterHashing.FasterHash.MeasureImplementations("SHA256", 102400, bufferoffset: 5))
					Console.WriteLine("{0, 20}:  {1} hashes/second", n.Item1, n.Item2);
                
				Console.WriteLine("Testing multithreadded execution to wiggle out any shared state problems");
                TestThreads();
            }
            else
            {
                var readbuffer = 5242880;
                var blocksize = 102400;
                var algorithm = "SHA256";

                var arglist = new List<string>(args);
                for(var i = arglist.Count - 1; i >= 0; i--)
                {
                    var p = (arglist[i] ?? string.Empty).Trim();
                    if (p.StartsWith("--readbuffer=", StringComparison.OrdinalIgnoreCase))
                    {
                        readbuffer = int.Parse(p.Substring("--readbuffer=".Length));
                        arglist.RemoveAt(i);
                    }
                    else if (p.StartsWith("--blocksize=", StringComparison.OrdinalIgnoreCase))
                    {
						blocksize = int.Parse(p.Substring("--blocksize=".Length));
						arglist.RemoveAt(i);
					}
					else if (p.StartsWith("--algorithm=", StringComparison.OrdinalIgnoreCase))
					{
                        algorithm = p.Substring("--algorithm=".Length).Trim().ToUpperInvariant();
						arglist.RemoveAt(i);
					}
				}

                foreach (var arg in arglist)
                {
                    if (System.IO.Directory.Exists(arg))
                    {
                        foreach (var line in CompareDirectory(arg, readbuffer, blocksize, algorithm))
                            Console.WriteLine(line);
                    }
                    else if (System.IO.File.Exists(arg))
                    {
                        foreach (var line in CompareFile(arg, readbuffer, blocksize, algorithm))
                            Console.WriteLine(line);
                    }
                    else
                    {
                        Console.WriteLine("Bad argument: {0}", arg);
                    }
                }

                //var path = "/Users/kenneth/testdata/data/mp3 - Brad Sucks/Out of It/";
                //path = "/Users/kenneth/Downloads/duplicati-bf19b64e8fdd948d7acb18792b0bcc767.dblock";
            }


		}

        private static IEnumerable<string> CompareDirectory(string directory, long readbuffer = 5242880, int blocksize = 102400, string algorithm = "SHA256")
        {
            if (!System.IO.Directory.Exists(directory))
                throw new Exception($"Not a directory: {directory}");

            foreach (var file in System.IO.Directory.GetFiles(directory))
            {
                foreach (var fr in CompareFile(file, readbuffer, blocksize, algorithm))
                    yield return fr;

                yield return string.Empty;
            }
        }

		private static IEnumerable<string> CompareFile(string file, long readbuffer = 5242880, int blocksize = 102400, string algorithm = "SHA256")
        {
            if (!System.IO.File.Exists(file))
                throw new Exception($"No such file: {file}");

			yield return string.Format("Hashing file: {0}", file);
			var st = DateTime.Now;

			foreach (var hi in FasterHashing.FasterHash.SupportedImplementations)
            {
                var buf = new byte[readbuffer];

                using (var fs = System.IO.File.OpenRead(file))
                using (var alg1 = FasterHashing.FasterHash.Create(algorithm, false, hi))
                using (var alg2 = FasterHashing.FasterHash.Create(algorithm, false, hi))
                {
                    alg1.Initialize();
                    alg2.Initialize();

                    var r = 0;
                    while ((r = fs.Read(buf, 0, buf.Length)) != 0)
                    {
                        var left = r;
                        var offset = 0;

                        while (left > 0)
                        {
                            var rr = Math.Min(left, blocksize);
                            alg1.TransformBlock(buf, offset, rr, buf, offset);
                            alg2.Initialize();
                            alg2.TransformBlock(buf, offset, rr, buf, offset);
                            var r1 = alg2.TransformFinalBlock(buf, 0, 0);

                            //var r0 = alg2.ComputeHash(buf, offset, rr);

                            left -= rr;
                            offset += rr;
                        }
                    }

                    var res = alg1.TransformFinalBlock(new byte[0], 0, 0);
                    var raw = Convert.ToBase64String(alg1.Hash);

                    /*alg1.Initialize();
                    fs.Position = 0;
                    var direct = Convert.ToBase64String(alg1.ComputeHash(fs));

                    if (raw != direct)
                        throw new Exception("The hashes for individual chunk differs from the complete hash");
                    */

                    var elapsed = DateTime.Now - st;
                    yield return string.Format("{0, 20}: {1} {2}", hi, raw, elapsed);
                }
            }
        }

        private static void CompareArrays(byte[] a, byte[] b)
        {
			if (a.Length != b.Length)
				throw new Exception("Bad length");

			for (var i = 0; i < a.Length; i++)
				if (a[i] != b[i])
					throw new Exception("Bad hash");
		}

        private static void Test(int seed = 42)
        {
            using(var r = System.Security.Cryptography.HashAlgorithm.Create("SHA256"))
            using(var f = FasterHashing.FasterHash.Create("SHA256"))
            foreach (var size in new int[] { 1, 2, 3, 4, 5, 6, 16, 32, 64, 128, 256, 257, 258, 300, 500, 512, 1024, 2048, 7000, 102400 })
            {
                var src = new byte[size];
                new Random(seed).NextBytes(src);

                var r1 = r.ComputeHash(src);
                var f1 = f.ComputeHash(src);

                CompareArrays(r1, f1);
			}
        }

		private static void TestWithOffset(int seed = 42)
		{
			using (var r = System.Security.Cryptography.HashAlgorithm.Create("SHA256"))
			using (var f = FasterHashing.FasterHash.Create("SHA256"))
				foreach (var size in new int[] { 1, 2, 3, 4, 5, 6, 16, 32, 64, 128, 256, 257, 258, 300, 500, 512, 1024, 2048, 7000, 102400 })
				{
					var src = new byte[size];
					new Random(seed).NextBytes(src);

                    r.Initialize();
                    f.Initialize();

                    for (var offset = 0; offset < size; offset++)
                    {
                        r.TransformBlock(src, offset, 1, src, offset);
                        f.TransformBlock(src, offset, 1, src, offset);
					}

                    var r1 = r.TransformFinalBlock(src, 0, 0);
                    var f1 = f.TransformFinalBlock(src, 0, 0);

                    CompareArrays(r1, f1);
				}
		}

        private static Tuple<string, TimeSpan>[] MeasureSpeeds(int seed = 42, int blocksize = 64)
        {
            return
                Enum.GetValues(typeof(FasterHashing.HashImplementation))
                    .OfType<FasterHashing.HashImplementation>()
                    .Where(x => x != FasterHashing.HashImplementation.Any)
                    .Where(x => FasterHashing.FasterHash.SupportsImplementation(x))
                    .Select(x =>
                    {
                        var s = DateTime.Now;
                        using (var alg = FasterHashing.FasterHash.Create("SHA256", false, x))
                            PerformanceTest(alg, seed, blocksize);

                        return new Tuple<string, TimeSpan>(x.ToString(), DateTime.Now - s);
                    })
                    .ToArray();
        }

        private static byte[] PerformanceTest(System.Security.Cryptography.HashAlgorithm alg, int seed = 42, int blocksize = 64)
        {
            var block = new byte[blocksize];
            new Random(seed).NextBytes(block);
               
            alg.Initialize();
            foreach (var n in Enumerable.Range(0, 1000000))
                alg.TransformBlock(block, 0, block.Length, block, 0);

            return alg.TransformFinalBlock(block, 0, 0);
        }

        private static void TestThreads(int seed = 42, int threads = 10)
        {
			var refs = Enumerable.Range(0, threads).Select(x => Task.Run(() =>
			{
                using (var alg = System.Security.Cryptography.HashAlgorithm.Create("SHA256"))
					return PerformanceTest(alg, seed + x);
			})).ToArray();

			var opt = Enumerable.Range(0, threads).Select(x => Task.Run(() =>
            {
                using(var alg = FasterHashing.FasterHash.Create("SHA256"))
                    return PerformanceTest(alg, seed + x);
            })).ToArray();

            Task.WaitAll(refs);
            Task.WaitAll(opt);

            for (var i = 0; i < threads; i++)
                CompareArrays(refs[i].Result, opt[i].Result);
        }
    }
}
