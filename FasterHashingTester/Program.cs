using System;
using System.Linq;
using System.Threading.Tasks;

namespace FasterHashingTester
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Optimal implementation is: {0}", FasterHashing.FasterHash.PreferedImplementation);

            Console.WriteLine("Performing basic tests");
            Test();

            Console.WriteLine("Performing tests with non-zero offsets");
            TestWithOffset();

            Console.WriteLine("Testing performance");
            foreach (var n in MeasureSpeeds())
                Console.WriteLine("{0, 10} {1}", n.Item1, n.Item2);

			Console.WriteLine("Testing multithreadded execution to wiggle out any shared state problems");
			TestThreads();
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

        private static Tuple<string, TimeSpan>[] MeasureSpeeds()
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
                            PerformanceTest(alg);

                        return new Tuple<string, TimeSpan>(x.ToString(), DateTime.Now - s);
                    })
                    .ToArray();
        }

        private static byte[] PerformanceTest(System.Security.Cryptography.HashAlgorithm alg, int seed = 42)
        {
            var block = new byte[alg.InputBlockSize];
            new Random(seed).NextBytes(block);

            alg.Initialize();
            foreach (var n in Enumerable.Range(0, 10000000))
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
