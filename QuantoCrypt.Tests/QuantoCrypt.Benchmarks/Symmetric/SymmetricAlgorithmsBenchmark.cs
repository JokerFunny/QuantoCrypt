using BenchmarkDotNet.Attributes;
using FluentAssertions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using QuantoCrypt.Benchmarks.Configuration;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Benchmarks.Symmetric
{
    [MemoryDiagnoser]
    //[RPlotExporter]
    //[Config(typeof(FastAndDirtyConfig))]
    public class SymmetricAlgorithmsBenchmark
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(SymmetricAlgorithmClassicalParams))]
        public void Aes_Executor(byte[] key, byte[] data)
        {
            var engine = new AesEngine();
            var keyParam = new KeyParameter(key);

            _PerformTest(engine, keyParam, data);
        }

        /*
        [Benchmark]
        [ArgumentsSource(nameof(SymmetricAlgorithmClassicalParams))]
        public void Aes_X86_Optimized_Executor(byte[] key, byte[] data)
        {
            var engine = new QuantoCrypt.Common.BlockCipher.AesEngine_X86();
            var keyParams = new QuantoCrypt.Common.Parameters.KeyParameter(key);

            var cipher = new QuantoCrypt.Common.BlockCipher.BufferedBlockCipher(engine);

            cipher.Init(true, keyParams);

            byte[] encoded = new byte[data.Length];

            int len1 = cipher.ProcessBytes(data, 0, data.Length, encoded, 0);

            cipher.DoFinal(encoded, len1);

            cipher.Init(false, keyParams);

            byte[] decoded = new byte[data.Length];
            int len2 = cipher.ProcessBytes(encoded, 0, encoded.Length, decoded, 0);

            cipher.DoFinal(decoded, len2);

            data.Should().BeEquivalentTo(decoded);
        }

        [Benchmark]
        [ArgumentsSource(nameof(SymmetricAlgorithmClassicalParams))]
        public void AesGcm_Optimized_Executor(byte[] key, byte[] data)
        {
            AesGcmAlgorithm service = new AesGcmAlgorithm(key);

            var encrypted = service.Encrypt(data);

            var decrypted = service.Decrypt(encrypted);

            data.Should().BeEquivalentTo(decrypted);
        }

        [Benchmark]
        [ArgumentsSource(nameof(SymmetricAlgorithmClassicalParams))]
        public void Aes_Optimized_Executor(byte[] key, byte[] data)
        {
            AesAlgorithm service = new AesAlgorithm(key);

            var encrypted = service.Encrypt(data);

            var decrypted = service.Decrypt(encrypted);

            data.Should().BeEquivalentTo(decrypted);
        }*/

        [Benchmark]
        [ArgumentsSource(nameof(Dstu7624_128Params))]
        public void Dstu7624_128_Executor(byte[] key, byte[] data)
        {
            var engine = new Dstu7624Engine(128);
            var keyParam = new KeyParameter(key);

            _PerformTest(engine, keyParam, data);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Dstu7624_256Params))]
        public void Dstu7624_256_Executor(byte[] key, byte[] data)
        {
            var engine = new Dstu7624Engine(256);
            var keyParam = new KeyParameter(key);

            _PerformTest(engine, keyParam, data);
        }

        [Benchmark]
        [ArgumentsSource(nameof(Dstu7624_512Params))]
        public void Dstu7624_512_Executor(byte[] key, byte[] data)
        {
            var engine = new Dstu7624Engine(512);
            var keyParam = new KeyParameter(key);

            _PerformTest(engine, keyParam, data);
        }

        [Benchmark]
        [ArgumentsSource(nameof(SymmetricAlgorithmCustomParams))]
        public void Blowfish_Executor(byte[] key, byte[] data)
        {
            var engine = new BlowfishEngine();
            var keyParam = new KeyParameter(key);

            _PerformTest(engine, keyParam, data);
        }

        [Benchmark]
        [ArgumentsSource(nameof(SymmetricAlgorithmClassicalParams))]
        public void Twofish_Executor(byte[] key, byte[] data)
        {
            var engine = new TwofishEngine();
            var keyParam = new KeyParameter(key);

            _PerformTest(engine, keyParam, data);
        }

        private void _PerformTest(IBlockCipher engine, ICipherParameters param, byte[] input)
        {
            BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

            cipher.Init(true, param);

            byte[] encoded = new byte[input.Length];

            int len1 = cipher.ProcessBytes(input, 0, input.Length, encoded, 0);

            cipher.DoFinal(encoded, len1);

            cipher.Init(false, param);

            byte[] decoded = new byte[input.Length];
            int len2 = cipher.ProcessBytes(encoded, 0, encoded.Length, decoded, 0);

            cipher.DoFinal(decoded, len2);

            input.Should().BeEquivalentTo(decoded);
        }

        /// <summary>
        /// Generates 15 input params.
        /// </summary>
        /// <returns>
        ///     5 params for 16-bits key, 5 - for 24-bits, 5 - for 32-bits.
        ///     input = [ byte[128], byte[256], byte[512], byte[1024], byte[2048] ].
        /// </returns>
        public static IEnumerable<object[]> SymmetricAlgorithmClassicalParams()
        {
            var secureRandom = new QuantoCrypt.Common.SecureRandom();
            int lengthMultiplicator = 16;

            List<Tuple<byte[], byte[]>> data = new();
            byte[] key, testData;
            for (int i = 0; i < 3; i++)
            {
                key = secureRandom.GenerateSeed(lengthMultiplicator);

                for (int j = 128; j <= 2048; j *= 2)
                {
                    testData = secureRandom.GenerateSeed(j);

                    data.Add(new Tuple<byte[], byte[]>(key, testData));
                }

                lengthMultiplicator += 8;
            }

            foreach (var item in data)
                yield return new object[] { item.Item1, item.Item2 };
        }

        /// <summary>
        /// Generates 10 input params.
        /// </summary>
        /// <returns>
        ///     5 params for 16-bits key, 5 - for 32-bits.
        ///     input = [ byte[128], byte[256], byte[512], byte[1024], byte[2048] ].
        /// </returns>
        public static IEnumerable<object[]> Dstu7624_128Params()
        {
            var secureRandom = new QuantoCrypt.Common.SecureRandom();
            int lengthMultiplicator = 16;

            List<Tuple<byte[], byte[]>> data = new();
            byte[] key, testData;
            for (int i = 0; i < 2; i++)
            {
                key = secureRandom.GenerateSeed(lengthMultiplicator);

                for (int j = 128; j <= 2048; j *= 2)
                {
                    testData = secureRandom.GenerateSeed(j);

                    data.Add(new Tuple<byte[], byte[]>(key, testData));
                }

                lengthMultiplicator *= 2;
            }

            foreach (var item in data)
                yield return new object[] { item.Item1, item.Item2 };
        }

        /// <summary>
        /// Generates 10 input params.
        /// </summary>
        /// <returns>
        ///     5 params for 32-bits key, 5 - for 64-bits.
        ///     input = [ byte[128], byte[256], byte[512], byte[1024], byte[2048] ].
        /// </returns>
        public static IEnumerable<object[]> Dstu7624_256Params()
        {
            var secureRandom = new QuantoCrypt.Common.SecureRandom();
            int lengthMultiplicator = 32;

            List<Tuple<byte[], byte[]>> data = new();
            byte[] key, testData;
            for (int i = 0; i < 2; i++)
            {
                key = secureRandom.GenerateSeed(lengthMultiplicator);

                for (int j = 128; j <= 2048; j *= 2)
                {
                    testData = secureRandom.GenerateSeed(j);

                    data.Add(new Tuple<byte[], byte[]>(key, testData));
                }

                lengthMultiplicator *= 2;
            }

            foreach (var item in data)
                yield return new object[] { item.Item1, item.Item2 };
        }

        /// <summary>
        /// Generates 5 input params.
        /// </summary>
        /// <returns>
        ///     5 params for 64-bits key.
        ///     input = [ byte[128], byte[256], byte[512], byte[1024], byte[2048] ].
        /// </returns>
        public static IEnumerable<object[]> Dstu7624_512Params()
        {
            var secureRandom = new QuantoCrypt.Common.SecureRandom();
            int lengthMultiplicator = 64;

            List<Tuple<byte[], byte[]>> data = new();
            byte[] key, testData;
            for (int i = 0; i < 1; i++)
            {
                key = secureRandom.GenerateSeed(lengthMultiplicator);

                for (int j = 128; j <= 2048; j *= 2)
                {
                    testData = secureRandom.GenerateSeed(j);

                    data.Add(new Tuple<byte[], byte[]>(key, testData));
                }

                lengthMultiplicator *= 2;
            }

            foreach (var item in data)
                yield return new object[] { item.Item1, item.Item2 };
        }

        /// <summary>
        /// Generates 15 input params.
        /// </summary>
        /// <returns>
        ///     5 params for 8-bits key, 5 - for 32-bits, 5 - for 56-bits.
        ///     input = [ byte[128], byte[256], byte[512], byte[1024], byte[2048] ].
        /// </returns>
        public static IEnumerable<object[]> SymmetricAlgorithmCustomParams()
        {
            var secureRandom = new QuantoCrypt.Common.SecureRandom();
            int lengthMultiplicator = 8;

            List<Tuple<byte[], byte[]>> data = new();
            byte[] key, testData;
            for (int i = 0; i < 3; i++)
            {
                key = secureRandom.GenerateSeed(lengthMultiplicator);

                for (int j = 128; j <= 2048; j *= 2)
                {
                    testData = secureRandom.GenerateSeed(j);

                    data.Add(new Tuple<byte[], byte[]>(key, testData));
                }

                lengthMultiplicator += 24;
            }

            foreach (var item in data)
                yield return new object[] { item.Item1, item.Item2 };
        }
    }
}
