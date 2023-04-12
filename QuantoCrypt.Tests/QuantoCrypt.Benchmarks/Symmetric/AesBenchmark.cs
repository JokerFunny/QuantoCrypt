using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Security;
using QuantoCrypt.Common.BlockCipher;
using QuantoCrypt.Common.Parameters;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Benchmarks.Symmetric
{
    [MemoryDiagnoser]
    public class AesBenchmark
    {
        //public static byte[] FileContent = File.ReadAllBytes("TestData\\input.txt");

        //public static byte[] RandomInput = new SecureRandom().GenerateSeed(2097152);
        //public static byte[] Key = Encoding.UTF8.GetBytes("b14ca5898a4e4133bbce2ea2315a1916");

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(SymmetricAlgorithmInputParams))]
        public void AesGcmAlgorithmExecutor(byte[] key, byte[] textToProceed)
        {
            AesGcmAlgorithm service = new AesGcmAlgorithm(key);

            var encrypted = service.Encrypt(textToProceed);

            var decrypted = service.Decrypt(encrypted);

            //textToProceed.Should().BeEquivalentTo(decrypted);
        }

        [Benchmark]
        [ArgumentsSource(nameof(SymmetricAlgorithmInputParams))]
        public void AesAlgorithmExecutor(byte[] key, byte[] textToProceed)
        {
            AesAlgorithm service = new AesAlgorithm(key);

            var encrypted = service.Encrypt(textToProceed);

            var decrypted = service.Decrypt(encrypted);

            /*if (decrypted.Length != textToProceed.Length)
                textToProceed.Should().BeEquivalentTo(decrypted[..textToProceed.Length]);
            else
                textToProceed.Should().BeEquivalentTo(decrypted);*/
        }

        [Benchmark]
        [ArgumentsSource(nameof(SymmetricAlgorithmInputParams))]
        public void Aes_X86AlgorithmExecutor(byte[] key, byte[] textToProceed)
        {
            var engine = new AesEngine_X86();
            ICipherParameter keyParams = new KeyParameter(key);

            BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

            cipher.Init(true, keyParams);

            byte[] encoded = new byte[textToProceed.Length];

            int len1 = cipher.ProcessBytes(textToProceed, 0, textToProceed.Length, encoded, 0);

            cipher.DoFinal(encoded, len1);

            cipher.Init(false, keyParams);

            byte[] decoded = new byte[textToProceed.Length];
            int len2 = cipher.ProcessBytes(encoded, 0, encoded.Length, decoded, 0);

            cipher.DoFinal(decoded, len2);

            //textToProceed.Should().BeEquivalentTo(decoded);
        }

        public IEnumerable<object[]> SymmetricAlgorithmInputParams()
        {
            SecureRandom secureRandom = new SecureRandom();
            byte[] fileContent = File.ReadAllBytes("TestData\\input.txt");
            byte[] key = secureRandom.GenerateSeed(32);

            // check the message size which is not alligned with the block_size value.
            yield return new object[] { key, fileContent[0..100] };

            for (int i = 32; i < fileContent.Length; i *= 2) 
            {
                if (i > fileContent.Length)
                    yield return new object[] { key, fileContent };
                else
                    yield return new object[] { key, fileContent[0..i] };
            }
        }
    }
}
