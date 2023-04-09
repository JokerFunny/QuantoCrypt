using BenchmarkDotNet.Attributes;
using FluentAssertions;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Common.BlockCipher;
using QuantoCrypt.Infrastructure.Common.Parameters;
using QuantoCrypt.Internal.Symmetric;
using System.Text;

namespace QuantoCrypt.Benchmarks.Symmetric
{
    [MemoryDiagnoser]
    public class AesBenchmark
    {
        //public static byte[] FileContent = File.ReadAllBytes("TestData\\input.txt");

        public static byte[] RandomInput = new SecureRandom().GenerateSeed(2097152);
        public static byte[] Key = Encoding.UTF8.GetBytes("b14ca5898a4e4133bbce2ea2315a1916");

        [Benchmark(Baseline = true)]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(100)] // add incorrect message size.
        [Arguments(128)]
        [Arguments(256)]
        [Arguments(512)]
        [Arguments(1024)]
        [Arguments(2048)]
        [Arguments(4096)]
        [Arguments(8192)]
        [Arguments(16384)]
        [Arguments(32768)]
        [Arguments(65536)]
        [Arguments(131072)]
        [Arguments(262144)]
        [Arguments(524288)]
        [Arguments(1048576)]
        [Arguments(2097152)]
        //[Arguments(int.MaxValue)]
        public void AesGcmAlgorithmExecutor(int symbolsToProceed)
        {
            /*byte[] textToProceed = FileContent.Length < symbolsToProceed 
                ? FileContent[0..symbolsToProceed] 
                : FileContent;*/

            byte[] textToProceed = RandomInput[0..symbolsToProceed];

            AesGcmAlgorithm service = new AesGcmAlgorithm(Key);

            var encrypted = service.Encrypt(textToProceed);

            var decrypted = service.Decrypt(encrypted);

            textToProceed.Should().BeEquivalentTo(decrypted);
        }

        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(100)] // add incorrect message size.
        [Arguments(128)]
        [Arguments(256)]
        [Arguments(512)]
        [Arguments(1024)]
        [Arguments(2048)]
        [Arguments(4096)]
        [Arguments(8192)]
        [Arguments(16384)]
        [Arguments(32768)]
        [Arguments(65536)]
        [Arguments(131072)]
        [Arguments(262144)]
        [Arguments(524288)]
        [Arguments(1048576)]
        [Arguments(2097152)]
        //[Arguments(int.MaxValue)]
        public void AesAlgorithmExecutor(int symbolsToProceed)
        {
            /*byte[] textToProceed = FileContent.Length < symbolsToProceed 
                ? FileContent[0..symbolsToProceed] 
                : FileContent;*/

            byte[] textToProceed = RandomInput[0..symbolsToProceed];

            AesAlgorithm service = new AesAlgorithm(Key);

            var encrypted = service.Encrypt(textToProceed);

            var decrypted = service.Decrypt(encrypted);

            if (decrypted.Length != textToProceed.Length)
                textToProceed.Should().BeEquivalentTo(decrypted[..textToProceed.Length]);
            else
                textToProceed.Should().BeEquivalentTo(decrypted);
        }

        [Benchmark]
        [Arguments(32)]
        [Arguments(64)]
        [Arguments(128)]
        [Arguments(256)]
        [Arguments(512)]
        [Arguments(1024)]
        [Arguments(2048)]
        [Arguments(4096)]
        [Arguments(8192)]
        [Arguments(16384)]
        [Arguments(32768)]
        [Arguments(65536)]
        [Arguments(131072)]
        [Arguments(262144)]
        [Arguments(524288)]
        [Arguments(1048576)]
        [Arguments(2097152)]
        public void Aes_X86AlgorithmExecutor(int symbolsToProceed)
        {
            byte[] textToProceed = RandomInput[0..symbolsToProceed];

            var engine = new AesEngine_X86();
            ICipherParameter keyParams = new KeyParameter(Key);

            BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

            cipher.Init(true, keyParams);

            byte[] encoded = new byte[symbolsToProceed];

            int len1 = cipher.ProcessBytes(textToProceed, 0, symbolsToProceed, encoded, 0);

            cipher.DoFinal(encoded, len1);

            cipher.Init(false, keyParams);

            byte[] decoded = new byte[symbolsToProceed];
            int len2 = cipher.ProcessBytes(encoded, 0, encoded.Length, decoded, 0);

            cipher.DoFinal(decoded, len2);

            textToProceed.Should().BeEquivalentTo(decoded);
        }
    }
}
