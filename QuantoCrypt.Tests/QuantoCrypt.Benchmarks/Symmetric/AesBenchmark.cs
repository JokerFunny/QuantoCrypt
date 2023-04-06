using BenchmarkDotNet.Attributes;
using FluentAssertions;
using QuantoCrypt.Internal.Symmetric;
using System.Text;

namespace QuantoCrypt.Benchmarks.Symmetric
{
    [MemoryDiagnoser]
    public class AesBenchmark
    {
        public static byte[] FileContent = File.ReadAllBytes("TestData\\input.txt");

        public static byte[] Key = Encoding.UTF8.GetBytes("b14ca5898a4e4133bbce2ea2315a1916");

        [Benchmark(Baseline = true)]
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
        [Arguments(int.MaxValue)]
        public void AesGcmAlgorithmExecutor(int symbolsToProceed)
        {
            byte[] textToProceed = FileContent[0..symbolsToProceed];

            AesGcmAlgorithm service = new AesGcmAlgorithm(Key);

            var res1 = service.Encrypt(textToProceed);

            var res2 = service.Decrypt(res1);

            textToProceed.Should().BeEquivalentTo(res2);
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
        [Arguments(int.MaxValue)]
        public void AesAlgorithmExecutor(int symbolsToProceed)
        {
            byte[] textToProceed = FileContent[0..symbolsToProceed];

            AesAlgorithm service = new AesAlgorithm(Key);

            var res1 = service.Encrypt(textToProceed);

            var res2 = service.Decrypt(res1);

            textToProceed.Should().BeEquivalentTo(res2);
        }

        /*[Benchmark]
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
        [Arguments(int.MaxValue)]
        public void AesTestAlgorithmExecutor(int symbolsToProceed)
        {
            string textToProceed = FileContent.Length > symbolsToProceed ? FileContent.Substring(0, symbolsToProceed) : FileContent;

            Span<byte> textToProceedSpan = Encoding.UTF8.GetBytes(textToProceed).AsSpan();

            Span<byte> encodedOutput = stackalloc byte[textToProceedSpan.Length];
            Span<byte> decodedOutput = stackalloc byte[textToProceedSpan.Length];

            var engine = new AesEngine_X86();
            engine.Init(true, new KeyParameter(Key));
            for (int i = 0; i < textToProceedSpan.Length; i += 16)
                engine.ProcessBlock(textToProceedSpan[i..], encodedOutput[i..]);

            engine.Init(false, new KeyParameter(Key));
            for (int i = 0; i < textToProceedSpan.Length; i += 16)
                engine.ProcessBlock(encodedOutput[i..], decodedOutput[i..]);

            textToProceedSpan.ToArray().Should().BeEquivalentTo(decodedOutput.ToArray());
        }*/
    }
}
