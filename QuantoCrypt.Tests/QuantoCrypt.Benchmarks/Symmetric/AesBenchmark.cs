using BenchmarkDotNet.Attributes;
using FluentAssertions;
using QuantoCrypt.Internal.Symmetric;
using System.Text;

namespace QuantoCrypt.Benchmarks.Symmetric
{
    [MemoryDiagnoser]
    public class AesBenchmark
    {
        public static string FileContent = File.ReadAllText("TestData\\input.txt");

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
            string textToProceed = FileContent.Length > symbolsToProceed ? FileContent.Substring(0, symbolsToProceed) : FileContent;
            byte[] textToProceedArray = Encoding.UTF8.GetBytes(textToProceed);

            AesGcmAlgorithm service = new AesGcmAlgorithm(Key);

            var res1 = service.Encrypt(textToProceedArray);

            var res2 = service.Decrypt(res1);

            textToProceedArray.Should().BeEquivalentTo(res2);
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
            string textToProceed = FileContent.Length > symbolsToProceed ? FileContent.Substring(0, symbolsToProceed) : FileContent;
            byte[] textToProceedArray = Encoding.UTF8.GetBytes(textToProceed);
            AesAlgorithm service = new AesAlgorithm(Key);

            var res1 = service.Encrypt(textToProceedArray);

            var res2 = service.Decrypt(res1);

            textToProceedArray.Should().BeEquivalentTo(res2);
        }
    }
}
