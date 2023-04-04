using BenchmarkDotNet.Attributes;
using FluentAssertions;

namespace QuantoCrypt.Internal.Symmetric
{
    [MemoryDiagnoser]
    public class AesBenchmark
    {
        public static string FileContent = File.ReadAllText("C:\\Users\\Danylo\\Desktop\\deeckLoooom\\QuantoCrypt\\QuantoCrypt\\input.txt");

        public static string Key = "b14ca5898a4e4133bbce2ea2315a1916";

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

            AesGcmAlgorithm service = new AesGcmAlgorithm(Key);

            var res1 = service.Encrypt(textToProceed);

            var res2 = service.Decrypt(res1);

            textToProceed.Should().Be(res2);
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

            AesAlgorithm service = new AesAlgorithm(Key);

            var res1 = service.Encrypt(textToProceed);

            var res2 = service.Decrypt(res1);

            textToProceed.Should().Be(res2);
        }
    }
}
