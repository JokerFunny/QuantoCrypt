using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using QuantoCrypt.Benchmarks.KEM;
using QuantoCrypt.Benchmarks.Symmetric;

class Program
{
    static void Main(string[] args)
    {
        BenchmarkRunner.Run<AesBenchmark>();

        //BenchmarkRunner.Run<CRYSTALS_KyberBenchmark>(ManualConfig.Create(DefaultConfig.Instance).WithOption(ConfigOptions.DisableOptimizationsValidator, true));

        //new CRYSTALS_KyberBenchmark().KYBERExecutor(KyberParameters.KYBER1024.Name, KyberParameters.KYBER1024);

        //new CRYSTALS_KyberBenchmark().BouncyCastleKYBERExecutor(Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512);

        //new AesBenchmark().AesTestAlgorithmExecutor(256);
        //new AesBenchmark().AesGcmAlgorithmExecutor(256);
    }
}