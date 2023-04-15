using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using QuantoCrypt.Benchmarks.Connection;
using QuantoCrypt.Benchmarks.KEM;
using QuantoCrypt.Benchmarks.Signature;
using QuantoCrypt.Benchmarks.Symmetric;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium;

class Program
{
    static void Main(string[] args)
    {
        //BenchmarkRunner.Run<QuantoCryptConnectionDataTransferBenchmark>();
        BenchmarkRunner.Run<QuantoCryptConnectionComparisonBenchmark>();
        //BenchmarkRunner.Run<QuantoCryptConnectionBenchmark>();
        //BenchmarkRunner.Run<CRYSTALS_KyberBenchmark>();
        //BenchmarkRunner.Run<CRYSTALS_DilithiumBenchmark>();
        //BenchmarkRunner.Run<AesBenchmark>();
        //BenchmarkRunner.Run<SymmetricAlgorithmsBenchmark>();

        //SecureRandom random = new SecureRandom();
        //new SymmetricAlgorithmsBenchmark().Dstu7624_128_Executor(random.GenerateSeed(16), random.GenerateSeed(64));

        //BenchmarkRunner.Run<CRYSTALS_KyberBenchmark>(ManualConfig.Create(DefaultConfig.Instance).WithOption(ConfigOptions.DisableOptimizationsValidator, true));

        //new CRYSTALS_KyberBenchmark().KYBERExecutor(KyberParameters.KYBER1024.Name, KyberParameters.KYBER1024);

        //new CRYSTALS_KyberBenchmark().BouncyCastleKYBERExecutor(Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512);

        //new CRYSTALS_DilithiumBenchmark().DilithiumExecutor(DilithiumParameters.DILITHIUM5_AES.Name, DilithiumParameters.DILITHIUM5_AES);
        //new CRYSTALS_DilithiumBenchmark().BouncyCastleDilithiumExecutor(Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters.Dilithium5Aes);

        //new AesBenchmark().AesAlgorithmExecutor(256);
        //new AesBenchmark().AesGcmAlgorithmExecutor(256);
    }
}