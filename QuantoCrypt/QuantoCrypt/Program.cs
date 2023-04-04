using BenchmarkDotNet.Running;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            new AesBenchmark().AesGcmAlgorithmExecutor(256);
            new AesBenchmark().AesAlgorithmExecutor(256);

            //BenchmarkRunner.Run<AesBenchmark>();
        }
    }
}