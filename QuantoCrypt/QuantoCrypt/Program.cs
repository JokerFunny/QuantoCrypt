using BenchmarkDotNet.Running;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            //new AesBenchmark().AesGcmServiceExecutor(10);

            BenchmarkRunner.Run<AesBenchmark>();
        }
    }
}