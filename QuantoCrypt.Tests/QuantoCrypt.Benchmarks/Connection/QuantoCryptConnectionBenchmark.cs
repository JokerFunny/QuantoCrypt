using BenchmarkDotNet.Attributes;
using FluentAssertions;
using QuantoCrypt.Benchmarks.Configuration;
using QuantoCrypt.Common;
using QuantoCrypt.Connection;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using System.Net;
using System.Net.Sockets;

namespace QuantoCrypt.Benchmarks.Connection
{
    [MemoryDiagnoser]
    [Config(typeof(FastAndDirtyConfig))]
    public class QuantoCryptConnectionBenchmark
    {
        static int port = 11000;

        static IPAddress _sIPAddress = Dns.GetHostEntry("localhost").AddressList[0];

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(PrefferedCipherSuiteParams))]
        public void DefaulConnectionMode(ulong csIndex, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Default);
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteParams))]
        public void FastConnectionMode(ulong csIndex, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Fast);
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteParams))]
        public void FastShortConnectionMode(ulong csIndex, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.FastShort);
        }

        private void _CreateServerClientConnection(AddressFamily addressFamily, IPEndPoint targetEndPoint, ICipherSuite prefferedCipherSuite, QuantoCryptConnection.ConnectionMode connectionMode)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, prefferedCipherSuite, connectionMode);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;
        }

        public IEnumerable<object[]> PrefferedCipherSuiteParams()
        {
            var quantoCryptCipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            foreach (var cipherSuite in quantoCryptCipherSuiteProvider.SupportedCipherSuites)
                yield return new object[] { cipherSuite.Value, cipherSuite.Key };
        }

        public IEnumerable<object[]> PrefferedCipherSuiteFroTransferParams()
        {
            yield return new object[] { "AES", new CrystalsKyber1024_CrystalsDilithium5Aes_Aes() };
            yield return new object[] { "AESGCM", new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm() };
        }
    }
}
