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
    public class QuantoCryptConnectionDataTransferBenchmark
    {
        static int port = 11000;

        static IPAddress _sIPAddress = Dns.GetHostEntry("localhost").AddressList[0];

        static byte[] test1024Message = new SecureRandom().GenerateSeed(1024);
        static byte[] test1048576Message = new SecureRandom().GenerateSeed(1048576);
        static byte[] test104857600Message = new SecureRandom().GenerateSeed(104857600);

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public void DefaulConnectionModeWithDataTransfer1024(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Default);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            secureClient1.Send(test1024Message);

            var recievedMessage = secureServer1.Receive();
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public async Task DefaulConnectionModeWithDataTransferAsync1024(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Default);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            await secureClient1.SendAsync(test1024Message);

            var recievedMessage = await secureServer1.ReceiveAsync();
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public void DefaulConnectionModeWithDataTransfer1048576(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Default);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            secureClient1.Send(test1048576Message);

            var recievedMessage = secureServer1.Receive();
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public async Task DefaulConnectionModeWithDataTransferAsync1048576(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Default);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            await secureClient1.SendAsync(test1048576Message);

            var recievedMessage = await secureServer1.ReceiveAsync();
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public void DefaulConnectionModeWithDataTransfer104857600(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Default);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            secureClient1.Send(test104857600Message);

            var recievedMessage = secureServer1.Receive();
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public async Task DefaulConnectionModeWithDataTransferAsync104857600(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite, QuantoCryptConnection.ConnectionMode.Default);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            await secureClient1.SendAsync(test104857600Message);

            var recievedMessage = await secureServer1.ReceiveAsync();
        }

        private (ISecureTransportConnection, ISecureTransportConnection) _CreateServerClientConnection(AddressFamily addressFamily, IPEndPoint targetEndPoint, ICipherSuite prefferedCipherSuite, QuantoCryptConnection.ConnectionMode connectionMode)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, prefferedCipherSuite, connectionMode);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            return new(secureClient1, secureServer1);
        }

        public IEnumerable<object[]> PrefferedCipherSuiteFroTransferParams()
        {
            yield return new object[] { "AES", new CrystalsKyber1024_CrystalsDilithium5Aes_Aes() };
            yield return new object[] { "AESGCM", new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm() };
        }
    }
}
