using BenchmarkDotNet.Attributes;
using QuantoCrypt.Benchmarks.Configuration;
using QuantoCrypt.Common;
using QuantoCrypt.Connection;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using System.Net;
using System.Net.Sockets;
using static QuantoCrypt.Internal.Connection.QuantoCryptConnection;

namespace QuantoCrypt.Benchmarks.Connection
{
    [MemoryDiagnoser]
    [Config(typeof(FastAndDirtyConfig))]
    public class QuantoCryptConnectionDataTransferBenchmark
    {
        static int port = 11000;

        static IPAddress _sIPAddress = Dns.GetHostEntry("localhost").AddressList[0];

        static byte[] test102400Message = new SecureRandom().GenerateSeed(102400);
        //static byte[] test100MbWithSmallMessage = new SecureRandom().GenerateSeed(102400);
        static byte[] test1048576Message = new SecureRandom().GenerateSeed(1048565);
        static byte[] test104857600Message = new SecureRandom().GenerateSeed(104857600);

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public void FastShortConnectionModeWithDataTransfer102400(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            secureClient1.Send(test102400Message);
            var recievedMessage = secureServer1.Receive();

            /*try
            {
            }
            catch { }*/
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public async Task FastShortConnectionModeWithDataTransferAsync102400(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            await secureClient1.SendAsync(test102400Message);
            var recievedMessage = await secureServer1.ReceiveAsync();

            /*try
            {

            }
            catch { }*/
        }

        /*[Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public void FastShortConnectionModeWithDataTransfer10240011(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            List<byte> data = new List<byte>();
            // send and recieve data.
            for (int i = 0; i < 1024; i++)
            {
                try
                {
                    secureClient1.Send(test100MbWithSmallMessage);
                    data.AddRange(secureServer1.Receive());
                }
                catch { }
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public async Task FastShortConnectionModeWithDataTransferAsync10240011(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            List<byte> data = new List<byte>();
            // send and recieve data.
            for (int i = 0; i < 1024; i++)
            {
                try
                {
                    await secureClient1.SendAsync(test100MbWithSmallMessage);
                    data.AddRange(await secureServer1.ReceiveAsync());
                }
                catch { }
            }
        }*/

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public void FastShortConnectionModeWithDataTransfer1048576(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            secureClient1.Send(test1048576Message);

            try
            {
                var recievedMessage = secureServer1.Receive();
            }
            catch { }
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public async Task FastShortConnectionModeWithDataTransferAsync1048576(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            await secureClient1.SendAsync(test1048576Message);

            try
            {
                var recievedMessage = await secureServer1.ReceiveAsync();
            }
            catch { }
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public void FastShortConnectionModeWithDataTransfer104857600(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            secureClient1.Send(test104857600Message);

            try
            {
                var recievedMessage = secureServer1.Receive();
            }
            catch { }
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteFroTransferParams))]
        public async Task FastShortConnectionModeWithDataTransferAsync104857600(string targetAes, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            var connections = _CreateServerClientConnection(addressFamily, targetEndPoint, prefferedCipherSuite);

            ISecureTransportConnection secureClient1 = connections.Item1;
            ISecureTransportConnection secureServer1 = connections.Item2;

            // send and recieve data.
            await secureClient1.SendAsync(test104857600Message);

            try
            {
                var recievedMessage = await secureServer1.ReceiveAsync();
            }
            catch { }
        }

        private (ISecureTransportConnection, ISecureTransportConnection) _CreateServerClientConnection(AddressFamily addressFamily, IPEndPoint targetEndPoint, ICipherSuite prefferedCipherSuite)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, prefferedCipherSuite, ConnectionMode.FastShort);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            return new(secureClient1, secureServer1);
        }

        public IEnumerable<object[]> PrefferedCipherSuiteFroTransferParams()
        {
            yield return new object[] { "AES", new CrystalsKyber1024_CrystalsDilithium5_Aes() };
            yield return new object[] { "AESGCM", new CrystalsKyber1024_CrystalsDilithium5_AesGcm() };
        }
    }
}
