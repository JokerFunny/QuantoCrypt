using QuantoCrypt.Common;
using QuantoCrypt.Connection;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit.Abstractions;

namespace QuantoCrypt.Tests.Connection
{
    [Collection("Serial")]
    public class QuantoCryptConnectionTests : IDisposable
    {
        private byte[] targetMessage1MB;
        private byte[] targetMessage01MB;
        private byte[] targetMessage05MB;
        private byte[] targetMessage100MB;
        /*private byte[] targetMessage200MB;
        private byte[] targetMessage500MB;
        private byte[] targetMessage1Gb;*/
        private readonly ITestOutputHelper _rOutput;
        private readonly AddressFamily _rAddressFamily;
        private readonly IPEndPoint _rIPEndPoint;

        private static int _portPlaceHolder = 11000;

        public QuantoCryptConnectionTests(ITestOutputHelper output)
        {
            _rOutput = output;

            SecureRandom random = new SecureRandom();

            // 100 Mb message.
            targetMessage100MB = random.GenerateSeed(104857600);
            /*targetMessage200MB = random.GenerateSeed(104857600 * 2);
            targetMessage500MB = random.GenerateSeed(104857600 * 5);
            targetMessage1Gb = random.GenerateSeed(104857600 * 10);*/
            targetMessage1MB = random.GenerateSeed(1048506);
            targetMessage05MB = random.GenerateSeed(524288);
            targetMessage01MB = random.GenerateSeed(104858);

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];

            _rIPEndPoint = new IPEndPoint(ipAddress, _portPlaceHolder++);
            _rAddressFamily = _rIPEndPoint.AddressFamily;
        }

        public void Dispose()
        {
            targetMessage100MB = null;
            targetMessage1MB = null;
        }

        [Theory]
        [MemberData(nameof(SupportedConnectionModes))]
        public void QuantoCryptConnection_Connection_Establishing_Works_Fine(QuantoCryptConnection.ConnectionMode connectionMode, ICipherSuite prefferedCipherSuite)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, prefferedCipherSuite, connectionMode);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;
        }

        #region DataTransfer

        [Fact]
        public void Test1Mb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            for (int i = 0; i < 100; i++)
            {
                // send and recieve data.
                secureClient1.Send(targetMessage1MB);

                var recievedMessage = secureServer1.Receive();
            }
        }

        [Fact]
        public async Task Test1MbAsync()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            for (int i = 0; i < 100; i++)
            {
                // send and recieve data.
                await secureClient1.SendAsync(targetMessage1MB);

                var recievedMessage = await secureServer1.ReceiveAsync();
            }
        }

        [Fact]
        public void Test01Mb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            for (int i = 0; i < 1000; i++)
            {
                // send and recieve data.
                secureClient1.Send(targetMessage01MB);

                var recievedMessage = secureServer1.Receive();
            }
        }

        [Fact]
        public void Test05Mb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            for (int i = 0; i < 200; i++)
            {
                // send and recieve data.
                secureClient1.Send(targetMessage05MB);

                var recievedMessage = secureServer1.Receive();
            }
        }

        [Fact]
        public void Test100Mb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            // send and recieve data.
            secureClient1.Send(targetMessage100MB);

            var recievedMessage = secureServer1.Receive();
        }

        [Fact]
        public async Task Test100MbAsync()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            // send and recieve data.
            await secureClient1.SendAsync(targetMessage100MB);

            var recievedMessage = await secureServer1.ReceiveAsync();
        }
        /*
        [Fact]
        public void Test200Mb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
        
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            // send and recieve data.
            secureClient1.Send(targetMessage200MB);

            var recievedMessage = secureServer1.Receive();
        }

        [Fact]
        public void Test500Mb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
        
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            // send and recieve data.
            secureClient1.Send(targetMessage500MB);

            var recievedMessage = secureServer1.Receive();
        }

        [Fact]
        public void Test1Gb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
        
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            stopwatch.Stop();

            _rOutput.WriteLine(stopwatch.ElapsedMilliseconds.ToString());

            // send and recieve data.
            secureClient1.Send(targetMessage1Gb);

            var recievedMessage = secureServer1.Receive();
        }*/

        #endregion

        public static IEnumerable<object[]> SupportedConnectionModes()
        {
            Type targetEnumType = typeof(QuantoCryptConnection.ConnectionMode);
            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            foreach (var mode in Enum.GetValues(targetEnumType).Cast<QuantoCryptConnection.ConnectionMode>())
            {
                foreach (var supportedCipherSuite in cipherSuiteProvider.SupportedCipherSuites.Keys)
                {
                    yield return new object[] { mode, supportedCipherSuite };
                }
            }
        }
    }
}
