using FluentAssertions;
using QuantoCrypt.Common;
using QuantoCrypt.Connection;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using QuantoCrypt.Internal.Message;
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
        [MemberData(nameof(SupportedConnectionModesWithCS))]
        public void QuantoCryptConnection_Connection_Establishing_Works_Fine(QuantoCryptConnection.ConnectionMode connectionMode, ICipherSuite prefferedCipherSuite)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection));

            ISecureTransportConnection secureClient = factory.CreateSecureClientConnection(clientCon, prefferedCipherSuite, connectionMode);
            ISecureTransportConnection secureServer = serverStartTask.Result;
        }

        [Theory]
        [MemberData(nameof(SupportedConnectionModes))]
        public void QuantoCryptConnection_Throw_Using_Invalid_CipherSuiteProvider_And_PrefferedCipherSuite(QuantoCryptConnection.ConnectionMode connectionMode)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection = serverCon.Connect();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(null);

            var secureClientCreateAction = () => factory.CreateSecureClientConnection(clientCon, null, connectionMode);
            secureClientCreateAction.Should().Throw<ArgumentException>()
                .WithMessage("SupportedCipherSuites can't be null or empty! Please, recheck your code - the [cipherSuiteProvider] param.");

            var secureServerCreateAction = () => factory.CreateSecureServerConnection(activeServerConnection);
            secureClientCreateAction.Should().Throw<ArgumentException>()
                .WithMessage("SupportedCipherSuites can't be null or empty! Please, recheck your code - the [cipherSuiteProvider] param.");

            ICipherSuiteProvider cipherSuiteProvider = new CustomCipherSuiteProvider(new List<ICipherSuite>() 
            { 
                new CrystalsKyber1024_CrystalsDilithium5_Aes(),
                new CrystalsKyber1024_CrystalsDilithium5_AesGcm()
            });

            QuantoCryptConnectionFactory factory1 = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var secureClientCreateActionWithValidProviderButWithoutPreferredCS = () => factory1.CreateSecureClientConnection(clientCon, null, connectionMode);
            secureClientCreateActionWithValidProviderButWithoutPreferredCS.Should().Throw<ArgumentException>()
                .WithMessage("[preferredCipher] shouldn't be null or empty.");

            var secureClientCreateActionWithValidProviderButPreferredCSIsNotAPartOfProvider = () => factory1.CreateSecureClientConnection(clientCon, new CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm(), connectionMode);
            secureClientCreateActionWithValidProviderButPreferredCSIsNotAPartOfProvider.Should().Throw<ArgumentException>()
                .WithMessage("You're trying to use the cipher suite that is not listened in the*");
        }

        [Theory]
        [MemberData(nameof(SupportedConnectionModes))]
        public void QuantoCryptConnection_Server_Throw_In_Case_Client_Init_message_Integrity_Fails(QuantoCryptConnection.ConnectionMode connectionMode)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var preferredCipher = cipherSuiteProvider.SupportedCipherSuites.Keys.First();
            var kemAlgorithm = preferredCipher.GetKEMAlgorithm();

            AsymmetricKeyPair keys = kemAlgorithm.KeyGen();
            byte[] publicKey = keys.Public.GetEncoded();

            var clientInitMessage1 = ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, (byte)connectionMode, publicKey);

            // change message integrity value.
            clientInitMessage1[7]++;
            clientInitMessage1[8]--;

            clientCon.Send(clientInitMessage1);

            var serverStartTask1 = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));
            var secureServerAction1 = () => serverStartTask1.Result;

            secureServerAction1.Should().Throw<ArgumentException>()
                .WithMessage("Message integrity check fails.");

            var clientInitMessage2 = ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, (byte)connectionMode, publicKey);

            // change message body.
            clientInitMessage2[11]++;
            clientInitMessage2[12]--;

            SocketTransportConnection clientCon2 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);
            var activeServerConnection2 = serverCon.Connect();
            clientCon2.Send(clientInitMessage2);

            var serverStartTask2 = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection2));
            var secureServerAction2 = () => serverStartTask2.Result;

            secureServerAction2.Should().Throw<ArgumentException>()
                .WithMessage("Message integrity check fails.");
        }

        [Theory]
        [MemberData(nameof(SupportedConnectionModes))]
        public void QuantoCryptConnection_Server_Throw_In_Case_Client_Sent_invalid_Message_Type_Instead_Of_ClientInit(QuantoCryptConnection.ConnectionMode connectionMode)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var preferredCipher = cipherSuiteProvider.SupportedCipherSuites.Keys.First();
            var kemAlgorithm = preferredCipher.GetKEMAlgorithm();

            AsymmetricKeyPair keys = kemAlgorithm.KeyGen();
            byte[] publicKey = keys.Public.GetEncoded();

            var clientInitMessage1 = ProtocolMessage.CreateServerInitMessage(publicKey);

            clientCon.Send(clientInitMessage1);

            var serverStartTask1 = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));
            var secureServerAction1 = () => serverStartTask1.Result;

            secureServerAction1.Should().Throw<ArgumentException>()
                .WithMessage($"Client sent invalid messageType. Expected [1], found [{clientInitMessage1[1]}].");

            var clientInitMessage2 = ProtocolMessage.CreateClientFinishMessage(publicKey);

            SocketTransportConnection clientCon2 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);
            var activeServerConnection2 = serverCon.Connect();
            clientCon2.Send(clientInitMessage2);

            var serverStartTask2 = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection2));
            var secureServerAction2 = () => serverStartTask2.Result;

            secureServerAction2.Should().Throw<ArgumentException>()
                .WithMessage($"Client sent invalid messageType. Expected [1], found [{clientInitMessage2[1]}].");
        }

        [Theory]
        [MemberData(nameof(SupportedConnectionModes))]
        public void QuantoCryptConnection_Server_Throw_In_Case_Client_Sent_invalid_Connection_Mode(QuantoCryptConnection.ConnectionMode connectionMode)
        {
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(_rAddressFamily, _rIPEndPoint);
            SocketTransportConnection clientCon = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var preferredCipher = cipherSuiteProvider.SupportedCipherSuites.Keys.First();
            var kemAlgorithm = preferredCipher.GetKEMAlgorithm();

            AsymmetricKeyPair keys = kemAlgorithm.KeyGen();
            byte[] publicKey = keys.Public.GetEncoded();

            var clientInitMessage1 = ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, 25, publicKey);

            clientCon.Send(clientInitMessage1);

            var serverStartTask1 = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));
            var secureServerAction1 = () => serverStartTask1.Result;

            secureServerAction1.Should().Throw<ArgumentOutOfRangeException>()
                .WithMessage("*Connection mode could be only 0, 1 or 2, but found [25]!*");

            var clientInitMessage2 = ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, 3, publicKey);

            SocketTransportConnection clientCon2 = SocketTransportConnection.CreateDefaultClient(_rAddressFamily, _rIPEndPoint);
            var activeServerConnection2 = serverCon.Connect();
            clientCon2.Send(clientInitMessage2);

            var serverStartTask2 = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection2));
            var secureServerAction2 = () => serverStartTask2.Result;

            secureServerAction2.Should().Throw<ArgumentOutOfRangeException>()
                .WithMessage("*Connection mode could be only 0, 1 or 2, but found [3]!*");
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

        public static IEnumerable<object[]> SupportedConnectionModesWithCS()
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

        public static IEnumerable<object[]> SupportedConnectionModes()
        {
            Type targetEnumType = typeof(QuantoCryptConnection.ConnectionMode);

            foreach (var mode in Enum.GetValues(targetEnumType).Cast<QuantoCryptConnection.ConnectionMode>())
                yield return new object[] { mode };
        }
    }
}
