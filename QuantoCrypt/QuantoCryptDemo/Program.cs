using FluentAssertions;
using QuantoCrypt.Connection;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace QuantoCryptDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            //Console.WriteLine("test");

            // Get Host IP Address that is used to establish a connection
            // In this case, we get one IP address of localhost that is IP : 127.0.0.1
            // If a host has multiple addresses, you will get a list of addresses
            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);

            _sUseGeneralConnectionModeDemo(ipAddress.AddressFamily, localEndPoint);

            localEndPoint.Port += 1;
            _sUseFastConnectionModeDemo(ipAddress.AddressFamily, localEndPoint);

            localEndPoint.Port += 1;
            _sUseFastShortConnectionModeDemo(ipAddress.AddressFamily, localEndPoint);

            localEndPoint.Port += 1;
            _sUseFastShortConnectionModeWithFallbackDemo(ipAddress.AddressFamily, localEndPoint);

            Console.ReadLine();
        }

        private static void _sUseGeneralConnectionModeDemo(AddressFamily addressFamily, EndPoint targetEndPoint)
        {
            Socket server = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            // A Socket must be associated with an endpoint using the Bind method
            server.Bind(targetEndPoint);
            // Specify how many requests a Socket can listen before it gives Server busy response.
            // We will listen 10 requests at a time
            server.Listen(10);

            Socket client = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(targetEndPoint);

            Action<string> traceAction = Console.WriteLine;

            // get SocketTransportConnection for client and server.
            SocketTransportConnection serverCon = new SocketTransportConnection(server.Accept(), traceAction, true);
            SocketTransportConnection clientCon = new SocketTransportConnection(client, traceAction, true);

            // init QuantoCryptConnectionFactory, create ISecureTransportConnection for client + server.
            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(serverCon));

            ISecureTransportConnection secureClient = factory.CreateSecureClientConnection(clientCon, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm());

            ISecureTransportConnection secureServer = serverStartTask.Result;

            // send and recieve data.
            string testData = "test message";

            secureClient.Send(Encoding.UTF8.GetBytes(testData));

            var recievedMessage = Encoding.UTF8.GetString(secureServer.Receive());

            secureClient.Close();
            secureServer.Close();

            Action act1 = () => secureClient.Send(Encoding.UTF8.GetBytes(testData));
            Action act2 = () => secureServer.Receive();

            act1.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");
            act2.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");

            recievedMessage.Should().Be(testData);
        }

        private static void _sUseFastConnectionModeDemo(AddressFamily addressFamily, EndPoint targetEndPoint)
        {
            Socket server = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            // A Socket must be associated with an endpoint using the Bind method
            server.Bind(targetEndPoint);
            // Specify how many requests a Socket can listen before it gives Server busy response.
            // We will listen 10 requests at a time
            server.Listen(10);

            Socket client = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(targetEndPoint);

            Action<string> traceAction = Console.WriteLine;

            // get SocketTransportConnection for client and server.
            SocketTransportConnection serverCon = new SocketTransportConnection(server.Accept(), traceAction, true);
            SocketTransportConnection clientCon = new SocketTransportConnection(client, traceAction, true);

            // init QuantoCryptConnectionFactory, create ISecureTransportConnection for client + server.
            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(serverCon));

            ISecureTransportConnection secureClient = factory.CreateSecureClientConnection(clientCon, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_Aes(), QuantoCryptConnection.ConnectionMode.Fast);

            ISecureTransportConnection secureServer = serverStartTask.Result;

            // send and recieve data.
            string testData = "test message";

            secureClient.Send(Encoding.UTF8.GetBytes(testData));

            var recievedMessage = Encoding.UTF8.GetString(secureServer.Receive());

            secureClient.Close();
            secureServer.Close();

            Action act1 = () => secureClient.Send(Encoding.UTF8.GetBytes(testData));
            Action act2 = () => secureServer.Receive();

            act1.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");
            act2.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");

            recievedMessage.Should().Be(testData);
        }

        private static void _sUseFastShortConnectionModeDemo(AddressFamily addressFamily, EndPoint targetEndPoint)
        {
            Socket server = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            // A Socket must be associated with an endpoint using the Bind method
            server.Bind(targetEndPoint);
            // Specify how many requests a Socket can listen before it gives Server busy response.
            // We will listen 10 requests at a time
            server.Listen(10);

            Socket client = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(targetEndPoint);

            Action<string> traceAction = Console.WriteLine;

            // get SocketTransportConnection for client and server.
            SocketTransportConnection serverCon = new SocketTransportConnection(server.Accept(), traceAction, true);
            SocketTransportConnection clientCon = new SocketTransportConnection(client, traceAction, true);

            // init QuantoCryptConnectionFactory, create ISecureTransportConnection for client + server.
            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(serverCon));

            ISecureTransportConnection secureClient = factory.CreateSecureClientConnection(clientCon, new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm(), QuantoCryptConnection.ConnectionMode.FastShort);

            ISecureTransportConnection secureServer = serverStartTask.Result;

            // send and recieve data.
            string testData = "test message";

            secureClient.Send(Encoding.UTF8.GetBytes(testData));

            var recievedMessage = Encoding.UTF8.GetString(secureServer.Receive());

            secureClient.Close();
            secureServer.Close();

            Action act1 = () => secureClient.Send(Encoding.UTF8.GetBytes(testData));
            Action act2 = () => secureServer.Receive();

            act1.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");
            act2.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");

            recievedMessage.Should().Be(testData);
        }

        private static void _sUseFastShortConnectionModeWithFallbackDemo(AddressFamily addressFamily, EndPoint targetEndPoint)
        {
            Socket server = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            // A Socket must be associated with an endpoint using the Bind method
            server.Bind(targetEndPoint);
            // Specify how many requests a Socket can listen before it gives Server busy response.
            // We will listen 10 requests at a time
            server.Listen(10);

            Socket client = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(targetEndPoint);

            Action<string> traceAction = Console.WriteLine;

            // get SocketTransportConnection for client and server.
            SocketTransportConnection serverCon = new SocketTransportConnection(server.Accept(), traceAction, true);
            SocketTransportConnection clientCon = new SocketTransportConnection(client, traceAction, true);

            // init QuantoCryptConnectionFactory, create ISecureTransportConnection for client + server.
            List<ICipherSuite> serverSupportedCipherSuites = new List<ICipherSuite>()
            {
                new CrystalsKyber1024_CrystalsDilithium5_Aes(),
                new CrystalsKyber1024_CrystalsDilithium5_AesGcm(),
                new CrystalsKyber1024_CrystalsDilithium5Aes_Aes(),
                new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm()
            };
            List<ICipherSuite> clientSupportedCipherSuites = new List<ICipherSuite>()
            {
                new CrystalsKyber1024_CrystalsDilithium5_Aes(),
                new CrystalsKyber1024_CrystalsDilithium5_AesGcm(),
                new CrystalsKyber1024_CrystalsDilithium5Aes_Aes(),
                new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm(),
                new CrystalsKyber1024Aes_CrystalsDilithium5_Aes(),
                new CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm()
            };
            ICipherSuiteProvider serverCipherSuiteProvider = new CustomCipherSuiteProvider(serverSupportedCipherSuites);
            ICipherSuiteProvider clientCipherSuiteProvider = new CustomCipherSuiteProvider(clientSupportedCipherSuites);

            var serverStartTask = Task.Run(() => QuantoCryptConnection.InitializeSecureServer(serverCipherSuiteProvider, serverCon));

            ISecureTransportConnection secureClient = QuantoCryptConnection.InitializeSecureClient(clientCipherSuiteProvider, new CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm(), clientCon, QuantoCryptConnection.ConnectionMode.FastShort);

            ISecureTransportConnection secureServer = serverStartTask.Result;

            // send and recieve data.
            string testData = "test message";

            secureClient.Send(Encoding.UTF8.GetBytes(testData));

            var recievedMessage = Encoding.UTF8.GetString(secureServer.Receive());

            secureClient.Close();
            secureServer.Close();

            Action act1 = () => secureClient.Send(Encoding.UTF8.GetBytes(testData));
            Action act2 = () => secureServer.Receive();

            act1.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");
            act2.Should().Throw<ObjectDisposedException>()
                .WithMessage("*The connection has been successfully closed and can't be used!*");

            recievedMessage.Should().Be(testData);
        }

        private void _sTestViaFluentAPIWithMultipleInstances(AddressFamily addressFamily, EndPoint targetEndPoint)
        {
            Action<string> traceAction = Console.WriteLine;
            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint, traceAction);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint, traceAction);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            // send and recieve data.
            string testData = "test message";

            // send from client1 to server1.
            secureClient1.Send(Encoding.UTF8.GetBytes(testData));
            var recievedMessage = Encoding.UTF8.GetString(secureServer1.Receive());

            if (!recievedMessage.Substring(0, testData.Length).Equals(testData, StringComparison.OrdinalIgnoreCase))
                throw new Exception($"Recieved massage [{recievedMessage}] != expected [{testData}].");

            // create 2nd connection pair.
            SocketTransportConnection clientCon2 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint, traceAction);
            var activeServerConnection2 = serverCon.Connect();

            serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection2));

            ISecureTransportConnection secureClient2 = factory.CreateSecureClientConnection(clientCon2);
            ISecureTransportConnection secureServer2 = serverStartTask.Result;

            // send from client2 to server2.
            secureClient2.Send(Encoding.UTF8.GetBytes(testData));
            var recievedMessage2 = Encoding.UTF8.GetString(secureServer2.Receive());

            if (!recievedMessage2.Substring(0, testData.Length).Equals(testData, StringComparison.OrdinalIgnoreCase))
                throw new Exception($"Recieved massage [{recievedMessage2}] != expected [{testData}].");

            // send from client1 to server1.
            secureClient1.Send(Encoding.UTF8.GetBytes(testData));
            var recievedMessage3 = Encoding.UTF8.GetString(secureServer1.Receive());

            recievedMessage.Should().Be(testData);
        }
    }
}