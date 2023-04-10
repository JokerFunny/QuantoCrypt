using QuantoCrypt.CipherSuites;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using QuantoCrypt.Protocol;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace QuantoCrypt
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

            Socket server = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            // A Socket must be associated with an endpoint using the Bind method
            server.Bind(localEndPoint);
            // Specify how many requests a Socket can listen before it gives Server busy response.
            // We will listen 10 requests at a time
            server.Listen(10);

            Socket client = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            client.Connect(localEndPoint);

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

            if (!recievedMessage.Substring(0, testData.Length).Equals(testData, StringComparison.OrdinalIgnoreCase))
                throw new Exception($"Recieved massage [{recievedMessage}] != expected [{testData}].");
            
            Console.ReadLine();
        }

        private void _TestViaFluentAPIWithMultipleInstances(AddressFamily addressFamily, EndPoint targetEndPoint)
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

            if (!recievedMessage3.Substring(0, testData.Length).Equals(testData, StringComparison.OrdinalIgnoreCase))
                throw new Exception($"Recieved massage [{recievedMessage3}] != expected [{testData}].");
        }
    }
}