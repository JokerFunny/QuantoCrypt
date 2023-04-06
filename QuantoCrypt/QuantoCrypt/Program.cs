using QuantoCrypt.CipherSuites;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
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
            Console.WriteLine("test");

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

            SocketTransportConnection serverCon = new SocketTransportConnection(server.Accept());
            SocketTransportConnection clientCon = new SocketTransportConnection(client);

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            ISecureTransportConnection secureServer;
            Task.Run(() => secureServer = factory.CreateSecureServerConnection(serverCon));

            var secureClient = factory.CreateSecureClientConnection(clientCon);

            secureClient.Send(Encoding.ASCII.GetBytes("test message"));

            //StartServer();

            Console.ReadLine();
        }
    }
}