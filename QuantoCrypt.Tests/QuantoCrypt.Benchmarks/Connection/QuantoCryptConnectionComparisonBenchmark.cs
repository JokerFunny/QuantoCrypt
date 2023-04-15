using BenchmarkDotNet.Attributes;
using FluentAssertions;
using QuantoCrypt.Benchmarks.Configuration;
using QuantoCrypt.Common;
using QuantoCrypt.Common.Utilities;
using QuantoCrypt.Connection;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using System.Net;
using System.Text;

namespace QuantoCrypt.Benchmarks.Connection
{
    [MemoryDiagnoser]
    [Config(typeof(FastAndDirtyConfig))]
    public class QuantoCryptConnectionComparisonBenchmark
    {
        static int port = 11000;

        static IPAddress _sIPAddress = Dns.GetHostEntry("localhost").AddressList[0];

        static HttpClientHandler clientHandler = new HttpClientHandler()
        {
            ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; }
        };

        // Pass the handler to httpclient(from you are calling api)
        static HttpClient _sClient = new HttpClient(clientHandler)
        {
            //specify to use TLS 1.2 as default connection
            //ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls;

            BaseAddress = new Uri("https://127.0.0.1:9000/")
        };

        [Benchmark]
        public async Task TLSHandshakeDataAsync()
        {
            string res = await _sClient.GetStringAsync("");

            res.Should().Contain("Raw Request");
        }

        [Benchmark]
        public void TLSHandshakeData()
        {
            string res = _sClient.GetStringAsync("").Result;

            res.Should().Contain("Raw Request");
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(PrefferedCipherSuiteParams))]
        public void QuantoCryptHandshakeData(ulong csIndex, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, prefferedCipherSuite);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            byte[] testData = ArrayUtilities.Combine(new SecureRandom().GenerateSeed(3900), Encoding.UTF8.GetBytes("test message"), new SecureRandom().GenerateSeed(100));

            secureClient1.Send(testData);
            var res = secureServer1.Receive();

            Encoding.UTF8.GetString(res).Should().Contain("test message");
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteParams))]
        public async Task QuantoCryptHandshakeDataAsync(ulong csIndex, ICipherSuite prefferedCipherSuite)
        {
            IPEndPoint targetEndPoint = new IPEndPoint(_sIPAddress, port++);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

            var activeServerConnection1 = serverCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection1));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon1, prefferedCipherSuite);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            byte[] testData = ArrayUtilities.Combine(new SecureRandom().GenerateSeed(3900), Encoding.UTF8.GetBytes("test message"), new SecureRandom().GenerateSeed(100));

            await secureClient1.SendAsync(testData);
            var res = await secureServer1.ReceiveAsync();

            Encoding.UTF8.GetString(res).Should().Contain("test message");
        }

        public IEnumerable<object[]> PrefferedCipherSuiteParams()
        {
            var quantoCryptCipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            foreach (var cipherSuite in quantoCryptCipherSuiteProvider.SupportedCipherSuites)
                yield return new object[] { cipherSuite.Value, cipherSuite.Key };
        }
    }
}
