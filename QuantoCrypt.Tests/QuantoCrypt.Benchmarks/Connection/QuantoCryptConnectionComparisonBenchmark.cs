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
using System.Diagnostics;
using System.Net;
using System.Text;

namespace QuantoCrypt.Benchmarks.Connection
{
    [MemoryDiagnoser]
    //[Config(typeof(FastAndDirtyConfig))]
    public class QuantoCryptConnectionComparisonBenchmark
    {
        static int port = 11000;

        static IPAddress _sIPAddress = Dns.GetHostEntry("localhost").AddressList[0];
        static IPEndPoint _sTargetEndPoint = new IPEndPoint(_sIPAddress, port);
        static SocketTransportConnection _sServerCon = SocketTransportConnection.CreateDefaultServer(_sIPAddress.AddressFamily, _sTargetEndPoint);

        static HttpClientHandler clientHandler = new HttpClientHandler()
        {
            ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; }
        };

        static HttpClient _sClientTLS12 = new HttpClient(clientHandler)
        {
            BaseAddress = new Uri("https://127.0.0.1:9000/")
        };

        static HttpClient _sClientTLS13 = new HttpClient(clientHandler)
        {
            BaseAddress = new Uri("https://127.0.0.1:9002/")
        };

        [Benchmark]
        public async Task TLS12HandshakeDataAsync()
        {
            string res = await _sClientTLS12.GetStringAsync("");

            res.Should().Contain("Raw Request");
        }

        [Benchmark]
        public void TLS12HandshakeData()
        {
            string res = _sClientTLS12.GetStringAsync("").Result;

            res.Should().Contain("Raw Request");
        }

        [Benchmark]
        public async Task TLS13HandshakeDataAsync()
        {
            string res = await _sClientTLS13.GetStringAsync("");

            res.Should().Contain("Raw Request");
        }

        [Benchmark]
        public void TLS13HandshakeData()
        {
            string res = _sClientTLS13.GetStringAsync("").Result;

            res.Should().Contain("Raw Request");
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(PrefferedCipherSuiteParams))]
        public void QuantoCryptHandshakeData(string name, ICipherSuite prefferedCipherSuite)
        {
            SocketTransportConnection clientCon = SocketTransportConnection.CreateDefaultClient(_sIPAddress.AddressFamily, _sTargetEndPoint);

            var activeServerConnection = _sServerCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon, prefferedCipherSuite);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            byte[] testData = ArrayUtilities.Combine(new SecureRandom().GenerateSeed(180), Encoding.UTF8.GetBytes("test message"), new SecureRandom().GenerateSeed(100));

            secureClient1.Send(testData);
            var res = secureServer1.Receive();

            Encoding.UTF8.GetString(res).Should().Contain("test message");

            //secureClient1.Close();
            //secureServer1.Close();
            /*try
            {
                secureClient1.Send(testData);
                var res = secureServer1.Receive();

                Encoding.UTF8.GetString(res).Should().Contain("test message");

                secureClient1.Close();
                secureServer1.Close();
            }
            catch { }*/
        }

        [Benchmark]
        [ArgumentsSource(nameof(PrefferedCipherSuiteParams))]
        public async Task QuantoCryptHandshakeDataAsync(string name, ICipherSuite prefferedCipherSuite)
        {
            SocketTransportConnection clientCon = SocketTransportConnection.CreateDefaultClient(_sIPAddress.AddressFamily, _sTargetEndPoint);

            var activeServerConnection = _sServerCon.Connect();

            ICipherSuiteProvider cipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            QuantoCryptConnectionFactory factory = new QuantoCryptConnectionFactory(cipherSuiteProvider);

            var serverStartTask = Task.Run(() => factory.CreateSecureServerConnection(activeServerConnection));

            ISecureTransportConnection secureClient1 = factory.CreateSecureClientConnection(clientCon, prefferedCipherSuite);
            ISecureTransportConnection secureServer1 = serverStartTask.Result;

            byte[] testData = ArrayUtilities.Combine(new SecureRandom().GenerateSeed(180), Encoding.UTF8.GetBytes("test message"), new SecureRandom().GenerateSeed(100));

            await secureClient1.SendAsync(testData);
            var res = await secureServer1.ReceiveAsync();

            Encoding.UTF8.GetString(res).Should().Contain("test message");

            //secureClient1.Close();
            //secureServer1.Close();
            /*try
            {
                await secureClient1.SendAsync(testData);
                var res = await secureServer1.ReceiveAsync();

                Encoding.UTF8.GetString(res).Should().Contain("test message");

                secureClient1.Close();
                secureServer1.Close();
            }
            catch { }*/
        }

        public IEnumerable<object[]> PrefferedCipherSuiteParams()
        {
            yield return new object[] { "K_DA_AG", new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm() };
            yield return new object[] { "KA_D_A", new CrystalsKyber1024Aes_CrystalsDilithium5_Aes() };

            /*var quantoCryptCipherSuiteProvider = new QuantoCryptCipherSuiteProvider();

            foreach (var cipherSuite in quantoCryptCipherSuiteProvider.SupportedCipherSuites)
                yield return new object[] { cipherSuite.Value, cipherSuite.Key };*/
        }
    }
}
