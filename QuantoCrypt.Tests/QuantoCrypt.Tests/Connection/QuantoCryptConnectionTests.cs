﻿using QuantoCrypt.Common;
using QuantoCrypt.Connection;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using System.Diagnostics;
using System.Net;
using Xunit.Abstractions;

namespace QuantoCrypt.Tests.Connection
{
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
        }

        public void Dispose()
        {
            targetMessage100MB = null;
            targetMessage1MB = null;
        }

        [Fact]
        public void Test1Mb()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11000);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11010);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11001);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11002);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11003);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11013);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11003);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11003);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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

            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint targetEndPoint = new IPEndPoint(ipAddress, 11003);
            var addressFamily = targetEndPoint.AddressFamily;

            SocketTransportConnection serverCon = SocketTransportConnection.CreateDefaultServer(addressFamily, targetEndPoint);
            SocketTransportConnection clientCon1 = SocketTransportConnection.CreateDefaultClient(addressFamily, targetEndPoint);

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
    }
}
