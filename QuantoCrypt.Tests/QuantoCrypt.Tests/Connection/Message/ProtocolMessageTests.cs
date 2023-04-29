using FluentAssertions;
using Microsoft.VisualStudio.TestPlatform.CommunicationUtilities;
using QuantoCrypt.Common;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Connection;
using QuantoCrypt.Internal.Message;

namespace QuantoCrypt.Tests.Connection.Message
{
    public class ProtocolMessageTests
    {
        [Fact]
        public void ProtocolMessage_CreateClientInitMessage_Works_Fine()
        {
            SecureRandom rand = new SecureRandom();
            var supportedCipherSuites = new QuantoCryptCipherSuiteProvider();

            var testKey = rand.GenerateSeed(128);
            var message = ProtocolMessage.CreateClientInitMessage(supportedCipherSuites, supportedCipherSuites.SupportedCipherSuites.First().Key, (byte)QuantoCryptConnection.ConnectionMode.Default, testKey);

            message.Should().NotBeNull();
            message.Length.Should().Be(128 + 2 + 10);
            message[0].Should().Be(1);
            message[1].Should().Be(1);
            ProtocolMessage.GetUintValue(message, 2, 4).Should().Be(128 + 2);

            var messageIntegrityCheck = message.ToArray();
            messageIntegrityCheck[6] = 0;
            messageIntegrityCheck[7] = 0;
            messageIntegrityCheck[8] = 0;
            messageIntegrityCheck[9] = 0;

            var messageIntegrity = message[6..10];
            var calculatedIntegrity = ProtocolMessage.GetMessageHash(messageIntegrityCheck)[0..4];
            messageIntegrity.Should().BeEquivalentTo(calculatedIntegrity);

            // message body.
            message[10].Should().Be((byte)supportedCipherSuites.SupportedCipherSuites.Keys.ToList().IndexOf(x => x.Name == supportedCipherSuites.SupportedCipherSuites.First().Key.Name));
            message[11].Should().Be((byte)QuantoCryptConnection.ConnectionMode.Default);

            message[12..].Should().BeEquivalentTo(testKey);
        }

        [Fact]
        public void ProtocolMessage_CreateServerInitMessage_Works_Fine()
        {
            SecureRandom rand = new SecureRandom();

            var cipherText = rand.GenerateSeed(128);
            var attachedSig = rand.GenerateSeed(100);

            // server init with signature.
            var message1 = ProtocolMessage.CreateServerInitMessage(cipherText, attachedSig, 40, 60);

            message1.Should().NotBeNull();
            message1.Length.Should().Be(128 + 12 + 100 + 10);
            message1[0].Should().Be(1);
            message1[1].Should().Be(2);
            ProtocolMessage.GetUintValue(message1, 2, 4).Should().Be(128 + 12 + 100);

            var messageIntegrityCheck1 = message1.ToArray();
            messageIntegrityCheck1[6] = 0;
            messageIntegrityCheck1[7] = 0;
            messageIntegrityCheck1[8] = 0;
            messageIntegrityCheck1[9] = 0;

            var messageIntegrity1 = message1[6..10];
            var calculatedIntegrity1 = ProtocolMessage.GetMessageHash(messageIntegrityCheck1)[0..4];
            messageIntegrity1.Should().BeEquivalentTo(calculatedIntegrity1);

            // message body.
            var cipherTextLength1 = ProtocolMessage.GetIntValue(message1, 10, 4);
            cipherTextLength1.Should().Be(cipherText.Length);
            message1[14..(14 + cipherTextLength1)].Should().BeEquivalentTo(cipherText);

            var signaturePartLength1 = ProtocolMessage.GetIntValue(message1, 14 + cipherTextLength1, 4);
            var signaturePublicKeyLength1 = ProtocolMessage.GetIntValue(message1, 18 + cipherTextLength1, 4);

            signaturePartLength1.Should().Be(40);
            signaturePublicKeyLength1.Should().Be(60);

            var attachedSignature1 = message1[(22 + cipherTextLength1)..];
            attachedSignature1.Should().BeEquivalentTo(attachedSig);

            // server init without signature.
            var message2 = ProtocolMessage.CreateServerInitMessage(cipherText);

            message2.Should().NotBeNull();
            message2.Length.Should().Be(128 + 4 + 10);
            message2[0].Should().Be(1);
            message2[1].Should().Be(2);
            ProtocolMessage.GetUintValue(message2, 2, 4).Should().Be(128 + 4);

            var messageIntegrityCheck2 = message2.ToArray();
            messageIntegrityCheck2[6] = 0;
            messageIntegrityCheck2[7] = 0;
            messageIntegrityCheck2[8] = 0;
            messageIntegrityCheck2[9] = 0;

            var messageIntegrity2 = message2[6..10];
            var calculatedIntegrity2 = ProtocolMessage.GetMessageHash(messageIntegrityCheck2)[0..4];
            messageIntegrity2.Should().BeEquivalentTo(calculatedIntegrity2);

            // message body.
            var cipherTextLength2 = ProtocolMessage.GetIntValue(message2, 10, 4);
            cipherTextLength2.Should().Be(cipherText.Length);
            message2[14..(14 + cipherTextLength2)].Should().BeEquivalentTo(cipherText);
        }

        [Fact]
        public void ProtocolMessage_CreateUnsupportedClientParamsMessage_Works_Fine()
        {
            SecureRandom rand = new SecureRandom();
            var supportedCipherSuites = new QuantoCryptCipherSuiteProvider();

            var message = ProtocolMessage.CreateUnsupportedClientParamsMessage(supportedCipherSuites);

            message.Should().NotBeNull();
            message.Length.Should().Be(10 + ProtocolMessage.SUPPORTED_CIPHER_SUITES_OFFSET);
            message[0].Should().Be(1);
            message[1].Should().Be(3);
            ProtocolMessage.GetUintValue(message, 2, 4).Should().Be(ProtocolMessage.SUPPORTED_CIPHER_SUITES_OFFSET);

            var messageIntegrityCheck = message.ToArray();
            messageIntegrityCheck[6] = 0;
            messageIntegrityCheck[7] = 0;
            messageIntegrityCheck[8] = 0;
            messageIntegrityCheck[9] = 0;

            var messageIntegrity = message[6..10];
            var calculatedIntegrity = ProtocolMessage.GetMessageHash(messageIntegrityCheck)[0..4];
            messageIntegrity.Should().BeEquivalentTo(calculatedIntegrity);

            // message body.
            ulong allCiphers = 0;
            foreach (var supportedCSBitValue in supportedCipherSuites.SupportedCipherSuites.Values)
                allCiphers += supportedCSBitValue;

            var supportedCiphers = ProtocolMessage.GetUlongValue(message, 10, 8);
            supportedCiphers.Should().Be(allCiphers);
        }

        [Fact]
        public void ProtocolMessage_CreateClientFinishMessage_Works_Fine()
        {
            SecureRandom rand = new SecureRandom();

            var serverInitMessage = rand.GenerateSeed(128);
            var message = ProtocolMessage.CreateClientFinishMessage(serverInitMessage);

            message.Should().NotBeNull();
            message.Length.Should().Be(10 + 128);
            message[0].Should().Be(1);
            message[1].Should().Be(4);
            ProtocolMessage.GetUintValue(message, 2, 4).Should().Be(128);

            var messageIntegrityCheck = message.ToArray();
            messageIntegrityCheck[6] = 0;
            messageIntegrityCheck[7] = 0;
            messageIntegrityCheck[8] = 0;
            messageIntegrityCheck[9] = 0;

            var messageIntegrity = message[6..10];
            var calculatedIntegrity = ProtocolMessage.GetMessageHash(messageIntegrityCheck)[0..4];
            messageIntegrity.Should().BeEquivalentTo(calculatedIntegrity);

            // message body.
            message[10..].Should().BeEquivalentTo(serverInitMessage);
        }

        [Fact]
        public void ProtocolMessage_CreateMessage_For_Data_Transfer_Works_Fine()
        {
            SecureRandom rand = new SecureRandom();

            var encryptedText = rand.GenerateSeed(128);
            var message = ProtocolMessage.CreateMessage(ProtocolMessage.PROTOCOL_VERSION, ProtocolMessage.DATA_TRANSFER, encryptedText, encryptedText.Length);

            message.Should().NotBeNull();
            message.Length.Should().Be(10 + 128);
            message[0].Should().Be(1);
            message[1].Should().Be(5);
            ProtocolMessage.GetUintValue(message, 2, 4).Should().Be(128);

            var messageIntegrityCheck = message.ToArray();
            messageIntegrityCheck[6] = 0;
            messageIntegrityCheck[7] = 0;
            messageIntegrityCheck[8] = 0;
            messageIntegrityCheck[9] = 0;

            var messageIntegrity = message[6..10];
            var calculatedIntegrity = ProtocolMessage.GetMessageHash(messageIntegrityCheck)[0..4];
            messageIntegrity.Should().BeEquivalentTo(calculatedIntegrity);

            // message body.
            message[10..].Should().BeEquivalentTo(encryptedText);
        }

        [Fact]
        public void ProtocolMessage_CreateCloseMessage_Works_Fine()
        {
            SecureRandom rand = new SecureRandom();

            var message = ProtocolMessage.CreateCloseMessage();

            message.Should().NotBeNull();
            message.Length.Should().Be(10);
            message[0].Should().Be(1);
            message[1].Should().Be(6);

            for (int i = 2; i < message.Length; i++)
                message[i].Should().Be(0);
        }
    }
}
