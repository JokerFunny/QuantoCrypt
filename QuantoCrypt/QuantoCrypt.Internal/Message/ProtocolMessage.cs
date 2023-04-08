﻿using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using System.Buffers.Binary;

namespace QuantoCrypt.Internal.Message
{
    /// <summary>
    /// Handle the message, that is transfered through protocol with the proper headers and all other necesarry stuff.
    /// </summary>
    internal sealed class ProtocolMessage
    {
        /// <summary>
        /// Indicates the begin of the connection. Client should sent the publick key to the server.
        /// </summary>
        public static readonly byte CLIENT_INIT = 1;

        /// <summary>
        /// The second stage of the connection. Server should generate and sent: cipher text, signature over the CLIENT_INIT's message hash + attach it to the hash.
        /// </summary>
        public static readonly byte SERVER_INIT = 2;
        public static readonly byte UNSUPPORTED_CLIENT_PARAMS = 3;
        public static readonly byte UNSUPPORTED_SERVER_PARAMS = 4;
        public static readonly byte CLIENT_FINISH = 5;
        public static readonly byte DATA_TRANSFER = 6;

        private readonly byte[] _rMessage;

        /// <remarks>
        ///     Part used by protocol version (0), message type (1) and total message length (2-5).
        /// </remarks>
        private const int _rHeaderOffset = 6;
        /// <remarks>
        ///     Part used by message integrity (6-9).
        /// </remarks>
        private const int _rMessageIntegrityOffset = 4;
        /// <remarks>
        ///     Part used by header part and message integrity information.
        /// </remarks>
        private const int _rProtocolHeaderOffset = _rHeaderOffset + _rMessageIntegrityOffset;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="message">Target message to be properly handled.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="message"/> is null.</exception>
        public ProtocolMessage(byte[] message)
        {
            _rMessage = message ?? throw new ArgumentNullException(nameof(message));
        }

        /// <summary>
        /// Get the message that indicates the error.
        /// </summary>
        /// <param name="unsupportedParamsReciever">Target message type (<see cref="UNSUPPORTED_CLIENT_PARAMS"/> or <see cref="UNSUPPORTED_SERVER_PARAMS"/>).</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [UNSUPPORTED_*_PARAMS]
        /// 2 - 5 - [dataLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - end - [supportedCipherSuites]
        /// </remarks>
        /// <returns>
        ///     UNSUPPORTED_*_PARAMS message with properly generated header.
        /// </returns>
        public static byte[] CreateUnsupportedParamsMessage(byte unsupportedParamsReciever, ICipherSuiteProvider supportedCipherSuites)
        {
            List<byte> supportedCS = new();

            // go through all supported CipherSuites.
            foreach (var item in supportedCipherSuites.SupportedCipherSuites)
            {
                byte targetCipherSuiteCode = (byte)Enum.Parse(typeof(CipherSuite.CipherSuite), item.Name);
                supportedCS.Add(targetCipherSuiteCode);
            }

            return CreateMessage(1, unsupportedParamsReciever, supportedCS.ToArray());
        }

        /// <summary>
        /// Generates the <see cref="CLIENT_INIT"/> message with the proper format.
        /// </summary>
        /// <param name="supportedCipherSuites">Target client <see cref="ICipherSuiteProvider"/>.</param>
        /// <param name="preferedCipherSuite">Target <see cref="ICipherSuite"/> that is preffered by client.</param>
        /// <param name="publicKey">Clients' public key, generated by <see cref="IKEMAlgorithm"/>.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [CLIENT_INIT]
        /// 2 - 5 - [dataLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - [prefferedCipherSuite]
        /// 11 - [supportedCipherSuites.Length]
        /// 12 - supportedCipherSuites.Count - [supportedCipherSuites]
        /// 13+supportedCipherSuites.Count - end - [publicKey]
        /// </remarks>
        /// <returns>
        ///     CLIENT_INIT message with properly generated header.
        /// </returns>
        public static byte[] CreateClientInitMessage(ICipherSuiteProvider supportedCipherSuites, ICipherSuite preferedCipherSuite, byte[] publicKey)
        {
            List<byte> supportedCS = new()
            {
                // add preffered CipherSuites.
                (byte)Enum.Parse(typeof(CipherSuite.CipherSuite), preferedCipherSuite.Name),

                // add the lenght of the supportedCipherSuites.SupportedCipherSuites to distinct them from the message.
                (byte)supportedCipherSuites.SupportedCipherSuites.Count
            };

            // go through all supported CipherSuites.
            foreach (var item in supportedCipherSuites.SupportedCipherSuites)
            {
                byte targetCipherSuiteCode = (byte)Enum.Parse(typeof(CipherSuite.CipherSuite), item.Name);
                supportedCS.Add(targetCipherSuiteCode);
            }

            var message = new byte[supportedCS.Count + publicKey.Length];

            // set prefferedCipherSuite, supportedCipherSuites.Length and supportedCipherSuites.
            supportedCS.CopyTo(message);

            // set publicKey.
            int offset = supportedCS.Count;
            publicKey.CopyTo(message, offset);

            return CreateMessage(1, CLIENT_INIT, message);
        }

        /// <summary>
        /// Generates the <see cref="SERVER_INIT"/> message with the proper format.
        /// </summary>
        /// <param name="cipherText">Target cipher text.</param>
        /// <param name="encryptedSigWithKey">Target attached signature + signature public key, encrypted.</param>
        /// <param name="signaturePartLength">Length of the attached signature in the <paramref name="encryptedSigWithKey"/>.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [SERVER_INIT]
        /// 2 - 5 - [dataLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - 13 - [cipherText.Length]
        /// 14 - 14+cipherText.Length - [cipherText]
        /// 15+cipherText.Length - 18+cipherText.Length - [signaturePartLength]
        /// 19+cipherText.Length - end - [encryptedSigWithKey]
        /// </remarks>
        /// <returns>
        ///     CLIENT_INIT message with properly generated header.
        /// </returns>
        public static byte[] CreateServerInitMessage(byte[] cipherText, byte[] encryptedSigWithKey, int signaturePartLength)
        {
            var message = new byte[4 + cipherText.Length + 4 + encryptedSigWithKey.Length];

            // attach length of the cipherText.
            _CopyToByteArray(cipherText.Length, message, 0);

            // set cipherText.
            int offset = 4;
            cipherText.CopyTo(message, offset);

            // attach signaturePartLength.
            offset += cipherText.Length;
            _CopyToByteArray(signaturePartLength, message, offset);

            // set encryptedSigWithKey.
            offset += 4;
            encryptedSigWithKey.CopyTo(message, offset);

            return CreateMessage(1, SERVER_INIT, message);
        }

        /// <summary>
        /// Creates a new message by provided params.
        /// </summary>
        /// <param name="version">Target version.</param>
        /// <param name="type">Target type.</param>
        /// <param name="body">Target message body.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [messageType]
        /// 2 - 5 - [dataLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - end - [body]
        /// </remarks>
        /// <returns>
        ///     New message with properly generated header.
        /// </returns>
        public static byte[] CreateMessage(byte version, byte type, byte[] body)
        {
            try
            {
                int encryptedDataLength = _rProtocolHeaderOffset + body.Length;
                Span<byte> headerPart = stackalloc byte[_rHeaderOffset];

                // fill headers
                headerPart[0] = version;
                headerPart[1] = type;
                BinaryPrimitives.WriteInt32LittleEndian(headerPart.Slice(2, 4), encryptedDataLength);

                byte[] messageIntegrity = _GetHash(body);

                var message = new byte[encryptedDataLength];

                headerPart.CopyTo(message);
                messageIntegrity.CopyTo(message, _rHeaderOffset);
                body.CopyTo(message, _rProtocolHeaderOffset);

                return message;
            }
            catch { throw; }
        }

        /// <summary>
        /// Check the message integrity.
        /// </summary>
        /// <returns>
        ///     True if match, otherwise - false.
        /// </returns>
        public static bool CheckMessageIntegrity(byte[] message)
        {
            byte[] targetIntegrity = message[6..10];

            byte[] calculatedIntegrity = _GetHash(message[10..]);

            return calculatedIntegrity.SequenceEqual(targetIntegrity);
        }

        /// <summary>
        /// Check the message integrity.
        /// </summary>
        /// <returns>
        ///     True if match, otherwise - false.
        /// </returns>
        public bool CheckMessageIntegrity()
        {
            byte[] targetIntegrity = _rMessage[6..10];

            byte[] calculatedIntegrity = _GetHash(_rMessage[10..]);

            return calculatedIntegrity.SequenceEqual(targetIntegrity);
        }

        /// <summary>
        /// Checks if the message didn't changed.
        /// </summary>
        /// <returns>
        ///     True if body integrity is valid, otherwise - false.
        /// </returns>
        public bool IsValid()
        {
            // MAC offset is 1 (version) + 1 (type) + 4 (lenght) = 6 bytes, so we can just check the integrity as it is.
            return _rMessage[6] == 127 && _rMessage[7] == 63 && _rMessage[8] == 31 && _rMessage[9] == 15;
        }
        /// <summary>
        /// Gets the message type.
        /// </summary>
        /// <returns>
        ///     Return message type used to generate current message.
        /// </returns>
        public int GetMessageType()
            => _rMessage[1];

        /// <summary>
        /// Get message body.
        /// </summary>
        /// <remarks>
        /// MESSAGE
        /// 0 - 9 - [header]
        /// 10 - end - [body]
        /// </remarks>
        /// <returns>
        ///     Message body, starting from the 10s' bit.
        /// </returns>
        public byte[] GetBody()
        {
            int targetLength = _rMessage.Length - _rHeaderOffset;
            byte[] messageBody = new byte[targetLength];

            Array.Copy(_rMessage, _rHeaderOffset, messageBody, 0, targetLength);

            return messageBody;
        }

        private static byte[] _GetHash(byte[] body)
        {
            // No body integrity for version 0.1 :(
            return new byte[] { 127, 63, 31, 15 };
        }

        private static void _CopyToByteArray(int source, byte[] destination, int offset)
        {
            if (destination == null)
                throw new ArgumentException("Destination array cannot be null");

            // check if there is enough space for all the 4 bytes we will copy
            if (destination.Length < offset + 4)
                throw new ArgumentException("Not enough room in the destination array");

            destination[offset] = (byte)(source >> 24); // fourth byte
            destination[offset + 1] = (byte)(source >> 16); // third byte
            destination[offset + 2] = (byte)(source >> 8); // second byte
            destination[offset + 3] = (byte)source; // last byte is already in proper position
        }

        private static void _CopyToByteArrayShort(int source, byte[] destination, int offset)
        {
            if (destination == null)
                throw new ArgumentException("Destination array cannot be null");

            // check if there is enough space for all the 4 bytes we will copy
            if (destination.Length < offset + 4)
                throw new ArgumentException("Not enough room in the destination array");

            destination[offset] = (byte)(source >> 8); // second byte
            destination[offset + 1] = (byte)source; // last byte is already in proper position
        }
    }
}
