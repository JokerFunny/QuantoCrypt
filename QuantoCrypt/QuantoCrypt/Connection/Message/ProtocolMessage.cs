﻿using QuantoCrypt.Common.Utilities;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

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

        /// <summary>
        /// In case if client send unsupported preferred CipherSuite - reply with the servers' supported CipherSuites.
        /// </summary>
        public static readonly byte UNSUPPORTED_CLIENT_PARAMS = 3;

        /// <summary>
        /// Indicates the message that requires additional checks on server side.
        /// </summary>
        public static readonly byte CLIENT_FINISH = 4;

        /// <summary>
        /// Indicates the encrypthed by symmetric algorithm message used after handshake.
        /// </summary>
        public static readonly byte DATA_TRANSFER = 5;
        
        /// <summary>
        /// Indicates or error or the end of the connection.
        /// </summary>
        public static readonly byte CLOSE = 6;

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
        /// The amount of the bytes that is allocated for the supported cipher suites bit-mask.
        /// </summary>
        public const int SUPPORTED_CIPHER_SUITES_OFFSET = 8;

        /// <summary>
        /// Current version of the protocol.
        /// </summary>
        public const int PROTOCOL_VERSION = 1;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="message">Target message to be properly handled.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="message"/> is null.</exception>
        internal ProtocolMessage(byte[] message)
        {
            _rMessage = message ?? throw new ArgumentNullException(nameof(message));
        }

        /// <summary>
        /// Get the message that indicates the error.
        /// </summary>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [UNSUPPORTED_CLIENT_PARAMS]
        /// 2 - 5 - [bodyLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - 17 - [supportedCipherSuites]
        /// </remarks>
        /// <returns>
        ///     UNSUPPORTED_CLIENT_PARAMS message with properly generated header.
        /// </returns>
        internal static byte[] CreateUnsupportedClientParamsMessage(ICipherSuiteProvider supportedCipherSuites)
        {
            // go through all supported CipherSuites to create a bit-mask of all supported CipherSuites.
            ulong allCiphers = 0;
            foreach (var supportedCSBitValue in supportedCipherSuites.SupportedCipherSuites.Values)
                allCiphers += supportedCSBitValue;

            byte[] allCiphersSuites = new byte[SUPPORTED_CIPHER_SUITES_OFFSET];

            _CopyToByteArrayUlong(allCiphers, allCiphersSuites, 0);

            return CreateMessage(1, UNSUPPORTED_CLIENT_PARAMS, allCiphersSuites);
        }

        /// <summary>
        /// Generates the <see cref="CLIENT_INIT"/> message with the proper format.
        /// </summary>
        /// <param name="supportedCipherSuites">Target client <see cref="ICipherSuiteProvider"/>.</param>
        /// <param name="preferedCipherSuite">Target <see cref="ICipherSuite"/> that is preferred by client.</param>
        /// <param name="connectionMode">Target connection mode to be used.</param>
        /// <param name="publicKey">Clients' public key, generated by <see cref="IKEMAlgorithm"/>.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [CLIENT_INIT]
        /// 2 - 5 - [bodyLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - [prefferedCipherSuite]
        /// 11 - [connectionMode]
        /// 12 - end - [publicKey]
        /// </remarks>
        /// <returns>
        ///     CLIENT_INIT message with properly generated header.
        /// </returns>
        internal static byte[] CreateClientInitMessage(ICipherSuiteProvider supportedCipherSuites, ICipherSuite preferedCipherSuite, byte connectionMode, byte[] publicKey)
        {
            // add preffered CipherSuites.
            byte prefferedCS = (byte)supportedCipherSuites.SupportedCipherSuites.Keys.ToList().IndexOf(x => x.Name == preferedCipherSuite.Name);

            var message = new byte[2 + publicKey.Length];

            // set prefferedCipherSuite.
            message[0] = prefferedCS;

            // set connection mode.
            message[1] = connectionMode;

            // set publicKey.
            publicKey.CopyTo(message, 2);

            return CreateMessage(1, CLIENT_INIT, message);
        }

        /// <summary>
        /// Generates the <see cref="SERVER_INIT"/> message with the proper format.
        /// </summary>
        /// <param name="cipherText">Target cipher text.</param>
        /// <param name="encryptedSignatureWithKey">Target signature + signature public key, encrypted.</param>
        /// <param name="signaturePartLength">Length of the decrypted signature in the <paramref name="encryptedSignatureWithKey"/>.</param>
        /// <param name="signaturePublicKeyLength">Length of the decrypted signature public key in the <paramref name="encryptedSignatureWithKey"/>.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [SERVER_INIT]
        /// 2 - 5 - [bodyLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - 13 - [cipherText.Length]
        /// 14 - 14+cipherText.Length - [cipherText]
        /// 15+cipherText.Length - 18+cipherText.Length - [signaturePartLength]
        /// 19+cipherText.Length - 22+cipherText.Length - [signaturePublicKeyLength]
        /// 23+cipherText.Length - end - [encryptedSignatureWithKey]
        /// </remarks>
        /// <returns>
        ///     CLIENT_INIT message with properly generated header, body with signature part.
        /// </returns>
        internal static byte[] CreateServerInitMessage(byte[] cipherText, byte[] encryptedSignatureWithKey, int signaturePartLength, int signaturePublicKeyLength)
        {
            var message = new byte[4 + cipherText.Length + 4 + 4 + encryptedSignatureWithKey.Length];

            // attach length of the cipherText.
            _CopyToByteArray(cipherText.Length, message, 0);

            // set cipherText.
            int offset = 4;
            cipherText.CopyTo(message, offset);

            // attach signaturePartLength.
            offset += cipherText.Length;
            _CopyToByteArray(signaturePartLength, message, offset);

            // attach signaturePublicKeyLength.
            offset += 4;
            _CopyToByteArray(signaturePublicKeyLength, message, offset);

            // set encryptedSigWithKey.
            offset += 4;
            encryptedSignatureWithKey.CopyTo(message, offset);

            return CreateMessage(1, SERVER_INIT, message);
        }

        /// <summary>
        /// Generates the <see cref="SERVER_INIT"/> message with the proper format.
        /// </summary>
        /// <param name="cipherText">Target cipher text.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [SERVER_INIT]
        /// 2 - 5 - [bodyLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - 13 - [cipherText.Length]
        /// 14 - end - [cipherText]
        /// </remarks>
        /// <returns>
        ///     CLIENT_INIT message with properly generated header, body without signature part.
        /// </returns>
        internal static byte[] CreateServerInitMessage(byte[] cipherText)
        {
            var message = new byte[4 + cipherText.Length];

            // attach length of the cipherText.
            _CopyToByteArray(cipherText.Length, message, 0);

            // set cipherText.
            int offset = 4;
            cipherText.CopyTo(message, offset);

            return CreateMessage(1, SERVER_INIT, message);
        }

        /// <summary>
        /// Generates the <see cref="CLIENT_FINISH"/> message with the proper format.
        /// </summary>
        /// <param name="encodedServerInitMessage">Hash of the <see cref="SERVER_INIT"/> message, encoded by symmetric algorithm.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [SERVER_INIT]
        /// 2 - 5 - [bodyLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - end - [encodedServerInitMessage]
        /// </remarks>
        /// <returns>
        ///     CLIENT_FINISH message with properly generated header.
        /// </returns>
        internal static byte[] CreateClientFinishMessage(byte[] encodedServerInitMessage)
            => CreateMessage(1, CLIENT_FINISH, encodedServerInitMessage);

        /// <summary>
        /// Generates the <see cref="CLOSE"/> message with the proper format.
        /// </summary>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [CLOSE]
        /// 2 - 5 - [bodyLength] - [0 0 0 0]
        /// 6 - 9 - [messageIntegrity] - [0 0 0 0]
        /// </remarks>
        /// <returns>
        ///     CLOSE message.
        /// </returns>
        internal static byte[] CreateCloseMessage()
        {
            Span<byte> headerPart = stackalloc byte[_rProtocolHeaderOffset];

            headerPart[0] = PROTOCOL_VERSION;
            headerPart[1] = CLOSE;

            return headerPart.ToArray();
        }

        /// <summary>
        /// Creates a new message by provided params.
        /// </summary>
        /// <param name="version">Target version.</param>
        /// <param name="type">Target type.</param>
        /// <param name="body">Target message body.</param>
        /// <param name="bodyLength">Target lenght of decrypted body.</param>
        /// <remarks>
        /// MESSAGE
        /// 0 - [version]
        /// 1 - [messageType]
        /// 2 - 5 - [bodyLength]
        /// 6 - 9 - [messageIntegrity]
        /// 10 - end - [body]
        /// </remarks>
        /// <returns>
        ///     New message with properly generated header.
        /// </returns>
        internal static byte[] CreateMessage(byte version, byte type, byte[] body, int bodyLength = -1)
        {
            int totalDataLength = _rProtocolHeaderOffset + body.Length;
            Span<byte> headerPart = stackalloc byte[_rHeaderOffset];

            // fill headers
            headerPart[0] = version;
            headerPart[1] = type;
            _CopyToByteArray(bodyLength < 0 ? body.Length : bodyLength, headerPart, 2);

            var message = new byte[totalDataLength];

            headerPart.CopyTo(message);
            body.CopyTo(message, _rProtocolHeaderOffset);

            byte[] messageIntegrity = _GetHash(message);
            messageIntegrity.CopyTo(message, _rHeaderOffset);

            return message;
        }

        /// <summary>
        /// Check the message integrity.
        /// </summary>
        /// <returns>
        ///     True if match, otherwise - false.
        /// </returns>
        internal static bool CheckMessageIntegrity(byte[] message)
        {
            var targetIntegrity = message[6..10];

            byte[] calculatedIntegrity = _GetHash(ArrayUtilities.Combine(message[0..6], new byte[4], message[10..]));

            return calculatedIntegrity.SequenceEqual(targetIntegrity);
        }

        /// <summary>
        /// Calculate the hash of the <paramref name="message"/>.
        /// </summary>
        /// <param name="message">Taget input message.</param>
        /// <returns>
        ///     <see cref="SHA384.HashData(byte[])"/> over <paramref name="message"/>.
        /// </returns>
        internal static byte[] GetMessageHash(byte[] message)
            => SHA384.HashData(message);

        /// <summary>
        /// Check the message integrity.
        /// </summary>
        /// <returns>
        ///     True if match, otherwise - false.
        /// </returns>
        internal bool CheckMessageIntegrity()
            => CheckMessageIntegrity(_rMessage);

        /// <summary>
        /// Gets the message type.
        /// </summary>
        /// <returns>
        ///     Return message type used to generate current message.
        /// </returns>
        internal int GetMessageType()
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
        internal byte[] GetBody()
            => _rMessage[10..];

        /// <summary>
        /// Get the length of the decrypted body length.
        /// </summary>
        /// <returns>
        ///     Length of the decrypted body length.
        /// </returns>
        internal int GetBodyLength()
            => GetIntValue(_rMessage, 2, 4);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong GetUlongValue(byte[] target, int start, int length)
        {
            var ulongPart = target.AsSpan().Slice(start, length);

            ulong acc = 0;

            foreach (var b in ulongPart)
                acc = (acc * 0x100) + b;

            return acc;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint GetUintValue(byte[] target, int start, int length)
        {
            var uintPart = target.AsSpan().Slice(start, length);

            uint acc = 0;

            foreach (var b in uintPart)
                acc = (acc * 0x100) + b;

            return acc;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static int GetIntValue(byte[] target, int start, int length)
        {
            var intPart = target.AsSpan().Slice(start, length);

            int acc = 0;

            foreach (var b in intPart)
                acc = (acc * 0x100) + b;

            return acc;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] _GetHash(byte[] body)
            => SHA384.HashData(body)[0..4];

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _CopyToByteArrayUlong(ulong source, byte[] destination, int offset)
        {
            if (destination == null)
                throw new ArgumentException("Destination array cannot be null");

            // check if there is enough space for all the 4 bytes we will copy
            if (destination.Length < offset + 4)
                throw new ArgumentException("Not enough room in the destination array");

            destination[offset] = (byte)(source >> 56); // 8th byte
            destination[offset + 1] = (byte)(source >> 48); // 7th byte
            destination[offset + 2] = (byte)(source >> 40); // 6th byte
            destination[offset + 3] = (byte)(source >> 32); // 5th byte
            destination[offset + 4] = (byte)(source >> 24); // four byte
            destination[offset + 5] = (byte)(source >> 16); // third byte
            destination[offset + 6] = (byte)(source >> 8); // second byte
            destination[offset + 7] = (byte)source; // last byte is already in proper position
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _CopyToByteArray(int source, Span<byte> destination, int offset)
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
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
    }
}
