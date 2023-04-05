using System.Buffers.Binary;

namespace QuantoCrypt.Internal.Message
{
    /// <summary>
    /// Handle the message, that is transfered through protocol with the proper headers and all other necesarry stuff.
    /// </summary>
    internal sealed class ProtocolMessage
    {
        public static readonly byte CLIENT_INIT = 1;
        public static readonly byte SERVER_INIT = 2;
        public static readonly byte UNSUPPORTED_CLIENT_PARAMS = 3;
        public static readonly byte UNSUPPORTED_SERVER_PARAMS = 4;
        public static readonly byte DATA_TRANSFER = 5;

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
        /// Creates a new message by provided params.
        /// </summary>
        /// <param name="version">Target version.</param>
        /// <param name="type">Target type.</param>
        /// <param name="body">Target message body.</param>
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
                BinaryPrimitives.WriteInt32LittleEndian(headerPart.Slice(2, 6), encryptedDataLength);

                byte[] messageIntegrity = _GetHash(body);

                var message = new byte[encryptedDataLength];

                headerPart.CopyTo(message);
                messageIntegrity.CopyTo(message, _rHeaderOffset);
                body.CopyTo(message, _rProtocolHeaderOffset);

                return message;
            }
            catch { throw; }
        }

        private static byte[] _GetHash(byte[] body)
        {
            // No body integrity for version 0.1 :(
            return new byte[] { 127, 63, 31, 15 };
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

        public byte[] GetBody()
        {
            int targetLength = _rMessage.Length - _rHeaderOffset;
            byte[] messageBody = new byte[targetLength];

            Array.Copy(_rMessage, _rHeaderOffset, messageBody, 0, targetLength);

            return messageBody;
        }
    }
}
