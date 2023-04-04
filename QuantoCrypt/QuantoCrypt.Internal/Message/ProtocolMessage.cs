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
        private const int _rHeaderOffset = 10;

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
                var headerPart = new byte[6];
                headerPart[0] = version;
                headerPart[1] = type;
                _CopyToByteArray(body.Length + _rHeaderOffset, headerPart, 2);
                byte[] messageIntegrity = _GetHash(body);

                var message = new byte[_rHeaderOffset + body.Length];
                headerPart.CopyTo(message, 0);
                messageIntegrity.CopyTo(message, headerPart.Length);
                body.CopyTo(message, _rHeaderOffset);

                return message;
            }
            catch (Exception ex)
            {
                throw;
            }
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
