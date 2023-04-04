using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.Message;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// Main provider of the <see cref="ISecureTransportConnection"/>, allows create server/client + transfer data securelly.
    /// </summary>
    public sealed class QuantoCryptConnection : ISecureTransportConnection
    {
        public Guid Id => _rWrappedUnsecureConnection.Id;

        private ITransportConnection _rWrappedUnsecureConnection;
        private ISymmetricAlgorithm _rSymmetricAlgorithm = null;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="connection">Target <see cref="ITransportConnection"/> to wrap.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="connection"/> is null.</exception>
        public QuantoCryptConnection(ITransportConnection connection)
        {
            _rWrappedUnsecureConnection = connection ?? throw new ArgumentNullException(nameof(connection));
        }

        /// <summary>
        /// Create a secure client using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="cipherSuiteProvider">Target <see cref="ICipherSuiteProvider"/> to be supported.</param>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/> to be wrapped.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public static ISecureTransportConnection InitializeSecureClient(ICipherSuiteProvider cipherSuiteProvider, ITransportConnection baseConnection)
        {
            try
            {
                var connection = new QuantoCryptConnection(baseConnection);

                // add creation logic here.
                return connection;
            }
            catch { throw; }
        }

        /// <summary>
        /// Create a secure server using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="cipherSuiteProvider">Target <see cref="ICipherSuiteProvider"/> to be supported.</param>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/> to be wrapped.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public static ISecureTransportConnection InitializeSecureServer(ICipherSuiteProvider cipherSuiteProvider, ITransportConnection baseConnection)
        {
            try
            {
                var connection = new QuantoCryptConnection(baseConnection);

                // add creation logic here.
                return connection;
            }
            catch { throw; }
        }

        public byte[] Recieve()
        {
            try
            {
                var message = new ProtocolMessage(_rWrappedUnsecureConnection.Recieve());

                if (message.GetMessageType() != ProtocolMessage.DATA_TRANSFER)
                    throw new ArgumentException($"Invalid message code recieved! Expected to be a [DATA_TRANSFER] got [{message.GetMessageType()}]");

                var body = message.GetBody();

                return _rSymmetricAlgorithm.Decrypt(body);
            }
            catch { throw; }
        }

        public void Send(byte[] data)
        {
            var encryptedText = _rSymmetricAlgorithm.Encrypt(data);

            var protocolMessage = ProtocolMessage.CreateMessage(1, ProtocolMessage.DATA_TRANSFER, encryptedText);

            _rWrappedUnsecureConnection.Send(protocolMessage);
        }
    }
}
