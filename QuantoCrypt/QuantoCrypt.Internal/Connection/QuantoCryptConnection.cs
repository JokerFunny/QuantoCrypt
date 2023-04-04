using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Infrastructure.Symmetric;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class QuantoCryptConnection : ISecureTransportConnection
    {
        public Guid Id => _rWrappedUnsecureConnection.Id;

        private ITransportConnection _rWrappedUnsecureConnection;
        private ISymmetricAlgorithm _rSymmetricAlgorithm;

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
            // add creation logic here.
            return null;
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
            // add creation logic here.
            return null;
        }

        public byte[] Recieve()
        {
            // add recieve logic.
            throw new NotImplementedException();
        }

        public void Send(byte[] data)
        {
            // TODO: rework ISymmetricAlgorithm to use byte[]
            string encryptedText = _rSymmetricAlgorithm.Encrypt(Convert.ToBase64String(data));

            // add send logic here.
        }
    }
}
