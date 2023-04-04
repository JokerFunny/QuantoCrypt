using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Internal.Connection;

namespace QuantoCrypt.Protocol
{
    /// <summary>
    /// Factory to create new connections (as new instances of the client + server) that use target <see cref="ICipherSuiteProvider"/>.
    /// </summary>
    public class QuantoCryptConnectionFactory
    {
        public ICipherSuiteProvider CipherSuiteProvider { get; private set; }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="supportedSuites">Target <see cref="ICipherSuiteProvider"/>.</param>
        public QuantoCryptConnectionFactory(ICipherSuiteProvider supportedSuites)
        {
            CipherSuiteProvider = supportedSuites;
        }

        /// <summary>
        /// Create a secure client using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/>.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public ISecureTransportConnection CreateSecureClientConnection(ITransportConnection baseConnection)
            => QuantoCryptConnection.InitializeSecureClient(CipherSuiteProvider, baseConnection);

        /// <summary>
        /// Create a secure server using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/>.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public ISecureTransportConnection CreateSecureServerConnection(ITransportConnection baseConnection)
            => QuantoCryptConnection.InitializeSecureServer(CipherSuiteProvider, baseConnection);
    }
}
