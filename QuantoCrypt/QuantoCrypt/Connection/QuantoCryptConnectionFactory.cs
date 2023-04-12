using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Connection;
using static QuantoCrypt.Internal.Connection.QuantoCryptConnection;

namespace QuantoCrypt.Connection
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
        /// <param name="supportedConnectionMode">Target <see cref="ConnectionMode"/>, default value - <see cref="ConnectionMode.Default"/>.</param>
        /// <remarks>
        ///     Use the first cipher from <see cref="CipherSuiteProvider"/>.
        /// </remarks>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public ISecureTransportConnection CreateSecureClientConnection(ITransportConnection baseConnection, ConnectionMode supportedConnectionMode = ConnectionMode.Default)
            => InitializeSecureClient(CipherSuiteProvider, baseConnection, supportedConnectionMode);

        /// <summary>
        /// Create a secure client using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/>.</param>
        /// <param name="preferredCipher">Preffered <see cref="ICipherSuite"/> to be used.</param>
        /// <param name="supportedConnectionMode">Target <see cref="ConnectionMode"/>, default value - <see cref="ConnectionMode.Default"/>.</param>
        /// <remarks>
        ///     Use the <paramref name="preferredCipher"/> if server supports it or the first cipher from <see cref="CipherSuiteProvider"/>.
        /// </remarks>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public ISecureTransportConnection CreateSecureClientConnection(ITransportConnection baseConnection, ICipherSuite preferredCipher, ConnectionMode supportedConnectionMode = ConnectionMode.Default)
            => InitializeSecureClient(CipherSuiteProvider, preferredCipher, baseConnection, supportedConnectionMode);

        /// <summary>
        /// Create a secure server using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/>.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public ISecureTransportConnection CreateSecureServerConnection(ITransportConnection baseConnection)
            => InitializeSecureServer(CipherSuiteProvider, baseConnection);
    }
}
