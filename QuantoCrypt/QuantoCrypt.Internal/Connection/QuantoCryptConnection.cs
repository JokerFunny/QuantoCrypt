using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.Message;
using System.Text;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// Main provider of the <see cref="ISecureTransportConnection"/>, allows create server/client + transfer data securelly.
    /// </summary>
    public sealed class QuantoCryptConnection : ISecureTransportConnection
    {
        public Guid Id => prWrappedUnsecureConnection.Id;

        /// <summary>
        /// <see cref="ISymmetricAlgorithm"/> that would be used durin data transfer.
        /// </summary>
        internal ISymmetricAlgorithm SymmetricAlgorithm;

        internal readonly ITransportConnection prWrappedUnsecureConnection;

        private bool _isDisposed;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="connection">Target <see cref="ITransportConnection"/> to wrap.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="connection"/> is null.</exception>
        public QuantoCryptConnection(ITransportConnection connection)
        {
            prWrappedUnsecureConnection = connection ?? throw new ArgumentNullException(nameof(connection));
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
                ISecureTransportConnection client = InitializeSecureClient(cipherSuiteProvider, cipherSuiteProvider.SupportedCipherSuites.First(), baseConnection);

                return client;
            }
            catch { throw; }
        }

        /// <summary>
        /// Create a secure client using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="cipherSuiteProvider">Target <see cref="ICipherSuiteProvider"/> to be supported.</param>
        /// <param name="preferredCipher">Preffered <see cref="ICipherSuite"/> to be used.</param>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/> to be wrapped.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public static ISecureTransportConnection InitializeSecureClient(ICipherSuiteProvider cipherSuiteProvider, ICipherSuite preferredCipher, ITransportConnection baseConnection)
        {
            try
            {
                var connection = new QuantoCryptConnection(baseConnection);

                // CLIENT_INIT - generate key pair + random message to be signed.
                IKEMAlgorithm kemAlgorithm = preferredCipher.GetKEMAlgorithm();

                AsymmetricKeyPair keys = kemAlgorithm.KeyGen();

                byte[] messageToBeSigned = new SecureRandom().GenerateSeed(71);
                byte[] publicKey = keys.Public.GetEncoded();

                byte[] clientInitMessage = ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, messageToBeSigned, publicKey);

                int bytesSent = connection.prWrappedUnsecureConnection.Send(clientInitMessage);



                // CLIENT_FINISH.
                var serverInitMessage = connection.prWrappedUnsecureConnection.Receive();

                // check message integrity.
                if (!ProtocolMessage.CheckMessageIntegrity(serverInitMessage))
                    throw new ArgumentException("Message integrity check fails.");

                // check that the server sent a proper message.
                if (serverInitMessage[1] == ProtocolMessage.SERVER_INIT)
                {
                    // get session key here, init 
                    Array.Empty<byte>();
                }
                else
                    throw new ArgumentException($"Server sent invalid messageType. Expected [{ProtocolMessage.SERVER_INIT}], found [{serverInitMessage[1]}].");

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

                // SERVER_INIT.
                var clientInitMessage = connection.prWrappedUnsecureConnection.Receive();

                // check message integrity.
                if (!ProtocolMessage.CheckMessageIntegrity(clientInitMessage))
                    throw new ArgumentException("Message integrity check fails.");

                byte[] serverInitMessage;

                // check that the ckient sent a proper message.
                if (clientInitMessage[1] == ProtocolMessage.CLIENT_INIT)
                {
                    byte prefferedCipherSuite = clientInitMessage[10];

                    ICipherSuite cipherSuiteToUse = null;
                    foreach (var cipherSuite in cipherSuiteProvider.SupportedCipherSuites)
                    {
                        byte supportedCipherSuite = (byte)Enum.Parse(typeof(CipherSuite.CipherSuite), cipherSuite.Name);
                        if (supportedCipherSuite == prefferedCipherSuite)
                        {
                            cipherSuiteToUse = cipherSuite;

                            break;
                        }
                    }

                    if (cipherSuiteToUse == null)
                        serverInitMessage = ProtocolMessage.CreateUnsupportedParamsMessage(ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS);
                    else
                    {


                        serverInitMessage = Array.Empty<byte>();
                    }
                }
                else
                    throw new ArgumentException($"Client sent invalid messageType. Expected [{ProtocolMessage.CLIENT_INIT}], found [{clientInitMessage[1]}].");

                int bytesSent = connection.prWrappedUnsecureConnection.Send(serverInitMessage);

                // add creation logic here.
                return connection;
            }
            catch { throw; }
        }

        public static ISecureTransportConnection InitializeSecureClientDemo(ICipherSuiteProvider cipherSuiteProvider, ICipherSuite preferredCipher, ITransportConnection baseConnection)
        {
            try
            {
                var connection = new QuantoCryptConnection(baseConnection);

                // Encode the data string into a byte array.
                byte[] msg = Encoding.ASCII.GetBytes("This is a test<EOF>");

                // Send the data through the socket.
                int bytesSent = connection.prWrappedUnsecureConnection.Send(msg);

                // Receive the response from the remote device.
                var bytes = connection.prWrappedUnsecureConnection.Receive();
                Console.WriteLine("Echoed test = {0}", Encoding.ASCII.GetString(bytes));

                // add creation logic here.
                return connection;
            }
            catch { throw; }
        }

        public static ISecureTransportConnection InitializeSecureServerDemo(ICipherSuiteProvider cipherSuiteProvider, ITransportConnection baseConnection)
        {
            try
            {
                var connection = new QuantoCryptConnection(baseConnection);

                // Incoming data from the client.
                string data = string.Empty;

                while (true)
                {
                    var bytes = connection.prWrappedUnsecureConnection.Receive();
                    data += Encoding.ASCII.GetString(bytes);
                    if (data.IndexOf("<EOF>") > -1)
                    {
                        break;
                    }
                }

                Console.WriteLine("Text received : {0}", data);

                byte[] msg = Encoding.ASCII.GetBytes(data);
                connection.prWrappedUnsecureConnection.Send(msg);

                // add creation logic here.
                return connection;
            }
            catch { throw; }
        }

        public byte[] Receive()
        {
            try
            {
                var message = new ProtocolMessage(prWrappedUnsecureConnection.Receive());

                if (!message.CheckMessageIntegrity())
                    throw new ArgumentException("Message integrity check fails.");

                if (message.GetMessageType() != ProtocolMessage.DATA_TRANSFER)
                    throw new ArgumentException($"Invalid message code recieved! Expected to be a [DATA_TRANSFER], got [{message.GetMessageType()}].");

                var body = message.GetBody();

                return SymmetricAlgorithm.Decrypt(body);
            }
            catch { throw; }
        }

        public int Send(byte[] data)
        {
            var encryptedText = SymmetricAlgorithm.Encrypt(data);

            var protocolMessage = ProtocolMessage.CreateMessage(1, ProtocolMessage.DATA_TRANSFER, encryptedText);

            return prWrappedUnsecureConnection.Send(protocolMessage);
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                prWrappedUnsecureConnection?.Dispose();

                SymmetricAlgorithm?.Dispose();

                _isDisposed = true;
            }
        }

        public bool Close()
        {
            bool result = false;

            if (!_isDisposed)
            {
                result = prWrappedUnsecureConnection.Close();
                Dispose();
            }

            return result;
        }
    }
}
