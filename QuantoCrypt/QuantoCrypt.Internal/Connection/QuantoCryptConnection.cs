using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.Message;
using QuantoCrypt.Internal.Utilities;
using System.Security.Cryptography;
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
        internal ISymmetricAlgorithm UsedSymmetricAlgorithm { get; private set; }

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
                byte[] publicKey = keys.Public.GetEncoded();

                byte[] clientInitMessage = ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, publicKey);

                int bytesSent = connection.prWrappedUnsecureConnection.Send(clientInitMessage);



                // CLIENT_FINISH - get cipherText to generate sessionSecret + encryptedSigWithKey to validate server by clientInitMessage.
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
                else if (serverInitMessage[1] == ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS)
                {
                    // fallback for the client.
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
            ICipherSuite __GetCipherSuiteToUse(byte[] clientInitMessage)
            {
                ICipherSuite cipherSuiteToUse = null;

                // get preffered client CipherSuite.
                byte prefferedCipherSuite = clientInitMessage[10];

                // check if the server support preffered client CipherSuite.
                foreach (var cipherSuite in cipherSuiteProvider.SupportedCipherSuites)
                {
                    byte supportedCipherSuite = (byte)Enum.Parse(typeof(CipherSuite.CipherSuite), cipherSuite.Name);
                    if (supportedCipherSuite == prefferedCipherSuite)
                    {
                        cipherSuiteToUse = cipherSuite;

                        break;
                    }
                }

                return cipherSuiteToUse;
            }

            byte[] __GetServerInitMessage(QuantoCryptConnection connection, byte[] clientInitMessage, ICipherSuite cipherSuiteToUse)
            {
                int supportedCipherSuitesOffset = clientInitMessage[11];
                int publicKeyOffset = 11 + supportedCipherSuitesOffset + 1;

                // get public key from client.
                byte[] publicKey = clientInitMessage[publicKeyOffset..];

                // create a proper KEM algorithm.
                IKEMAlgorithm kemAlgorithm = cipherSuiteToUse.GetKEMAlgorithm();

                // create encapsulated data (session secret + ciphertext for client).
                ISecretWithEncapsulation secretWithEncapsulatedData = kemAlgorithm.Encaps(publicKey);

                byte[] sessionSecret = secretWithEncapsulatedData.GetSecret();
                byte[] generatedCipherText = secretWithEncapsulatedData.GetEncapsulation();

                // get Signature algorithm.
                ISignatureAlgorithm signatureAlgorithmForSigning = cipherSuiteToUse.GetSignatureAlgorithm(true);

                // create keys and sign clinets' message.
                AsymmetricKeyPair signatureKeys = signatureAlgorithmForSigning.KeyGen();

                // generate hash over clientInitMessage to be signed.
                byte[] messageToBeSigned = SHA384.HashData(clientInitMessage);
                byte[] signature = signatureAlgorithmForSigning.Sign(messageToBeSigned);

                // create a proper ISymmetricAlgorithm using genereted session secret.
                connection.UsedSymmetricAlgorithm = cipherSuiteToUse.GetSymmetricAlgorithm(sessionSecret);

                // prepare params for client. We need to sent cipher text + [signature public key + attachedSig] (encrypted).
                byte[] encryptedSigWithKey = connection.UsedSymmetricAlgorithm.Encrypt(ArrayUtilities.Combine(signature, messageToBeSigned, signatureKeys.Public.GetEncoded()));

                return ProtocolMessage.CreateServerInitMessage(generatedCipherText, encryptedSigWithKey, signature.Length + messageToBeSigned.Length);
            }

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
                    // get preffered client CipherSuite.
                    ICipherSuite cipherSuiteToUse = __GetCipherSuiteToUse(clientInitMessage);

                    if (cipherSuiteToUse == null)
                    {
                        // return failed message to client.
                        serverInitMessage = ProtocolMessage.CreateUnsupportedParamsMessage(ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS, cipherSuiteProvider);
                    }
                    else
                        serverInitMessage = __GetServerInitMessage(connection, clientInitMessage, cipherSuiteToUse);
                }
                else
                    throw new ArgumentException($"Client sent invalid messageType. Expected [{ProtocolMessage.CLIENT_INIT}], found [{clientInitMessage[1]}].");

                /*
                // fallback for unsopperted client cipher suite.
                if (serverInitMessage[1] == ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS)
                {
                    connection.prWrappedUnsecureConnection.Send(serverInitMessage);

                    clientInitMessage = connection.prWrappedUnsecureConnection.Receive();

                    // check message integrity.
                    if (!ProtocolMessage.CheckMessageIntegrity(clientInitMessage))
                        throw new ArgumentException("Message integrity check fails.");

                    // get preffered client CipherSuite.
                    ICipherSuite cipherSuiteToUse = __GetCipherSuiteToUse(clientInitMessage);

                    if (cipherSuiteToUse == null)
                    {
                        string supportedCipherSuites = cipherSuiteProvider.SupportedCipherSuites
                            .Select(x => x.Name)
                            .Aggregate("Supported CipherSuites:" (first, next) => $"{first}{Enviroment.NewLine}{next}");

                        throw new ArgumentException($"Client sent unsupported CipherSuite in a second time. {supportedCipherSuites}.");
                    }
                    else
                        clientInitMessage = __GetServerInitMessage(connection, clientInitMessage, cipherSuiteToUse);
                }
                */

                connection.prWrappedUnsecureConnection.Send(serverInitMessage);

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

        public int Send(byte[] data)
        {
            var encryptedText = UsedSymmetricAlgorithm.Encrypt(data);

            var protocolMessage = ProtocolMessage.CreateMessage(1, ProtocolMessage.DATA_TRANSFER, encryptedText);

            return prWrappedUnsecureConnection.Send(protocolMessage);
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

                return UsedSymmetricAlgorithm.Decrypt(body);
            }
            catch { throw; }
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                prWrappedUnsecureConnection?.Dispose();

                UsedSymmetricAlgorithm?.Dispose();

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
