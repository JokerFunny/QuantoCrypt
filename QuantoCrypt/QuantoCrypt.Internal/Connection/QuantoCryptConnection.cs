using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.CipherSuite;
using QuantoCrypt.Internal.Message;
using QuantoCrypt.Internal.Utilities;
using System.Security.Cryptography.X509Certificates;
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
                ISecureTransportConnection client = InitializeSecureClient(cipherSuiteProvider, cipherSuiteProvider.SupportedCipherSuites.Keys.First(), baseConnection);

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
            byte[] __GetClientInitMessage(ICipherSuite preferredCipher, out IKEMAlgorithm kemAlgorithm)
            {
                // CLIENT_INIT - generate key pair + random message to be signed.
                kemAlgorithm = preferredCipher.GetKEMAlgorithm();

                AsymmetricKeyPair keys = kemAlgorithm.KeyGen();
                byte[] publicKey = keys.Public.GetEncoded();

                return ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, publicKey);
            };

            bool __ValidateServerInitMessage(QuantoCryptConnection connection, IKEMAlgorithm kemAlgorithm, byte[] serverInitMessage, byte[] clientInitMessageHash)
            {
                int cipherTextLength = ProtocolMessage.GetIntValue(serverInitMessage, 10, 4);

                // get session key via cipher text from server.
                byte[] cipherText = new byte[cipherTextLength];
                Array.Copy(serverInitMessage, 14, cipherText, 0, cipherTextLength);

                byte[] sessionKey = kemAlgorithm.Decaps(cipherText);

                // create a proper ISymmetricAlgorithm using genereted session secret.
                connection.UsedSymmetricAlgorithm = preferredCipher.GetSymmetricAlgorithm(sessionKey);

                // get target lengths of the signature + public key.
                int offset = 14 + cipherTextLength;
                int signaturePartLength = ProtocolMessage.GetIntValue(serverInitMessage, offset, 4);
                offset += 4;
                int signaturePublicKeyLength = ProtocolMessage.GetIntValue(serverInitMessage, offset, 4);

                // get decrypted signature with public key.
                offset += 4;
                byte[] decryptedSignatureWithKey = connection.UsedSymmetricAlgorithm.Decrypt(serverInitMessage[offset..]);

                byte[] signature = decryptedSignatureWithKey[0..signaturePartLength];
                byte[] signaturePublicKey = new byte[signaturePublicKeyLength];
                Array.Copy(decryptedSignatureWithKey, signaturePartLength, signaturePublicKey, 0, signaturePublicKeyLength);

                // verify signature.
                ISignatureAlgorithm verifier = preferredCipher.GetSignatureAlgorithm(false);

                return verifier.Verify(signaturePublicKey, clientInitMessageHash, signature);
            }

            try
            {
                var connection = new QuantoCryptConnection(baseConnection);

                _sValidateCipherSuites(cipherSuiteProvider, preferredCipher);

                // CLIENT_INIT - generate key pair + random message to be signed.
                byte[] clientInitMessage = __GetClientInitMessage(preferredCipher, out IKEMAlgorithm kemAlgorithm);

                connection.prWrappedUnsecureConnection.Send(clientInitMessage);



                var serverResponseMessage = connection.prWrappedUnsecureConnection.Receive();

                // check message integrity.
                if (!ProtocolMessage.CheckMessageIntegrity(serverResponseMessage))
                    throw new ArgumentException("Message integrity check fails.");

                // check that the server sent a proper message.
                if (serverResponseMessage[1] == ProtocolMessage.SERVER_INIT)
                {
                    // SERVER_INIT - get cipherText to generate sessionSecret + encryptedSigWithKey to validate server by clientInitMessage.
                    byte[] calculatedMessage = ProtocolMessage.GetMessageHash(clientInitMessage);

                    if (!__ValidateServerInitMessage(connection, kemAlgorithm, serverResponseMessage, calculatedMessage))
                        throw new Exception("Can't validate the server's signature!");

                    //_SendClientFinishMessage(connection, serverInitMessage);
                }
                else if (serverResponseMessage[1] == ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS)
                {
                    // TODO: add fallback for the client.

                    //preferredCipher = ...;

                    // CLIENT_INIT - generate key pair + random message to be signed.
                    clientInitMessage = __GetClientInitMessage(preferredCipher, out kemAlgorithm);

                    connection.prWrappedUnsecureConnection.Send(clientInitMessage);

                    serverResponseMessage = connection.prWrappedUnsecureConnection.Receive();

                    // check message integrity.
                    if (!ProtocolMessage.CheckMessageIntegrity(serverResponseMessage))
                        throw new ArgumentException("Message integrity check fails.");

                    if (serverResponseMessage[1] == ProtocolMessage.SERVER_INIT)
                    {
                        // SERVER_INIT - get cipherText to generate sessionSecret + encryptedSigWithKey to validate server by clientInitMessage.
                        byte[] calculatedMessage = ProtocolMessage.GetMessageHash(clientInitMessage);

                        if (!__ValidateServerInitMessage(connection, kemAlgorithm, serverResponseMessage, calculatedMessage))
                            throw new Exception("Can't validate the server's signature!");
                    }
                    else
                        throw new Exception($"Server sent unsupported message after fallback! Expected message [{ProtocolMessage.SERVER_INIT}], actual - [{serverResponseMessage[1]}].");
                }
                else
                    throw new ArgumentException($"Server sent invalid messageType. Expected [{ProtocolMessage.SERVER_INIT}] or [{ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS}], found [{serverResponseMessage[1]}].");



                // Secure connection established.
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
                // get preferred clients' CipherSuite.
                byte prefferedCipherSuite = clientInitMessage[10];

                return cipherSuiteProvider.SupportedCipherSuites.Keys.ToList().ElementAt(prefferedCipherSuite);
            }

            byte[] __GetServerInitMessage(QuantoCryptConnection connection, byte[] clientInitMessage, ICipherSuite cipherSuiteToUse)
            {
                // header = 10 + prefferedCS = 1 + supportedCS = 8.
                int publicKeyOffset = 19;

                // get public key from client.
                byte[] kemPublicKey = clientInitMessage[publicKeyOffset..];

                // create a proper KEM algorithm.
                IKEMAlgorithm kemAlgorithm = cipherSuiteToUse.GetKEMAlgorithm();

                // create encapsulated data (session secret + ciphertext for client).
                ISecretWithEncapsulation secretWithEncapsulatedData = kemAlgorithm.Encaps(kemPublicKey);

                byte[] sessionSecret = secretWithEncapsulatedData.GetSecret();
                byte[] generatedCipherText = secretWithEncapsulatedData.GetEncapsulation();

                // get Signature algorithm.
                ISignatureAlgorithm signatureAlgorithmForSigning = cipherSuiteToUse.GetSignatureAlgorithm(true);

                // create keys and sign clinets' message.
                AsymmetricKeyPair signatureKeys = signatureAlgorithmForSigning.KeyGen();

                // generate hash over clientInitMessage to be signed.
                byte[] messageToBeSigned = ProtocolMessage.GetMessageHash(clientInitMessage);
                byte[] signature = signatureAlgorithmForSigning.Sign(messageToBeSigned);

                // create a proper ISymmetricAlgorithm using genereted session secret.
                connection.UsedSymmetricAlgorithm = cipherSuiteToUse.GetSymmetricAlgorithm(sessionSecret);

                // prepare params for client. We need to sent cipher text + [signature + signature public key](encrypted).
                byte[] signaturePublicKey = signatureKeys.Public.GetEncoded();
                byte[] encryptedSignatureWithKey = connection.UsedSymmetricAlgorithm.Encrypt(ArrayUtilities.Combine(signature, signaturePublicKey));

                return ProtocolMessage.CreateServerInitMessage(generatedCipherText, encryptedSignatureWithKey, signature.Length, signaturePublicKey.Length);
            }

            try
            {
                var connection = new QuantoCryptConnection(baseConnection);

                _sValidateCipherSuites(cipherSuiteProvider);

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
                        // return failed message to client fi server doesn't support a preffered Cipher Suite.
                        serverInitMessage = ProtocolMessage.CreateUnsupportedParamsMessage(ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS, cipherSuiteProvider);
                    }
                    else
                        serverInitMessage = __GetServerInitMessage(connection, clientInitMessage, cipherSuiteToUse);
                }
                else
                    throw new ArgumentException($"Client sent invalid messageType. Expected [{ProtocolMessage.CLIENT_INIT}], found [{clientInitMessage[1]}].");

                
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
                            .Select(x => x.Key.Name)
                            .Aggregate("Supported CipherSuites:", (first, next) => $"{first}{Environment.NewLine}{next}");

                        throw new ArgumentException($"Client sent unsupported CipherSuite in a second time. {supportedCipherSuites}.");
                    }
                    else
                        serverInitMessage = __GetServerInitMessage(connection, clientInitMessage, cipherSuiteToUse);
                }

                connection.prWrappedUnsecureConnection.Send(serverInitMessage);

                //_ProceedClientFinishMessage(connection, serverInitMessage);


                // Secure connection established.
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


        private static void _sValidateCipherSuites(ICipherSuiteProvider cipherSuiteProvider)
        {
            if ((cipherSuiteProvider?.SupportedCipherSuites?.Count ?? 0) == 0)
                throw new ArgumentException($"SupportedCipherSuites can't be null or empty! Please, recheck your code - the [{nameof(cipherSuiteProvider)}] param.");
        }

        private static void _sValidateCipherSuites(ICipherSuiteProvider cipherSuiteProvider, ICipherSuite preferredCipher)
        {
            _sValidateCipherSuites(cipherSuiteProvider);

            // in case if try to use the CS that is not supported - throw.
            if (cipherSuiteProvider.SupportedCipherSuites.Keys.FirstOrDefault(x => x.Name == preferredCipher.Name) == null)
                throw new ArgumentException($"You're trying to use the cipher suite that is not listened in the [{nameof(cipherSuiteProvider)}]. " +
                    $"Target preferredCipher - [{preferredCipher.Name}], supported cipher suites by provider: {cipherSuiteProvider.SupportedCipherSuites.Select(x => x.Key.Name).Aggregate((first, next) => $"{first}{Environment.NewLine}{next}")}");
        }

        private static void _SendClientFinishMessage(QuantoCryptConnection connection, byte[] serverInitMessage)
        {
            // get hash of the SERVER_INIT message + encode it to sent to the server for verify.
            byte[] encodedServerInitMessageHash = connection.UsedSymmetricAlgorithm.Encrypt(ProtocolMessage.GetMessageHash(serverInitMessage));

            byte[] clientFinishMessage = ProtocolMessage.CreateClientFinishMessage(encodedServerInitMessageHash);

            connection.prWrappedUnsecureConnection.Send(clientFinishMessage);
        }

        private static void _ProceedClientFinishMessage(QuantoCryptConnection connection, byte[] serverInitMessage)
        {
            // CLIENT_FINISH.
            var clientFinishMessage = connection.prWrappedUnsecureConnection.Receive();

            if (!ProtocolMessage.CheckMessageIntegrity(clientFinishMessage))
                throw new ArgumentException($"{ProtocolMessage.CLIENT_FINISH} messsage integrity check fails.");

            // check that the client sent a proper message (SHA384 over serverInit message, encoded via session key).
            if (clientFinishMessage[1] == ProtocolMessage.CLIENT_FINISH)
            {
                byte[] clientFinishCheck = clientFinishMessage[10..];

                Span<byte> message = connection.UsedSymmetricAlgorithm.Decrypt(clientFinishCheck);

                if (!message.SequenceEqual(ProtocolMessage.GetMessageHash(serverInitMessage)))
                    throw new ArgumentException("Client validation fails!");
            }
            else
                throw new ArgumentException($"Client sent invalid messageType. Expected [{ProtocolMessage.CLIENT_FINISH}], found [{clientFinishMessage[1]}].");
        }
    }
}
