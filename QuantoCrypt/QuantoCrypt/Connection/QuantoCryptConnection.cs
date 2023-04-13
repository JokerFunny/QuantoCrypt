using QuantoCrypt.Common.Utilities;
using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Connection;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.Message;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// Main provider of the <see cref="ISecureTransportConnection"/>, allows create server/client + transfer data securelly.
    /// </summary>
    public sealed class QuantoCryptConnection : ISecureTransportConnection
    {
        /// <summary>
        /// Supported connection modes.
        /// </summary>
        public enum ConnectionMode : byte
        {
            /// <summary>
            /// Default mode (use KEM + DSA). Requires 2 messages: ClientInit + ServerInit. Checks servers' signature.
            /// </summary>
            /// <remarks>
            ///     Should be used in 99% of cases.
            /// </remarks>
            Default,
            /// <summary>
            /// Fast mode, server doesn't create signature (use KEM only). Requires 3 messages: ClientInit + ServerInit + ClientFinish (server validate that client get proper params).
            /// </summary>
            /// <remarks>
            ///     Should be used with caution, susceptible to attacks in the middle, no server authentication.
            ///     Performance is higher than when using the default mode.
            /// </remarks>
            Fast,
            /// <summary>
            /// Fast short mode, server doesn't create signature (use KEM only). Requires 2 messages: ClientInit + ServerInit.
            /// </summary>
            /// <remarks>
            ///     Should be used with caution, susceptible to attacks in the middle, no server authentication.
            ///     Performance is higher than when using the fast mode.
            /// </remarks>
            FastShort
        }

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
        private QuantoCryptConnection(ITransportConnection connection)
        {
            prWrappedUnsecureConnection = connection ?? throw new ArgumentNullException(nameof(connection));
        }

        #region Factory methods.

        /// <summary>
        /// Create a secure client using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="cipherSuiteProvider">Target <see cref="ICipherSuiteProvider"/> to be supported.</param>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/> to be wrapped.</param>
        /// <param name="connectionMode">Target <see cref="ConnectionMode"/>.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public static ISecureTransportConnection InitializeSecureClient(ICipherSuiteProvider cipherSuiteProvider, ITransportConnection baseConnection, ConnectionMode connectionMode)
            => InitializeSecureClient(cipherSuiteProvider, cipherSuiteProvider.SupportedCipherSuites.Keys.First(), baseConnection, connectionMode);

        /// <summary>
        /// Create a secure client using <paramref name="baseConnection"/>.
        /// </summary>
        /// <param name="cipherSuiteProvider">Target <see cref="ICipherSuiteProvider"/> to be supported.</param>
        /// <param name="preferredCipher">Preffered <see cref="ICipherSuite"/> to be used.</param>
        /// <param name="baseConnection">Target <see cref="ITransportConnection"/> to be wrapped.</param>
        /// <param name="connectionMode">Target <see cref="ConnectionMode"/>.</param>
        /// <returns>
        ///     Wrapped secure connection over <paramref name="baseConnection"/> with the support of <see cref="CipherSuiteProvider"/>.
        /// </returns>
        public static ISecureTransportConnection InitializeSecureClient(ICipherSuiteProvider cipherSuiteProvider, ICipherSuite preferredCipher, ITransportConnection baseConnection, ConnectionMode connectionMode)
        {
            byte[] __GetClientInitMessage(ICipherSuite preferredCipher, ConnectionMode connectionMode, out IKEMAlgorithm kemAlgorithm)
            {
                // CLIENT_INIT - generate key pair + random message to be signed.
                kemAlgorithm = preferredCipher.GetKEMAlgorithm();

                AsymmetricKeyPair keys = kemAlgorithm.KeyGen();
                byte[] publicKey = keys.Public.GetEncoded();

                return ProtocolMessage.CreateClientInitMessage(cipherSuiteProvider, preferredCipher, (byte)connectionMode, publicKey);
            };

            bool __ValidateServerInitMessage(QuantoCryptConnection connection, ConnectionMode connectionMode, IKEMAlgorithm kemAlgorithm, byte[] serverInitMessage, byte[] clientInitMessageHash)
            {
                int cipherTextLength = ProtocolMessage.GetIntValue(serverInitMessage, 10, 4);

                // get session key via cipher text from server.
                byte[] cipherText = new byte[cipherTextLength];
                Array.Copy(serverInitMessage, 14, cipherText, 0, cipherTextLength);

                byte[] sessionKey = kemAlgorithm.Decaps(cipherText);

                // create a proper ISymmetricAlgorithm using genereted session secret.
                connection.UsedSymmetricAlgorithm = preferredCipher.GetSymmetricAlgorithm(sessionKey);

                // validate signature in case if Default connection mode used.
                if (connectionMode == ConnectionMode.Default)
                {
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

                return true;
            }

            void __SendClientFinishMessage(QuantoCryptConnection connection, byte[] serverInitMessage)
            {
                // get hash of the SERVER_INIT message + encode it to sent to the server for verify.
                byte[] encodedServerInitMessageHash = connection.UsedSymmetricAlgorithm.Encrypt(ProtocolMessage.GetMessageHash(serverInitMessage));

                byte[] clientFinishMessage = ProtocolMessage.CreateClientFinishMessage(encodedServerInitMessageHash);

                connection.prWrappedUnsecureConnection.Send(clientFinishMessage);
            }

            var connection = new QuantoCryptConnection(baseConnection);

            try
            {
                _sValidateCipherSuites(cipherSuiteProvider, preferredCipher);

                // CLIENT_INIT - generate key pair + random message to be signed.
                byte[] clientInitMessage = __GetClientInitMessage(preferredCipher, connectionMode, out IKEMAlgorithm kemAlgorithm);

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

                    if (!__ValidateServerInitMessage(connection, connectionMode, kemAlgorithm, serverResponseMessage, calculatedMessage))
                        throw new Exception("Can't validate the server's signature!");

                    if (connectionMode == ConnectionMode.Fast)
                        __SendClientFinishMessage(connection, serverResponseMessage);
                }
                else if (serverResponseMessage[1] == ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS)
                {
                    // TODO: add fallback for the client.

                    //preferredCipher = ...;

                    // CLIENT_INIT - generate key pair + random message to be signed.
                    clientInitMessage = __GetClientInitMessage(preferredCipher, connectionMode, out kemAlgorithm);

                    connection.prWrappedUnsecureConnection.Send(clientInitMessage);

                    serverResponseMessage = connection.prWrappedUnsecureConnection.Receive();

                    // check message integrity.
                    if (!ProtocolMessage.CheckMessageIntegrity(serverResponseMessage))
                        throw new ArgumentException("Message integrity check fails.");

                    if (serverResponseMessage[1] == ProtocolMessage.SERVER_INIT)
                    {
                        // SERVER_INIT - get cipherText to generate sessionSecret + encryptedSigWithKey to validate server by clientInitMessage.
                        byte[] calculatedMessage = ProtocolMessage.GetMessageHash(clientInitMessage);

                        if (!__ValidateServerInitMessage(connection, connectionMode, kemAlgorithm, serverResponseMessage, calculatedMessage))
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
            catch 
            {
                connection.Close();

                throw; 
            }
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

            ConnectionMode __GetConnectionMode(byte[] clientInitMessage)
            {
                byte targetConnectionMode = clientInitMessage[11];

                if (targetConnectionMode < 0 || targetConnectionMode > 2)
                    throw new ArgumentOutOfRangeException($"Connection mode could be only 0, 1 or 2, but found [{targetConnectionMode}]!");

                return (ConnectionMode)targetConnectionMode;
            }

            byte[] __GetServerInitMessage(QuantoCryptConnection connection, byte[] clientInitMessage, ICipherSuite cipherSuiteToUse, ConnectionMode connectionMode)
            {
                // header = 10 + prefferedCS = 1.
                int publicKeyOffset = 11;

                // get public key from client.
                byte[] kemPublicKey = clientInitMessage[publicKeyOffset..];

                // create a proper KEM algorithm.
                IKEMAlgorithm kemAlgorithm = cipherSuiteToUse.GetKEMAlgorithm();

                // create encapsulated data (session secret + ciphertext for client).
                ISecretWithEncapsulation secretWithEncapsulatedData = kemAlgorithm.Encaps(kemPublicKey);

                byte[] sessionSecret = secretWithEncapsulatedData.GetSecret();
                byte[] generatedCipherText = secretWithEncapsulatedData.GetEncapsulation();

                // generate message with DS in case if Default connetion mode selected.
                if (connectionMode == ConnectionMode.Default)
                {
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

                return ProtocolMessage.CreateServerInitMessage(generatedCipherText);
            }

            void __ProceedClientFinishMessage(QuantoCryptConnection connection, byte[] serverInitMessage)
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

            var connection = new QuantoCryptConnection(baseConnection);

            try
            {
                _sValidateCipherSuites(cipherSuiteProvider);

                // SERVER_INIT.
                var clientInitMessage = connection.prWrappedUnsecureConnection.Receive();

                // check message integrity.
                if (!ProtocolMessage.CheckMessageIntegrity(clientInitMessage))
                    throw new ArgumentException("Message integrity check fails.");

                byte[] serverInitMessage;
                ConnectionMode connectionMode;

                // check that the ckient sent a proper message.
                if (clientInitMessage[1] == ProtocolMessage.CLIENT_INIT)
                {
                    // get preffered client CipherSuite.
                    ICipherSuite cipherSuiteToUse = __GetCipherSuiteToUse(clientInitMessage);
                    connectionMode = __GetConnectionMode(clientInitMessage);

                    if (cipherSuiteToUse == null)
                    {
                        // return failed message to client fi server doesn't support a preffered Cipher Suite.
                        serverInitMessage = ProtocolMessage.CreateUnsupportedClientParamsMessage(cipherSuiteProvider);
                    }
                    else
                        serverInitMessage = __GetServerInitMessage(connection, clientInitMessage, cipherSuiteToUse, connectionMode);
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
                    connectionMode = __GetConnectionMode(clientInitMessage);

                    if (cipherSuiteToUse == null)
                    {
                        string supportedCipherSuites = cipherSuiteProvider.SupportedCipherSuites
                            .Select(x => x.Key.Name)
                            .Aggregate("Supported CipherSuites:", (first, next) => $"{first}{Environment.NewLine}{next}");

                        throw new ArgumentException($"Client sent unsupported CipherSuite in a second time. {supportedCipherSuites}.");
                    }
                    else
                        serverInitMessage = __GetServerInitMessage(connection, clientInitMessage, cipherSuiteToUse, connectionMode);
                }


                connection.prWrappedUnsecureConnection.Send(serverInitMessage);


                // proceed CLIENT_FINISH if needed.
                if (connectionMode == ConnectionMode.Fast)
                    __ProceedClientFinishMessage(connection, serverInitMessage);



                // Secure connection established.
                return connection;
            }
            catch
            {
                connection.Close();

                throw;
            }
        }

        #endregion

        #region ISecureTransportConnection members.

        public int Send(byte[] data)
        {
            var encryptedText = UsedSymmetricAlgorithm.Encrypt(data);

            var protocolMessage = ProtocolMessage.CreateMessage(ProtocolMessage.PROTOCOL_VERSION, ProtocolMessage.DATA_TRANSFER, encryptedText);

            return prWrappedUnsecureConnection.Send(protocolMessage);
        }

        public byte[] Receive()
        {
            try
            {
                var message = new ProtocolMessage(prWrappedUnsecureConnection.Receive());

                return _ProceedReceivedMessage(message);
            }
            catch { throw; }
        }

        public async Task<int> SendAsync(byte[] data)
        {
            var encryptedText = UsedSymmetricAlgorithm.Encrypt(data);

            var targetMessage = ProtocolMessage.CreateMessage(ProtocolMessage.PROTOCOL_VERSION, ProtocolMessage.DATA_TRANSFER, encryptedText);

            return await prWrappedUnsecureConnection.SendAsync(targetMessage).ConfigureAwait(false);
        }

        public async Task<byte[]> ReceiveAsync()
        {
            try
            {
                byte[] targetData = await prWrappedUnsecureConnection.ReceiveAsync().ConfigureAwait(false);

                var message = new ProtocolMessage(targetData);

                return _ProceedReceivedMessage(message);
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

        /// <summary>
        /// Close this connection (with inner one) + send cloes message to recipient.
        /// </summary>
        /// <returns>
        ///     True - if sucesfully closed, otherwise - false.
        /// </returns>
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

        #endregion

        private byte[] _ProceedReceivedMessage(ProtocolMessage message)
        {
            if (!message.CheckMessageIntegrity())
                throw new ArgumentException("Message integrity check fails.");

            // if CLOSE message recieved - close connection.
            if (message.GetMessageType() == ProtocolMessage.CLOSE)
            {
                Close();

                return null;
            }

            if (message.GetMessageType() != ProtocolMessage.DATA_TRANSFER)
                throw new ArgumentException($"Invalid message code recieved! Expected to be a [DATA_TRANSFER], got [{message.GetMessageType()}].");

            var body = message.GetBody();

            return UsedSymmetricAlgorithm.Decrypt(body);
        }

        private void _ThrowAndClose(Exception targetException)
        {
            Close();

            throw targetException;
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
    }
}
