namespace QuantoCrypt.Infrastructure.Common
{
    /// <summary>
    /// Handler to store info about public/private key pair.
    /// </summary>
    public class AsymmetricKeyPair
    {
        private readonly AsymmetricKey _rPublicKey;
        private readonly AsymmetricKey _rPrivateKey;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="publicKey">Target public key.</param>
        /// <param name="privateKey">Target private key.</param>
        public AsymmetricKeyPair(AsymmetricKey publicKey, AsymmetricKey privateKey)
        {
            if (publicKey.IsPrivate)
                throw new ArgumentException("Public key expected to be a public, but was private.", nameof(publicKey));
            if (!privateKey.IsPrivate)
                throw new ArgumentException("Private key expected to be a private, but was public.", nameof(privateKey));

            _rPublicKey = publicKey;
            _rPrivateKey = privateKey;
        }

        /// <summary>
        /// Target public key <see cref="AsymmetricKey"/>.
        /// </summary>
        public AsymmetricKey Public => _rPublicKey;

        /// <summary>
        /// Target private key <see cref="AsymmetricKey"/>.
        /// </summary>
        public AsymmetricKey Private => _rPrivateKey;
    }
}
