using QuantoCrypt.Common;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Signature;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Implementation of the <see cref="ISignatureAlgorithm"/> for CRYSTALS-Dilithium.
    /// </summary>
    public sealed class DilithiumAlgorithm : ISignatureAlgorithm
    {
        private DilithiumParameters _dilithiumParameters;
        private DilithiumPrivateKey _privateKey;
        private SecureRandom _secureRandom;
        private bool _isDisposed;
        private readonly bool _rIsForSigning;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="dilithiumParameters">Target <see cref="DilithiumParameters"/>.</param>
        /// <param name="isForSigning">If this should sign or verify messages.</param>
        public DilithiumAlgorithm(DilithiumParameters dilithiumParameters, bool isForSigning) 
        {
            _dilithiumParameters = dilithiumParameters;
            _rIsForSigning = isForSigning;
        }

        public AsymmetricKeyPair KeyGen()
        {
            DilithiumKeyGenerationParameters keyGenerationParameters = new DilithiumKeyGenerationParameters(_GetRandom(), _dilithiumParameters);

            DilithiumKeyPairGenerator keyPairGenerator = new DilithiumKeyPairGenerator(keyGenerationParameters);

            AsymmetricKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            _privateKey = (DilithiumPrivateKey)keyPair.Private;

            return keyPair;
        }

        public byte[] Sign(byte[] message)
        {
            DilithiumSigner signer = new DilithiumSigner(_rIsForSigning, _privateKey);

            byte[] generatedSignature = signer.GenerateSignature(message);

            return generatedSignature;
        }

        public bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            DilithiumPublicKey dilithiumPublicKey = new DilithiumPublicKey(_dilithiumParameters, publicKey);

            DilithiumSigner verifier = new DilithiumSigner(_rIsForSigning, dilithiumPublicKey);

            return verifier.VerifySignature(message, signature);
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                _dilithiumParameters = null;
                _secureRandom = null;
                _privateKey = null;
            }

            _isDisposed = true;
        }

        private SecureRandom _GetRandom()
        {
            if (_secureRandom == null && !_isDisposed)
                _secureRandom = new SecureRandom();

            return _secureRandom;
        }
    }
}
