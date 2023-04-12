using QuantoCrypt.Common;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.KEM;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Implementation of the <see cref="IKEMAlgorithm"/> for CRYSTALS-Kyber.
    /// </summary>
    public sealed class KyberAlgorithm : IKEMAlgorithm
    {
        private KyberParameters _kyberParameters;
        private SecureRandom _secureRandom;
        private KyberKeyGenerationParameters _keyGenerationParameters;
        private KyberKeyPairGenerator _keyPairGenerator;
        private KyberKemGenerator _kemGenerator;
        private KyberPrivateKey _privateKey;
        private bool _isDisposed;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="kyberParameters">Target <see cref="KyberParameters"/>.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public KyberAlgorithm(KyberParameters kyberParameters)
        {
            _kyberParameters = kyberParameters ?? throw new ArgumentNullException(nameof(kyberParameters));
        }

        public byte[] Decaps(byte[] cipherText)
        {
            KyberKemExtractor kemExtractor = new KyberKemExtractor(_privateKey);

            return kemExtractor.ExtractSecret(cipherText);
        }

        public ISecretWithEncapsulation Encaps(byte[] publicKey)
        {
            KyberPublicKey kyberPublicKey = new KyberPublicKey(_kyberParameters, publicKey);

            KyberKemGenerator kemGenerator = _GetKemGenerator();

            return kemGenerator.GenerateEncapsulated(kyberPublicKey);
        }

        public AsymmetricKeyPair KeyGen()
        {
            KyberKeyPairGenerator keyPairGenerator = _GetKeyPairGenerator();

            AsymmetricKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            _privateKey = (KyberPrivateKey)keyPair.Private;

            return keyPair;
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                _kyberParameters = null;
                _secureRandom = null;
                _keyGenerationParameters = null;
                _keyPairGenerator = null;
                _kemGenerator = null;
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

        private KyberKeyGenerationParameters _GetKeyGenerationParameters()
        {
            if (_keyGenerationParameters == null && !_isDisposed)
                _keyGenerationParameters = new KyberKeyGenerationParameters(_GetRandom(), _kyberParameters);

            return _keyGenerationParameters;
        }

        private KyberKeyPairGenerator _GetKeyPairGenerator()
        {
            if (_keyPairGenerator == null && !_isDisposed)
                _keyPairGenerator = new KyberKeyPairGenerator(_GetKeyGenerationParameters());

            return _keyPairGenerator;
        }

        private KyberKemGenerator _GetKemGenerator()
        {
            if (_kemGenerator == null && !_isDisposed)
                _kemGenerator = new KyberKemGenerator(_GetRandom());

            return _kemGenerator;
        }
    }
}
