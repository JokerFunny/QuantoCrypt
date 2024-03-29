﻿using QuantoCrypt.Common;
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

        public AsymmetricKeyPair KeyGen()
        {
            KyberKeyGenerationParameters keyGenerationParameters = new KyberKeyGenerationParameters(new SecureRandom(), _kyberParameters);

            KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator(keyGenerationParameters);

            AsymmetricKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            _privateKey = (KyberPrivateKey)keyPair.Private;

            return keyPair;
        }

        public byte[] Decaps(byte[] cipherText)
        {
            KyberKemExtractor kemExtractor = new KyberKemExtractor(_privateKey);

            return kemExtractor.ExtractSecret(cipherText);
        }

        public ISecretWithEncapsulation Encaps(byte[] publicKey)
        {
            KyberPublicKey kyberPublicKey = new KyberPublicKey(_kyberParameters, publicKey);

            KyberKemGenerator kemGenerator = new KyberKemGenerator(new SecureRandom());

            return kemGenerator.GenerateEncapsulated(kyberPublicKey);
        }

        public void Dispose()
        {
            if (!_isDisposed)
            {
                _kyberParameters = null;
                _privateKey = null;
            }

            _isDisposed = true;
        }
    }
}
