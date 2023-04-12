using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Generator of the public/private key pair for the CRYSTALS-Kyber.
    /// </summary>
    internal class KyberKeyPairGenerator
    {
        private readonly KyberParameters _rKyberParams;
        private readonly SecureRandom _rSecureRandom;

        /// <summary>
        /// Intialise the key pair generator.
        /// </summary>
        /// <param name="param">Target <see cref="KyberKeyGenerationParameters"/>.</param>
        internal KyberKeyPairGenerator(KyberKeyGenerationParameters param)
        {
            _rKyberParams = param.Parameters;
            _rSecureRandom = param.Random;
        }

        /// <summary>
        /// Creates an <see cref="AsymmetricKeyPair"/> containing the generated keys.
        /// </summary>
        /// <returns>
        ///     Target <see cref="AsymmetricKeyPair"/>.
        /// </returns>
        internal AsymmetricKeyPair GenerateKeyPair()
        {
            KyberEngine engine = _rKyberParams.Engine;
            engine.Init(_rSecureRandom);

            byte[] s, hpk, nonce, t, rho;
            engine.GenerateKemKeyPair(out t, out rho, out s, out hpk, out nonce);

            KyberPublicKey pubKey = new KyberPublicKey(_rKyberParams, t, rho);
            KyberPrivateKey privKey = new KyberPrivateKey(_rKyberParams, s, hpk, nonce, t, rho);

            return new AsymmetricKeyPair(pubKey, privKey);
        }
    }
}
