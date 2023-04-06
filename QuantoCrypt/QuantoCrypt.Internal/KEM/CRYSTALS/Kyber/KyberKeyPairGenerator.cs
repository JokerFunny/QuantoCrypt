using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.Common.Random;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Generator of the public/private key pair for the CRYSTALS-Kyber.
    /// </summary>
    public class KyberKeyPairGenerator
    {
        private readonly KyberParameters _rKyberParams;
        private readonly SecureRandom _rSecureRandom;

        /// <summary>
        /// Intialise the key pair generator
        /// </summary>
        /// <param name="param"></param>
        internal KyberKeyPairGenerator(KyberKeyGenerationParameters param)
        {
            _rKyberParams = param.Parameters;
            _rSecureRandom = param.Random;
        }

        /// <summary>
        /// Creates an <see cref="AsymmetricCipherKeyPair"/> containing the generated keys.
        /// </summary>
        /// <returns></returns>
        public AsymmetricKeyPair GenerateKeyPair()
            => _GenKeyPair();

        private AsymmetricKeyPair _GenKeyPair()
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
