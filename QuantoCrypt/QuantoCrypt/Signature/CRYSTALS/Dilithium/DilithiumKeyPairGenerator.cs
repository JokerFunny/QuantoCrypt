using QuantoCrypt.Common;
using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Generator of the public/private key pair for the CRYSTALS-Dilithium.
    /// </summary>
    internal class DilithiumKeyPairGenerator
    {
        private readonly DilithiumParameters _rDilithiumParameters;
        private readonly SecureRandom _rSecureRandom;

        /// <summary>
        /// Intialise the key pair generator.
        /// </summary>
        /// <param name="param">Target <see cref="DilithiumKeyGenerationParameters"/>.</param>
        internal DilithiumKeyPairGenerator(DilithiumKeyGenerationParameters param)
        {
            _rDilithiumParameters = param.Parameters;
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
            DilithiumEngine engine = _rDilithiumParameters.GetEngine(_rSecureRandom);

            byte[] rho, key, tr, s1, s2, t0, encT1;
            engine.GenerateKeyPair(out rho, out key, out tr, out s1, out s2, out t0, out encT1);

            DilithiumPublicKey pubKey = new DilithiumPublicKey(_rDilithiumParameters, rho, encT1);
            DilithiumPrivateKey privKey = new DilithiumPrivateKey(_rDilithiumParameters, rho, key, tr, s1, s2, t0, encT1);

            return new AsymmetricKeyPair(pubKey, privKey);
        }
    }
}
