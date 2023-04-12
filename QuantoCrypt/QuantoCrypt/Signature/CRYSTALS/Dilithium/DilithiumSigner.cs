using QuantoCrypt.Common;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Used to generate\verify CRYSTALS-Dilithium signatures.
    /// </summary>
    internal class DilithiumSigner
    {
        private readonly DilithiumPublicKey _rPublicKey;
        private readonly DilithiumPrivateKey _rPrivateKey;
        private readonly SecureRandom _rRandom;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="forSigning">If used for signing, otherwise - for verify.</param>
        /// <param name="targetKey">Target <see cref="DilithiumKey"/>.</param>
        /// <param name="random">Target <see cref="SecureRandom"/>.</param>
        internal DilithiumSigner(bool forSigning, DilithiumKey targetKey, SecureRandom random = null)
        {
            if (forSigning)
                _rPrivateKey = (DilithiumPrivateKey)targetKey;
            else
                _rPublicKey = (DilithiumPublicKey)targetKey;

            _rRandom = random;
        }

        /// <summary>
        /// Sign target message.
        /// </summary>
        /// <param name="message">Target message to be signed.</param>
        /// <returns>
        ///     Generated signature over <paramref name="message"/>.
        /// </returns>
        internal byte[] GenerateSignature(byte[] message)
        {
            if (_rPrivateKey == null)
                throw new InvalidOperationException($"You can't create signature using [{nameof(DilithiumSigner)}] created for signature verify.");

            DilithiumEngine engine = _rPrivateKey.Parameters.GetEngine(_rRandom);
            byte[] sig = new byte[engine.CryptoBytes];

            engine.Sign(sig, sig.Length, message, message.Length, _rPrivateKey);
            
            return sig;
        }

        /// <summary>
        /// Verify signature.
        /// </summary>
        /// <param name="message">Target message.</param>
        /// <param name="signature">Target signature.</param>
        /// <returns>
        ///     True in case of successful, otherwise - false.
        /// </returns>
        internal bool VerifySignature(byte[] message, byte[] signature)
        {
            if (_rPublicKey == null)
                throw new InvalidOperationException($"You can't verify signature using [{nameof(DilithiumSigner)}] created for signing.");

            DilithiumEngine engine = _rPublicKey.Parameters.GetEngine(_rRandom);

            return engine.Verify(message, signature, signature.Length, _rPublicKey);
        }
    }
}
