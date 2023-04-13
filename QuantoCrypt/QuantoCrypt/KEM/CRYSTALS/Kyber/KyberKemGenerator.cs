using QuantoCrypt.Common;
using QuantoCrypt.Infrastructure.KEM;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Generates encapsulated secret (session key + ciphertext) for CRYSTALS-Kyber algorithm.
    /// </summary>
    internal sealed class KyberKemGenerator
    {
        // the source of randomness
        private readonly SecureRandom _rSecureRandom;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="random">Target <see cref="SecureRandom"/>.</param>
        internal KyberKemGenerator(SecureRandom random)
        {
            _rSecureRandom = random;
        }

        /// <summary>
        /// Generate an exchange pair based on the recipient public key.
        /// </summary>
        /// <param name="recipientKey">Target public key params</param>
        /// <returns> 
        ///     An SecretWithEncapsulation derived from the recipient public key.
        /// </returns>
        internal ISecretWithEncapsulation GenerateEncapsulated(KyberPublicKey recipientKey)
        {
            KyberEngine engine = recipientKey.Parameters.Engine;
            engine.Init(_rSecureRandom);

            byte[] cipherText = new byte[engine.CryptoCipherTextBytes];
            byte[] sessionKey = new byte[engine.CryptoBytes];
            engine.KemEncrypt(cipherText, sessionKey, recipientKey.GetEncoded());

            return new KyberSecretWithEncapsulation(sessionKey, cipherText);
        }

        private sealed class KyberSecretWithEncapsulation : ISecretWithEncapsulation
        {
            private volatile bool _hasBeenDestroyed = false;

            private readonly byte[] _rSessionKey;
            private readonly byte[] _rCipherText;

            internal KyberSecretWithEncapsulation(byte[] sessionKey, byte[] cipherText)
            {
                _rSessionKey = sessionKey;
                _rCipherText = cipherText;
            }

            public byte[] GetSecret()
            {
                _CheckDestroyed();

                return (byte[])_rSessionKey.Clone();
            }

            public byte[] GetEncapsulation()
            {
                _CheckDestroyed();

                return (byte[])_rCipherText.Clone();
            }

            public void Dispose()
            {
                if (!_hasBeenDestroyed)
                {
                    Array.Clear(_rSessionKey, 0, _rSessionKey.Length);
                    Array.Clear(_rCipherText, 0, _rCipherText.Length);

                    _hasBeenDestroyed = true;
                }

                GC.SuppressFinalize(this);
            }

            internal bool IsDestroyed()
                => _hasBeenDestroyed;

            private void _CheckDestroyed()
            {
                if (IsDestroyed())
                    throw new ArgumentException("data has been destroyed");
            }
        }
    }
}
