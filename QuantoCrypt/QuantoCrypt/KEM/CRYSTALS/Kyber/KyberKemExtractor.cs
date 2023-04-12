namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Key extractor from encapsulated message for CRYSTALS-Kyber algorithm.
    /// </summary>
    internal sealed class KyberKemExtractor
    {
        private readonly KyberPrivateKey _rKyberKey;
        private readonly KyberEngine _rKyberEngine;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="privParams">Private key.</param>
        internal KyberKemExtractor(KyberPrivateKey privParams)
        {
            _rKyberKey = privParams;
            _rKyberEngine = _rKyberKey.Parameters.Engine;
        }

        /// <summary>
        /// The length in bytes of the encapsulation.
        /// </summary>
        internal int EncapsulationLength => _rKyberEngine.CryptoCipherTextBytes;

        /// <summary>
        /// Generate an exchange pair based on the recipient public key.
        /// </summary>
        /// <param name="encapsulation">The encapsulated secret.</param>
        internal byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] sharedSecret = new byte[_rKyberEngine.CryptoBytes];
            _rKyberEngine.KemDecrypt(sharedSecret, encapsulation, _rKyberKey.GetEncoded());

            return sharedSecret;
        }
    }
}
