using QuantoCrypt.Common.Utilities;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Handle work with CRYSTALS-Kyber public key.
    /// </summary>
    internal sealed class KyberPublicKey : KyberKey
    {
        private readonly byte[] _rT;
        private readonly byte[] _rRho;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="KyberParameters"/>.</param>
        /// <param name="encoded">Target public key.</param>
        internal KyberPublicKey(KyberParameters parameters, byte[] encoded)
            : base(false, parameters)
        {
            _rT = ArrayUtilities.CopyOfRange(encoded, 0, encoded.Length - KyberEngine.SymBytes);
            _rRho = ArrayUtilities.CopyOfRange(encoded, encoded.Length - KyberEngine.SymBytes, encoded.Length);
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="KyberParameters"/>.</param>
        /// <param name="t">First part of the public key [0, IndCpaPublicKeyBytes - 32].</param>
        /// <param name="rho">Second part of the public key [IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes].</param>
        internal KyberPublicKey(KyberParameters parameters, byte[] t, byte[] rho)
            : base(false, parameters)
        {
            _rT = (byte[])t.Clone();
            _rRho = (byte[])rho.Clone();
        }

        public override byte[] GetEncoded()
            => ArrayUtilities.Combine(_rT, _rRho);

        internal byte[] T => _rT;
        internal byte[] Rho => _rRho;
    }
}
