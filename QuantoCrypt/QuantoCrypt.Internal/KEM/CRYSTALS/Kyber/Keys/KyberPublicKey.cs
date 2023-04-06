using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    internal sealed class KyberPublicKey : KyberKey
    {
        private readonly byte[] _rT;
        private readonly byte[] _rRho;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="KyberParameters"/>.</param>
        /// <param name="encoding">Target public key.</param>
        public KyberPublicKey(KyberParameters parameters, byte[] encoding)
            : base(false, parameters)
        {
            _rT = ArrayUtilities.CopyOfRange(encoding, 0, encoding.Length - KyberEngine.SymBytes);
            _rRho = ArrayUtilities.CopyOfRange(encoding, encoding.Length - KyberEngine.SymBytes, encoding.Length);
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="KyberParameters"/>.</param>
        /// <param name="t">First part of the public key [0, IndCpaPublicKeyBytes - 32].</param>
        /// <param name="rho">Second part of the public key [IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes].</param>
        public KyberPublicKey(KyberParameters parameters, byte[] t, byte[] rho)
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
