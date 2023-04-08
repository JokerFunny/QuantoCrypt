using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Handle work with CRYSTALS-Dilithium public key.
    /// </summary>
    internal sealed class DilithiumPublicKey : DilithiumKey
    {
        private readonly byte[] _rT;
        private readonly byte[] _rRho;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="DilithiumParameters"/>.</param>
        /// <param name="encoded">Target public key.</param>
        public DilithiumPublicKey(DilithiumParameters parameters, byte[] encoded)
            : base(false, parameters)
        {
            _rRho = ArrayUtilities.CopyOfRange(encoded, 0, DilithiumEngine.SeedBytes);
            _rT = ArrayUtilities.CopyOfRange(encoded, DilithiumEngine.SeedBytes, encoded.Length);
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="DilithiumParameters"/>.</param>
        /// <param name="rho">Expanded matrix of the vectored polinomial matrix, absorbed by shake digest.</param>
        /// <param name="t1">Packed and updated by shake block publick key.</param>
        public DilithiumPublicKey(DilithiumParameters parameters, byte[] rho, byte[] t1)
            : base(false, parameters)
        {
            _rRho = (byte[])rho.Clone();
            _rT = (byte[])t1.Clone();
        }

        public override byte[] GetEncoded()
            => ArrayUtilities.Combine(_rRho, _rT);

        internal byte[] Rho => _rRho;
        internal byte[] T => _rT;
    }
}
