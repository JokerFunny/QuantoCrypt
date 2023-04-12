using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Handle work with CRYSTALS-Dilithium private key.
    /// </summary>
    internal sealed class DilithiumPrivateKey : DilithiumKey
    {
        private readonly byte[] _rRho;
        private readonly byte[] _rK;
        private readonly byte[] _rTr;
        private readonly byte[] _rS1;
        private readonly byte[] _rS2;
        private readonly byte[] _rT0;
        private readonly byte[] _rT1;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="DilithiumParameters"/>.</param>
        /// <param name="rho">Expanded matrix of the vectored polinomial matrix, absorbed by shake digest.</param>
        /// <param name="k">Target random key, obtained by random + digest operations.</param>
        /// <param name="tr">The results of the final calculation for shake XOF.</param>
        /// <param name="s1">Random vector, part of the private key, depends on security level (l-sized). Packed by polynomial rings operation.</param>
        /// <param name="s2">Random vector, part of the private key, depends on security level (l-sized). Packed by polynomial rings operation.</param>
        /// <param name="t0">Target packed bytes.</param>
        /// <param name="t1">Packed and updated by shake block publick key.</param>
        internal DilithiumPrivateKey(DilithiumParameters parameters, byte[] rho, byte[] k, byte[] tr, byte[] s1, byte[] s2, byte[] t0, byte[] t1)
            : base(true, parameters)
        {
            _rRho = (byte[])rho.Clone();
            _rK = (byte[])k.Clone();
            _rTr = (byte[])tr.Clone();
            _rS1 = (byte[])s1.Clone();
            _rS2 = (byte[])s2.Clone();
            _rT0 = (byte[])t0.Clone();
            _rT1 = (byte[])t1.Clone();
        }

        internal override byte[] GetEncoded()
            => ArrayUtilities.Combine(_rRho, _rK, _rTr, _rS1, _rS2, _rT0);

        internal byte[] Rho => _rRho;
        internal byte[] K => _rK;
        internal byte[] Tr => _rTr;
        internal byte[] S1 => _rS1;
        internal byte[] S2 => _rS2;
        internal byte[] T0 => _rT0;
        internal byte[] T1 => _rT1;
    }
}
