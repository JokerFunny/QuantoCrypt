namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// A K*L matrix A each of whose entries is a polynomial in the ring Rq = Zq[X]/(Xn + 1).
    /// </summary>
    internal class PolyVecMatrix
    {
        private readonly PolyVecL[] _rMatrix;
        private readonly int _rK;
        private readonly int _rL;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="dilithiumEngine">Target <see cref="DilithiumEngine"/>.</param>
        internal PolyVecMatrix(DilithiumEngine dilithiumEngine)
        {
            _rK = dilithiumEngine.K;
            _rL = dilithiumEngine.L;
            _rMatrix = new PolyVecL[_rK];

            for (int i = 0; i < _rK; i++)
                _rMatrix[i] = new PolyVecL(dilithiumEngine);
        }

        internal void ExpandMatrix(byte[] rho)
        {
            int i, j;
            for (i = 0; i < _rK; ++i)
            {
                for (j = 0; j < _rL; ++j)
                    _rMatrix[i].rVec[j].UniformBlocks(rho, (ushort)((ushort)(i << 8) + j));
            }
        }

        internal void PointwiseMontgomery(PolyVecK t, PolyVecL v)
        {
            int i;
            for (i = 0; i < _rK; ++i)
                t.rVec[i].PointwiseAccountMontgomery(_rMatrix[i], v);
        }
    }
}
