namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Random L-sized polynomial, needed as a part of the internal-key polynomial matrix A for Dilithium.
    /// </summary>
    internal class PolyVecL
    {
        internal readonly Poly[] rVec;
        private readonly int _rL;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="dilithiumEngine">Target <see cref="DilithiumEngine"/>.</param>
        internal PolyVecL(DilithiumEngine dilithiumEngine)
        {
            _rL = dilithiumEngine.L;
            rVec = new Poly[_rL];

            for (int i = 0; i < _rL; i++)
                rVec[i] = new Poly(dilithiumEngine);
        }

        internal void UniformEta(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < _rL; i++)
                rVec[i].UniformEta(seed, nonce++);
        }

        internal void CopyPolyVecL(PolyVecL OutPoly)
        {
            for (int i = 0; i < _rL; i++)
            {
                for (int j = 0; j < DilithiumEngine.N; j++)
                    OutPoly.rVec[i].rCoeffs[j] = rVec[i].rCoeffs[j];
            }
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < _rL; i++)
                rVec[i].InverseNttToMont();
        }

        internal void Ntt()
        {
            for (int i = 0; i < _rL; i++)
                rVec[i].PolyNtt();
        }

        internal void UniformGamma1(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < _rL; i++)
                rVec[i].UniformGamma1(seed, (ushort)(_rL * nonce + i));
        }

        internal void PointwisePolyMontgomery(Poly a, PolyVecL v)
        {
            for (int i = 0; i < _rL; ++i)
                rVec[i].PointwiseMontgomery(a, v.rVec[i]);
        }

        internal void AddPolyVecL(PolyVecL b)
        {
            for (int i = 0; i < _rL; i++)
                rVec[i].AddPoly(b.rVec[i]);
        }

        internal void Reduce()
        {
            for (int i = 0; i < _rL; i++)
                rVec[i].ReducePoly();
        }

        internal bool CheckNorm(int bound)
        {
            for (int i = 0; i < _rL; ++i)
            {
                if (rVec[i].CheckNorm(bound))
                    return true;
            }

            return false;
        }
    }
}
