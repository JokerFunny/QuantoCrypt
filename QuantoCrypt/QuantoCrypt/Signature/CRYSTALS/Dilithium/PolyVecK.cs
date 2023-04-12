namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Random K-sized polynomial, needed as a part of the public-key polynomial matrix A for Dilithium.
    /// </summary>
    internal class PolyVecK
    {
        internal readonly Poly[] rVec;
        private readonly int _rK;
        private readonly int _rPolyW1PackedBytes;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="dilithiumEngine">Target <see cref="DilithiumEngine"/>.</param>
        internal PolyVecK(DilithiumEngine dilithiumEngine)
        {
            _rK = dilithiumEngine.K;
            _rPolyW1PackedBytes = dilithiumEngine.PolyW1PackedBytes;
            rVec = new Poly[_rK];

            for (int i = 0; i < _rK; i++)
                rVec[i] = new Poly(dilithiumEngine);
        }

        internal void UniformEta(byte[] seed, ushort nonce)
        {
            ushort n = nonce;
            for (int i = 0; i < _rK; i++)
                rVec[i].UniformEta(seed, n++);
        }

        internal void Reduce()
        {
            for (int i = 0; i < _rK; i++)
                rVec[i].ReducePoly();
        }

        internal void Ntt()
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].PolyNtt();
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].InverseNttToMont();
        }

        internal void AddPolyVecK(PolyVecK b)
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].AddPoly(b.rVec[i]);
        }

        internal void Subtract(PolyVecK v)
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].Subtract(v.rVec[i]);
        }

        internal void ConditionalAddQ()
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].ConditionalAddQ();
        }

        internal void Power2Round(PolyVecK v)
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].Power2Round(v.rVec[i]);
        }

        internal void Decompose(PolyVecK v)
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].Decompose(v.rVec[i]);
        }

        internal void PackW1(byte[] r)
        {
            for (int i = 0; i < _rK; i++)
                rVec[i].PackW1(r, i * _rPolyW1PackedBytes);
        }

        internal void PointwisePolyMontgomery(Poly a, PolyVecK v)
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].PointwiseMontgomery(a, v.rVec[i]);
        }

        internal bool CheckNorm(int bound)
        {
            for (int i = 0; i < _rK; ++i)
            {
                if (rVec[i].CheckNorm(bound))
                    return true;
            }

            return false;
        }

        internal int MakeHint(PolyVecK v0, PolyVecK v1)
        {
            int s = 0;
            for (int i = 0; i < _rK; ++i)
                s += rVec[i].PolyMakeHint(v0.rVec[i], v1.rVec[i]);

            return s;
        }

        internal void UseHint(PolyVecK a, PolyVecK h)
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].PolyUseHint(a.rVec[i], h.rVec[i]);
        }

        internal void ShiftLeft()
        {
            for (int i = 0; i < _rK; ++i)
                rVec[i].ShiftLeft();
        }
    }
}
