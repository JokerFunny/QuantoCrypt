namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Vector of polynomials.
    /// </summary>
    internal class PolyVec
    {
        internal readonly Poly[] rVector;
        private readonly KyberEngine _rKyberEngine;

        internal PolyVec(KyberEngine engine)
        {
            _rKyberEngine = engine;
            rVector = new Poly[engine.K];

            for (int i = 0; i < engine.K; i++)
                rVector[i] = new Poly(engine);
        }

        internal void Ntt()
        {
            for (int i = 0; i < _rKyberEngine.K; i++)
                rVector[i].PolyNtt();
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < _rKyberEngine.K; i++)
                rVector[i].PolyInverseNttToMont();
        }

        internal static void PointwiseAccountMontgomery(Poly r, PolyVec a, PolyVec b, KyberEngine engine)
        {
            Poly t = new Poly(engine);
            Poly.BaseMultMontgomery(r, a.rVector[0], b.rVector[0]);

            for (int i = 1; i < engine.K; i++)
            {
                Poly.BaseMultMontgomery(t, a.rVector[i], b.rVector[i]);
                r.Add(t);
            }

            r.PolyReduce();
        }

        internal void Add(PolyVec a)
        {
            for (int i = 0; i < _rKyberEngine.K; i++)
                rVector[i].Add(a.rVector[i]);
        }

        internal void Reduce()
        {
            for (int i = 0; i < _rKyberEngine.K; i++)
                rVector[i].PolyReduce();
        }

        internal void CompressPolyVec(byte[] r)
        {
            _ConditionalSubQ();
            int count = 0;
            if (_rKyberEngine.PolyVecCompressedBytes == _rKyberEngine.K * 320)
            {
                Span<short> t = stackalloc short[4];

                for (int i = 0; i < _rKyberEngine.K; i++)
                {
                    for (int j = 0; j < KyberEngine.N / 4; j++)
                    {
                        for (int k = 0; k < 4; k++)
                        {
                            t[k] = (short)
                                (
                                    (
                                        (((uint)rVector[i].Coeffs[4 * j + k] << 10)
                                            + (KyberEngine.Q / 2))
                                            / KyberEngine.Q)
                                        & 0x3ff);
                        }
                        r[count + 0] = (byte)(t[0] >> 0);
                        r[count + 1] = (byte)((t[0] >> 8) | (t[1] << 2));
                        r[count + 2] = (byte)((t[1] >> 6) | (t[2] << 4));
                        r[count + 3] = (byte)((t[2] >> 4) | (t[3] << 6));
                        r[count + 4] = (byte)((t[3] >> 2));
                        count += 5;
                    }
                }
            }
            else if (_rKyberEngine.PolyVecCompressedBytes == _rKyberEngine.K * 352)
            {
                Span<short> t = stackalloc short[8];

                for (int i = 0; i < _rKyberEngine.K; i++)
                {
                    for (int j = 0; j < KyberEngine.N / 8; j++)
                    {
                        for (int k = 0; k < 8; k++)
                        {
                            t[k] = (short)
                                (
                                    (
                                        (((uint)rVector[i].Coeffs[8 * j + k] << 11)
                                            + (KyberEngine.Q / 2))
                                            / KyberEngine.Q)
                                        & 0x7ff);
                        }
                        r[count + 0] = (byte)((t[0] >> 0));
                        r[count + 1] = (byte)((t[0] >> 8) | (t[1] << 3));
                        r[count + 2] = (byte)((t[1] >> 5) | (t[2] << 6));
                        r[count + 3] = (byte)((t[2] >> 2));
                        r[count + 4] = (byte)((t[2] >> 10) | (t[3] << 1));
                        r[count + 5] = (byte)((t[3] >> 7) | (t[4] << 4));
                        r[count + 6] = (byte)((t[4] >> 4) | (t[5] << 7));
                        r[count + 7] = (byte)((t[5] >> 1));
                        r[count + 8] = (byte)((t[5] >> 9) | (t[6] << 2));
                        r[count + 9] = (byte)((t[6] >> 6) | (t[7] << 5));
                        r[count + 10] = (byte)((t[7] >> 3));
                        count += 11;
                    }
                }
            }
            else
                throw new ArgumentException("Kyber PolyVecCompressedBytes neither 320 * KyberK or 352 * KyberK!");
        }

        internal void DecompressPolyVec(byte[] compressedCipherText)
        {
            int count = 0;

            if (_rKyberEngine.PolyVecCompressedBytes == (_rKyberEngine.K * 320))
            {
                Span<short> t = stackalloc short[4];

                for (int i = 0; i < _rKyberEngine.K; i++)
                {
                    for (int j = 0; j < KyberEngine.N / 4; j++)
                    {
                        t[0] = (short)(((compressedCipherText[count] & 0xFF) >> 0) | ((ushort)(compressedCipherText[count + 1] & 0xFF) << 8));
                        t[1] = (short)(((compressedCipherText[count + 1] & 0xFF) >> 2) | ((ushort)(compressedCipherText[count + 2] & 0xFF) << 6));
                        t[2] = (short)(((compressedCipherText[count + 2] & 0xFF) >> 4) | ((ushort)(compressedCipherText[count + 3] & 0xFF) << 4));
                        t[3] = (short)(((compressedCipherText[count + 3] & 0xFF) >> 6) | ((ushort)(compressedCipherText[count + 4] & 0xFF) << 2));
                        count += 5;

                        for (int k = 0; k < 4; k++)
                            rVector[i].Coeffs[4 * j + k] = (short)(((t[k] & 0x3FF) * KyberEngine.Q + 512) >> 10);
                    }
                }
            }
            else if (_rKyberEngine.PolyVecCompressedBytes == (_rKyberEngine.K * 352))
            {
                Span<short> t = stackalloc short[8];

                for (int i = 0; i < _rKyberEngine.K; i++)
                {
                    for (int j = 0; j < KyberEngine.N / 8; j++)
                    {
                        t[0] = (short)(((compressedCipherText[count] & 0xFF) >> 0) | ((ushort)(compressedCipherText[count + 1] & 0xFF) << 8));
                        t[1] = (short)(((compressedCipherText[count + 1] & 0xFF) >> 3) | ((ushort)(compressedCipherText[count + 2] & 0xFF) << 5));
                        t[2] = (short)(((compressedCipherText[count + 2] & 0xFF) >> 6) | ((ushort)(compressedCipherText[count + 3] & 0xFF) << 2) | ((ushort)((compressedCipherText[count + 4] & 0xFF) << 10)));
                        t[3] = (short)(((compressedCipherText[count + 4] & 0xFF) >> 1) | ((ushort)(compressedCipherText[count + 5] & 0xFF) << 7));
                        t[4] = (short)(((compressedCipherText[count + 5] & 0xFF) >> 4) | ((ushort)(compressedCipherText[count + 6] & 0xFF) << 4));
                        t[5] = (short)(((compressedCipherText[count + 6] & 0xFF) >> 7) | ((ushort)(compressedCipherText[count + 7] & 0xFF) << 1) | ((ushort)((compressedCipherText[count + 8] & 0xFF) << 9)));
                        t[6] = (short)(((compressedCipherText[count + 8] & 0xFF) >> 2) | ((ushort)(compressedCipherText[count + 9] & 0xFF) << 6));
                        t[7] = (short)(((compressedCipherText[count + 9] & 0xFF) >> 5) | ((ushort)(compressedCipherText[count + 10] & 0xFF) << 3));
                        count += 11;

                        for (int k = 0; k < 8; k++)
                            rVector[i].Coeffs[8 * j + k] = (short)(((t[k] & 0x7FF) * KyberEngine.Q + 1024) >> 11);
                    }
                }
            }
            else
                throw new ArgumentException("Kyber PolyVecCompressedBytes neither 320 * KyberK or 352 * KyberK!");
        }

        internal void ToBytes(byte[] r)
        {
            for (int i = 0; i < _rKyberEngine.K; i++)
                rVector[i].ToBytes(r, i * KyberEngine.PolyBytes);
        }

        internal void FromBytes(byte[] pk)
        {
            for (int i = 0; i < _rKyberEngine.K; i++)
                rVector[i].FromBytes(pk, i * KyberEngine.PolyBytes);
        }

        private void _ConditionalSubQ()
        {
            for (int i = 0; i < _rKyberEngine.K; i++)
                rVector[i].CondSubQ();
        }
    }
}
