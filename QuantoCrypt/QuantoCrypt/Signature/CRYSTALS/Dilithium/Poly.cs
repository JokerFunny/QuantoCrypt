using QuantoCrypt.Common.Digest;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Represent operations with polynomial rings.
    /// </summary>
    internal class Poly
    {
        internal readonly int[] rCoeffs = new int[DilithiumEngine.N];

        private readonly int _rN = DilithiumEngine.N;
        private readonly DilithiumEngine _rEngine;
        private readonly int _rPolyUniformNBlocks;
        private readonly Symmetric _rSymmetric;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="dilithiumEngine">Target <see cref="DilithiumEngine"/>.</param>
        internal Poly(DilithiumEngine dilithiumEngine)
        {
            _rEngine = dilithiumEngine;
            _rSymmetric = dilithiumEngine.Symmetric;
            _rPolyUniformNBlocks = (768 + _rSymmetric.rStream128BlockBytes - 1) / _rSymmetric.rStream128BlockBytes;
        }

        internal void UniformBlocks(byte[] seed, ushort nonce)
        {
            int i, ctr, off,
            buflen = _rPolyUniformNBlocks * _rSymmetric.rStream128BlockBytes;
            byte[] buf = new byte[buflen + 2];

            _rSymmetric.Stream128Init(seed, nonce);

            _rSymmetric.Stream128SqueezeBlocks(buf, 0, buflen);

            ctr = _RejectUniform(rCoeffs, 0, _rN, buf, buflen);

            while (ctr < _rN)
            {
                off = buflen % 3;
                for (i = 0; i < off; ++i)
                {
                    buf[i] = buf[buflen - off + i];
                }
                _rSymmetric.Stream128SqueezeBlocks(buf, off, _rSymmetric.rStream128BlockBytes);
                buflen = _rSymmetric.rStream128BlockBytes + off;
                ctr += _RejectUniform(rCoeffs, ctr, _rN - ctr, buf, buflen);
            }
        }

        internal void UniformEta(byte[] seed, ushort nonce)
        {
            int ctr, PolyUniformEtaNBlocks, eta = _rEngine.Eta;

            if (_rEngine.Eta == 2)
                PolyUniformEtaNBlocks = ((136 + _rSymmetric.rStream256BlockBytes - 1) / _rSymmetric.rStream256BlockBytes);
            else if (_rEngine.Eta == 4)
                PolyUniformEtaNBlocks = ((227 + _rSymmetric.rStream256BlockBytes - 1) / _rSymmetric.rStream256BlockBytes);
            else
                throw new ArgumentException("Wrong Dilithium Eta!");

            int buflen = PolyUniformEtaNBlocks * _rSymmetric.rStream256BlockBytes;

            byte[] buf = new byte[buflen];

            _rSymmetric.Stream256Init(seed, nonce);
            _rSymmetric.Stream256SqueezeBlocks(buf, 0, buflen);
            ctr = _RejectEta(rCoeffs, 0, _rN, buf, buflen, eta);

            while (ctr < _rN)
            {
                _rSymmetric.Stream256SqueezeBlocks(buf, 0, _rSymmetric.rStream256BlockBytes);
                ctr += _RejectEta(rCoeffs, ctr, _rN - ctr, buf, _rSymmetric.rStream256BlockBytes, eta);
            }
        }

        internal void PointwiseMontgomery(Poly v, Poly w)
        {
            int i;

            for (i = 0; i < _rN; ++i)
                rCoeffs[i] = Reduce.MontgomeryReduce(v.rCoeffs[i] * (long)w.rCoeffs[i]);
        }

        internal void PointwiseAccountMontgomery(PolyVecL u, PolyVecL v)
        {
            int i;
            Poly t = new Poly(_rEngine);

            PointwiseMontgomery(u.rVec[0], v.rVec[0]);

            for (i = 1; i < _rEngine.L; ++i)
            {
                t.PointwiseMontgomery(u.rVec[i], v.rVec[i]);
                AddPoly(t);
            }
        }

        internal void AddPoly(Poly a)
        {
            int i;

            for (i = 0; i < _rN; i++)
                rCoeffs[i] += a.rCoeffs[i];
        }

        internal void Subtract(Poly b)
        {
            for (int i = 0; i < _rN; ++i)
                rCoeffs[i] -= b.rCoeffs[i];
        }

        internal void ReducePoly()
        {
            for (int i = 0; i < _rN; ++i)
                rCoeffs[i] = Reduce.Reduce32(rCoeffs[i]);
        }

        internal void PolyNtt()
            => Ntt.NTT(rCoeffs);

        internal void InverseNttToMont()
            => Ntt.InverseNttToMont(rCoeffs);

        internal void ConditionalAddQ()
        {
            for (int i = 0; i < _rN; ++i)
                rCoeffs[i] = Reduce.ConditionalAddQ(rCoeffs[i]);
        }

        internal void Power2Round(Poly a)
        {
            for (int i = 0; i < _rN; ++i)
            {
                int[] Power2Round = RoundingUtility.Power2Round(rCoeffs[i]);

                rCoeffs[i] = Power2Round[0];
                a.rCoeffs[i] = Power2Round[1];
            }
        }

        internal void PolyT0Pack(byte[] r, int off)
        {
            int i;
            int[] t = new int[8];
            for (i = 0; i < _rN / 8; ++i)
            {
                t[0] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 0];
                t[1] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 1];
                t[2] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 2];
                t[3] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 3];
                t[4] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 4];
                t[5] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 5];
                t[6] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 6];
                t[7] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 7];

                r[off + 13 * i + 0] = (byte)(t[0]);

                r[off + 13 * i + 1] = (byte)(t[0] >> 8);
                r[off + 13 * i + 1] = (byte)(r[off + 13 * i + 1] | (byte)(t[1] << 5));
                r[off + 13 * i + 2] = (byte)(t[1] >> 3);
                r[off + 13 * i + 3] = (byte)(t[1] >> 11);
                r[off + 13 * i + 3] = (byte)(r[off + 13 * i + 3] | (byte)(t[2] << 2));
                r[off + 13 * i + 4] = (byte)(t[2] >> 6);
                r[off + 13 * i + 4] = (byte)(r[off + 13 * i + 4] | (byte)(t[3] << 7));
                r[off + 13 * i + 5] = (byte)(t[3] >> 1);
                r[off + 13 * i + 6] = (byte)(t[3] >> 9);
                r[off + 13 * i + 6] = (byte)(r[off + 13 * i + 6] | (byte)(t[4] << 4));
                r[off + 13 * i + 7] = (byte)(t[4] >> 4);
                r[off + 13 * i + 8] = (byte)(t[4] >> 12);
                r[off + 13 * i + 8] = (byte)(r[off + 13 * i + 8] | (byte)(t[5] << 1));
                r[off + 13 * i + 9] = (byte)(t[5] >> 7);
                r[off + 13 * i + 9] = (byte)(r[off + 13 * i + 9] | (byte)(t[6] << 6));
                r[off + 13 * i + 10] = (byte)(t[6] >> 2);
                r[off + 13 * i + 11] = (byte)(t[6] >> 10);
                r[off + 13 * i + 11] = (byte)(r[off + 13 * i + 11] | (byte)(t[7] << 3));
                r[off + 13 * i + 12] = (byte)(t[7] >> 5);
            }
        }

        internal void PolyT0Unpack(byte[] a, int off)
        {
            int i;
            for (i = 0; i < _rN / 8; ++i)
            {
                rCoeffs[8 * i + 0] =
                    (
                        (a[off + 13 * i + 0] & 0xFF) |
                            ((a[off + 13 * i + 1] & 0xFF) << 8)
                    ) & 0x1FFF;
                rCoeffs[8 * i + 1] =
                    (
                        (((a[off + 13 * i + 1] & 0xFF) >> 5) |
                            ((a[off + 13 * i + 2] & 0xFF) << 3)) |
                            ((a[off + 13 * i + 3] & 0xFF) << 11)
                    ) & 0x1FFF;

                rCoeffs[8 * i + 2] =
                    (
                        (((a[off + 13 * i + 3] & 0xFF) >> 2) |
                            ((a[off + 13 * i + 4] & 0xFF) << 6))
                    ) & 0x1FFF;

                rCoeffs[8 * i + 3] =
                    (
                        (((a[off + 13 * i + 4] & 0xFF) >> 7) |
                            ((a[off + 13 * i + 5] & 0xFF) << 1)) |
                            ((a[off + 13 * i + 6] & 0xFF) << 9)
                    ) & 0x1FFF;

                rCoeffs[8 * i + 4] =
                    (
                        (((a[off + 13 * i + 6] & 0xFF) >> 4) |
                            ((a[off + 13 * i + 7] & 0xFF) << 4)) |
                            ((a[off + 13 * i + 8] & 0xFF) << 12)
                    ) & 0x1FFF;

                rCoeffs[8 * i + 5] =
                    (
                        (((a[off + 13 * i + 8] & 0xFF) >> 1) |
                            ((a[off + 13 * i + 9] & 0xFF) << 7))
                    ) & 0x1FFF;

                rCoeffs[8 * i + 6] =
                    (
                        (((a[off + 13 * i + 9] & 0xFF) >> 6) |
                            ((a[off + 13 * i + 10] & 0xFF) << 2)) |
                            ((a[off + 13 * i + 11] & 0xFF) << 10)
                    ) & 0x1FFF;

                rCoeffs[8 * i + 7] =
                    (
                        ((a[off + 13 * i + 11] & 0xFF) >> 3 |
                            ((a[off + 13 * i + 12] & 0xFF) << 5))
                    ) & 0x1FFF;

                rCoeffs[8 * i + 0] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 0];
                rCoeffs[8 * i + 1] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 1];
                rCoeffs[8 * i + 2] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 2];
                rCoeffs[8 * i + 3] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 3];
                rCoeffs[8 * i + 4] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 4];
                rCoeffs[8 * i + 5] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 5];
                rCoeffs[8 * i + 6] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 6];
                rCoeffs[8 * i + 7] = (1 << (DilithiumEngine.D - 1)) - rCoeffs[8 * i + 7];
            }
        }

        internal byte[] PolyT1Pack()
        {
            byte[] output = new byte[DilithiumEngine.PolyT1PackedBytes];

            for (int i = 0; i < _rN / 4; ++i)
            {
                output[5 * i + 0] = (byte)(rCoeffs[4 * i + 0] >> 0);
                output[5 * i + 1] = (byte)((rCoeffs[4 * i + 0] >> 8) | (rCoeffs[4 * i + 1] << 2));
                output[5 * i + 2] = (byte)((rCoeffs[4 * i + 1] >> 6) | (rCoeffs[4 * i + 2] << 4));
                output[5 * i + 3] = (byte)((rCoeffs[4 * i + 2] >> 4) | (rCoeffs[4 * i + 3] << 6));
                output[5 * i + 4] = (byte)(rCoeffs[4 * i + 3] >> 2);
            }

            return output;
        }

        internal void PolyT1Unpack(byte[] a)
        {
            int i;

            for (i = 0; i < _rN / 4; ++i)
            {
                rCoeffs[4 * i + 0] = (((a[5 * i + 0] & 0xFF) >> 0) | ((a[5 * i + 1] & 0xFF) << 8)) & 0x3FF;
                rCoeffs[4 * i + 1] = (((a[5 * i + 1] & 0xFF) >> 2) | ((a[5 * i + 2] & 0xFF) << 6)) & 0x3FF;
                rCoeffs[4 * i + 2] = (((a[5 * i + 2] & 0xFF) >> 4) | ((a[5 * i + 3] & 0xFF) << 4)) & 0x3FF;
                rCoeffs[4 * i + 3] = (((a[5 * i + 3] & 0xFF) >> 6) | ((a[5 * i + 4] & 0xFF) << 2)) & 0x3FF;
            }
        }

        internal void PolyEtaPack(byte[] r, int off)
        {
            int i;
            byte[] t = new byte[8];

            if (_rEngine.Eta == 2)
            {
                for (i = 0; i < _rN / 8; ++i)
                {
                    t[0] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 0]);
                    t[1] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 1]);
                    t[2] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 2]);
                    t[3] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 3]);
                    t[4] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 4]);
                    t[5] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 5]);
                    t[6] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 6]);
                    t[7] = (byte)(_rEngine.Eta - rCoeffs[8 * i + 7]);

                    r[off + 3 * i + 0] = (byte)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
                    r[off + 3 * i + 1] = (byte)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
                    r[off + 3 * i + 2] = (byte)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
                }
            }
            else if (_rEngine.Eta == 4)
            {
                for (i = 0; i < _rN / 2; ++i)
                {
                    t[0] = (byte)(_rEngine.Eta - rCoeffs[2 * i + 0]);
                    t[1] = (byte)(_rEngine.Eta - rCoeffs[2 * i + 1]);
                    r[off + i] = (byte)(t[0] | t[1] << 4);
                }
            }
            else
                throw new ArgumentException("Eta needs to be 2 or 4!");
        }

        internal void PolyEtaUnpack(byte[] a, int off)
        {
            int i, eta = _rEngine.Eta;

            if (eta == 2)
            {
                for (i = 0; i < _rN / 8; ++i)
                {
                    rCoeffs[8 * i + 0] = (((a[off + 3 * i + 0] & 0xFF) >> 0) & 7);
                    rCoeffs[8 * i + 1] = ((((a[off + 3 * i + 0] & 0xFF) >> 3)) & 7);
                    rCoeffs[8 * i + 2] = (((a[off + 3 * i + 0] & 0xFF) >> 6) | ((a[off + 3 * i + 1] & 0xFF) << 2) & 7);
                    rCoeffs[8 * i + 3] = ((((a[off + 3 * i + 1] & 0xFF) >> 1)) & 7);
                    rCoeffs[8 * i + 4] = ((((a[off + 3 * i + 1] & 0xFF) >> 4)) & 7);
                    rCoeffs[8 * i + 5] = (((a[off + 3 * i + 1] & 0xFF) >> 7) | ((a[off + 3 * i + 2] & 0xFF) << 1) & 7);
                    rCoeffs[8 * i + 6] = ((((a[off + 3 * i + 2] & 0xFF) >> 2)) & 7);
                    rCoeffs[8 * i + 7] = ((((a[off + 3 * i + 2] & 0xFF) >> 5)) & 7);

                    rCoeffs[8 * i + 0] = eta - rCoeffs[8 * i + 0];
                    rCoeffs[8 * i + 1] = eta - rCoeffs[8 * i + 1];
                    rCoeffs[8 * i + 2] = eta - rCoeffs[8 * i + 2];
                    rCoeffs[8 * i + 3] = eta - rCoeffs[8 * i + 3];
                    rCoeffs[8 * i + 4] = eta - rCoeffs[8 * i + 4];
                    rCoeffs[8 * i + 5] = eta - rCoeffs[8 * i + 5];
                    rCoeffs[8 * i + 6] = eta - rCoeffs[8 * i + 6];
                    rCoeffs[8 * i + 7] = eta - rCoeffs[8 * i + 7];
                }
            }
            else if (eta == 4)
            {
                for (i = 0; i < _rN / 2; ++i)
                {
                    rCoeffs[2 * i + 0] = ((a[off + i] & 0xFF) & 0x0F);
                    rCoeffs[2 * i + 1] = ((a[off + i] & 0xFF) >> 4);
                    rCoeffs[2 * i + 0] = eta - rCoeffs[2 * i + 0];
                    rCoeffs[2 * i + 1] = eta - rCoeffs[2 * i + 1];
                }
            }
        }

        internal void UniformGamma1(byte[] seed, ushort nonce)
        {
            byte[] buf = new byte[_rEngine.PolyUniformGamma1NBytes * _rSymmetric.rStream256BlockBytes];

            _rSymmetric.Stream256Init(seed, nonce);
            _rSymmetric.Stream256SqueezeBlocks(buf, 0, buf.Length);

            UnpackZ(buf);
        }

        internal void PackZ(byte[] r, int offset)
        {
            int i;
            uint[] t = new uint[4];
            if (_rEngine.Gamma1 == (1 << 17))
            {
                for (i = 0; i < _rN / 4; ++i)
                {
                    t[0] = (uint)(_rEngine.Gamma1 - rCoeffs[4 * i + 0]);
                    t[1] = (uint)(_rEngine.Gamma1 - rCoeffs[4 * i + 1]);
                    t[2] = (uint)(_rEngine.Gamma1 - rCoeffs[4 * i + 2]);
                    t[3] = (uint)(_rEngine.Gamma1 - rCoeffs[4 * i + 3]);

                    r[offset + 9 * i + 0] = (byte)t[0];
                    r[offset + 9 * i + 1] = (byte)(t[0] >> 8);
                    r[offset + 9 * i + 2] = (byte)((byte)(t[0] >> 16) | (t[1] << 2));
                    r[offset + 9 * i + 3] = (byte)(t[1] >> 6);
                    r[offset + 9 * i + 4] = (byte)((byte)(t[1] >> 14) | (t[2] << 4));
                    r[offset + 9 * i + 5] = (byte)(t[2] >> 4);
                    r[offset + 9 * i + 6] = (byte)((byte)(t[2] >> 12) | (t[3] << 6));
                    r[offset + 9 * i + 7] = (byte)(t[3] >> 2);
                    r[offset + 9 * i + 8] = (byte)(t[3] >> 10);
                }
            }
            else if (_rEngine.Gamma1 == (1 << 19))
            {
                for (i = 0; i < _rN / 2; ++i)
                {
                    t[0] = (uint)(_rEngine.Gamma1 - rCoeffs[2 * i + 0]);
                    t[1] = (uint)(_rEngine.Gamma1 - rCoeffs[2 * i + 1]);

                    r[offset + 5 * i + 0] = (byte)t[0];
                    r[offset + 5 * i + 1] = (byte)(t[0] >> 8);
                    r[offset + 5 * i + 2] = (byte)((byte)(t[0] >> 16) | (t[1] << 4));
                    r[offset + 5 * i + 3] = (byte)(t[1] >> 4);
                    r[offset + 5 * i + 4] = (byte)(t[1] >> 12);

                }
            }
            else
                throw new ArgumentException("Wrong Dilithium Gamma1!");
        }

        internal void UnpackZ(byte[] a)
        {
            int i;
            if (_rEngine.Gamma1 == (1 << 17))
            {
                for (i = 0; i < _rN / 4; ++i)
                {
                    rCoeffs[4 * i + 0] =
                        (
                            (((a[9 * i + 0] & 0xFF)) |
                                ((a[9 * i + 1] & 0xFF) << 8)) |
                                ((a[9 * i + 2] & 0xFF) << 16)
                        ) & 0x3FFFF;
                    rCoeffs[4 * i + 1] =
                        (
                            (((a[9 * i + 2] & 0xFF) >> 2) |
                                ((a[9 * i + 3] & 0xFF) << 6)) |
                                ((a[9 * i + 4] & 0xFF) << 14)
                        ) & 0x3FFFF;
                    rCoeffs[4 * i + 2] =
                        (
                            (((a[9 * i + 4] & 0xFF) >> 4) |
                                ((a[9 * i + 5] & 0xFF) << 4)) |
                                ((a[9 * i + 6] & 0xFF) << 12)
                        ) & 0x3FFFF;
                    rCoeffs[4 * i + 3] =
                        (
                            (((a[9 * i + 6] & 0xFF) >> 6) |
                                ((a[9 * i + 7] & 0xFF) << 2)) |
                                ((a[9 * i + 8] & 0xFF) << 10)
                        ) & 0x3FFFF;


                    rCoeffs[4 * i + 0] = _rEngine.Gamma1 - rCoeffs[4 * i + 0];
                    rCoeffs[4 * i + 1] = _rEngine.Gamma1 - rCoeffs[4 * i + 1];
                    rCoeffs[4 * i + 2] = _rEngine.Gamma1 - rCoeffs[4 * i + 2];
                    rCoeffs[4 * i + 3] = _rEngine.Gamma1 - rCoeffs[4 * i + 3];
                }
            }
            else if (_rEngine.Gamma1 == (1 << 19))
            {
                for (i = 0; i < _rN / 2; ++i)
                {
                    rCoeffs[2 * i + 0] =
                        (
                            (((a[5 * i + 0] & 0xFF)) |
                                ((a[5 * i + 1] & 0xFF) << 8)) |
                                ((a[5 * i + 2] & 0xFF) << 16)
                        ) & 0xFFFFF;
                    rCoeffs[2 * i + 1] =
                        (
                            (((a[5 * i + 2] & 0xFF) >> 4) |
                                ((a[5 * i + 3] & 0xFF) << 4)) |
                                ((a[5 * i + 4] & 0xFF) << 12)
                        ) & 0xFFFFF;

                    rCoeffs[2 * i + 0] = _rEngine.Gamma1 - rCoeffs[2 * i + 0];
                    rCoeffs[2 * i + 1] = _rEngine.Gamma1 - rCoeffs[2 * i + 1];
                }
            }
            else
                throw new ArgumentException("Wrong Dilithiumn Gamma1!");
        }

        internal void Decompose(Poly a)
        {
            int i;
            for (i = 0; i < _rN; ++i)
            {
                int[] decomp = RoundingUtility.Decompose(rCoeffs[i], _rEngine.Gamma2);

                a.rCoeffs[i] = decomp[0];
                rCoeffs[i] = decomp[1];
            }
        }

        internal void PackW1(byte[] r, int off)
        {
            int i;
            if (_rEngine.Gamma2 == (DilithiumEngine.Q - 1) / 88)
            {
                for (i = 0; i < _rN / 4; ++i)
                {
                    r[off + 3 * i + 0] = (byte)(((byte)rCoeffs[4 * i + 0]) | (rCoeffs[4 * i + 1] << 6));
                    r[off + 3 * i + 1] = (byte)((byte)(rCoeffs[4 * i + 1] >> 2) | (rCoeffs[4 * i + 2] << 4));
                    r[off + 3 * i + 2] = (byte)((byte)(rCoeffs[4 * i + 2] >> 4) | (rCoeffs[4 * i + 3] << 2));
                }
            }
            else if (_rEngine.Gamma2 == (DilithiumEngine.Q - 1) / 32)
            {
                for (i = 0; i < _rN / 2; ++i)
                    r[off + i] = (byte)(rCoeffs[2 * i + 0] | (rCoeffs[2 * i + 1] << 4));
            }
        }

        internal void Challenge(byte[] seed)
        {
            int i, b, pos;
            ulong signs;
            byte[] buf = new byte[_rSymmetric.rStream256BlockBytes];

            ShakeDigest ShakeDigest256 = new ShakeDigest(256);
            ShakeDigest256.BlockUpdate(seed, 0, DilithiumEngine.SeedBytes);
            ShakeDigest256.Output(buf, 0, _rSymmetric.rStream256BlockBytes);

            signs = 0;
            for (i = 0; i < 8; ++i)
                signs |= (ulong)(buf[i] & 0xFF) << 8 * i;

            pos = 8;

            for (i = 0; i < _rN; ++i)
                rCoeffs[i] = 0;

            for (i = _rN - _rEngine.Tau; i < _rN; ++i)
            {
                do
                {
                    if (pos >= _rSymmetric.rStream256BlockBytes)
                    {
                        ShakeDigest256.Output(buf, 0, _rSymmetric.rStream256BlockBytes);
                        pos = 0;
                    }

                    b = (buf[pos++] & 0xFF);
                }
                while (b > i);

                rCoeffs[i] = rCoeffs[b];
                rCoeffs[b] = (int)(1 - 2 * (signs & 1));
                signs >>= 1;
            }
        }

        internal bool CheckNorm(int B)
        {
            int i, t;

            if (B > (DilithiumEngine.Q - 1) / 8)
                return true;

            for (i = 0; i < _rN; ++i)
            {
                t = rCoeffs[i] >> 31;
                t = rCoeffs[i] - (t & 2 * rCoeffs[i]);

                if (t >= B)
                    return true;
            }

            return false;
        }

        internal int PolyMakeHint(Poly a0, Poly a1)
        {
            int i, s = 0;

            for (i = 0; i < _rN; ++i)
            {
                rCoeffs[i] = RoundingUtility.MakeHint(a0.rCoeffs[i], a1.rCoeffs[i], _rEngine);
                s += rCoeffs[i];
            }

            return s;
        }

        internal void PolyUseHint(Poly a, Poly h)
        {
            for (int i = 0; i < _rN; ++i)
                rCoeffs[i] = RoundingUtility.UseHint(a.rCoeffs[i], h.rCoeffs[i], _rEngine.Gamma2);
        }

        internal void ShiftLeft()
        {
            for (int i = 0; i < _rN; ++i)
                rCoeffs[i] <<= DilithiumEngine.D;
        }

        private static int _RejectUniform(int[] coeffs, int off, int len, byte[] buf, int buflen)
        {
            int ctr, pos;
            uint t;

            ctr = pos = 0;
            while (ctr < len && pos + 3 <= buflen)
            {
                t = (uint)(buf[pos++] & 0xFF);
                t |= (uint)(buf[pos++] & 0xFF) << 8;
                t |= (uint)(buf[pos++] & 0xFF) << 16;
                t &= 0x7FFFFF;

                if (t < DilithiumEngine.Q)
                    coeffs[off + ctr++] = (int)t;
            }

            return ctr;
        }

        private static int _RejectEta(int[] coeffs, int off, int len, byte[] buf, int buflen, int eta)
        {
            int ctr, pos;
            uint t0, t1;

            ctr = pos = 0;

            while (ctr < len && pos < buflen)
            {
                t0 = (uint)(buf[pos] & 0xFF) & 0x0F;
                t1 = (uint)(buf[pos++] & 0xFF) >> 4;

                if (eta == 2)
                {
                    if (t0 < 15)
                    {
                        t0 = t0 - (205 * t0 >> 10) * 5;
                        coeffs[off + ctr++] = (int)(2 - t0);
                    }

                    if (t1 < 15 && ctr < len)
                    {
                        t1 = t1 - (205 * t1 >> 10) * 5;
                        coeffs[off + ctr++] = (int)(2 - t1);
                    }
                }
                else if (eta == 4)
                {
                    if (t0 < 9)
                        coeffs[off + ctr++] = (int)(4 - t0);

                    if (t1 < 9 && ctr < len)
                        coeffs[off + ctr++] = (int)(4 - t1);
                }
            }

            return ctr;
        }
    }
}
