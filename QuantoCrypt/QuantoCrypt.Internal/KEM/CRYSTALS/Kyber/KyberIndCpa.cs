using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Kyber’s IND-CPA-secure encryption - IND-CPA secure under the ModuleLWE hardness assumption.
    /// </summary>
    internal sealed class KyberIndCpa
    {
        private readonly KyberEngine _rKyberEngine;
        private readonly Symmetric _rSymmetric;

        internal KyberIndCpa(KyberEngine engine)
        {
            _rKyberEngine = engine;
            _rSymmetric = engine.Symmetric;
        }

        private int _GenerateMatrixNBlocks => ((12 * KyberEngine.N / 8 * (1 << 12) / KyberEngine.Q + _rSymmetric.rXofBlockBytes) / _rSymmetric.rXofBlockBytes);

        /// <summary>
        /// Encrypts target <paramref name="c"/> using provided params.
        /// </summary>
        /// <param name="c">Target ciphertext.</param>
        /// <param name="m">Target [KYBER_INDCPA_MSG] message.</param>
        /// <param name="pk">Target private key.</param>
        /// <param name="coins">Target noise coins.</param>
        public void Encrypt(byte[] c, byte[] m, byte[] pk, byte[] coins)
        {
            int K = _rKyberEngine.K;

            byte[] seed = new byte[KyberEngine.SymBytes];
            byte nonce = 0;
            PolyVec sp = new PolyVec(_rKyberEngine), pkpv = new PolyVec(_rKyberEngine), ep = new PolyVec(_rKyberEngine), bp = new PolyVec(_rKyberEngine);
            PolyVec[] MatrixTransposed = new PolyVec[K];
            Poly v = new Poly(_rKyberEngine), k = new Poly(_rKyberEngine), epp = new Poly(_rKyberEngine);

            _UnpackPublicKey(pkpv, seed, pk);

            k.FromMsg(m);

            for (int i = 0; i < K; i++)
                MatrixTransposed[i] = new PolyVec(_rKyberEngine);

            _GenerateMatrix(MatrixTransposed, seed, true);

            for (int i = 0; i < K; i++)
                sp.rVector[i].GetNoiseEta1(coins, nonce++);

            for (int i = 0; i < K; i++)
                ep.rVector[i].GetNoiseEta2(coins, nonce++);

            epp.GetNoiseEta2(coins, nonce++);

            sp.Ntt();

            for (int i = 0; i < K; i++)
                PolyVec.PointwiseAccountMontgomery(bp.rVector[i], MatrixTransposed[i], sp, _rKyberEngine);

            PolyVec.PointwiseAccountMontgomery(v, pkpv, sp, _rKyberEngine);

            bp.InverseNttToMont();

            v.PolyInverseNttToMont();

            bp.Add(ep);

            v.Add(epp);
            v.Add(k);

            bp.Reduce();
            v.PolyReduce();

            _PackCipherText(c, bp, v);
        }

        internal void GenerateKeyPair(out byte[] pk, out byte[] sk)
        {
            int K = _rKyberEngine.K;

            byte[] buf = new byte[2 * KyberEngine.SymBytes];
            byte nonce = 0;
            PolyVec[] Matrix = new PolyVec[K];
            PolyVec e = new PolyVec(_rKyberEngine), pkpv = new PolyVec(_rKyberEngine), skpv = new PolyVec(_rKyberEngine);

            byte[] d = new byte[32];
            _rKyberEngine.RandomBytes(d, 32);
            _rSymmetric.Hash_g(buf, d);

            byte[] PublicSeed = ArrayUtilities.CopyOfRange(buf, 0, KyberEngine.SymBytes);
            byte[] NoiseSeed = ArrayUtilities.CopyOfRange(buf, KyberEngine.SymBytes, 2 * KyberEngine.SymBytes);

            for (int i = 0; i < K; i++)
                Matrix[i] = new PolyVec(_rKyberEngine);

            _GenerateMatrix(Matrix, PublicSeed, false);

            for (int i = 0; i < K; i++)
                skpv.rVector[i].GetNoiseEta1(NoiseSeed, nonce++);

            for (int i = 0; i < K; i++)
                e.rVector[i].GetNoiseEta1(NoiseSeed, nonce++);

            skpv.Ntt();
            e.Ntt();

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(pkpv.rVector[i], Matrix[i], skpv, _rKyberEngine);
                pkpv.rVector[i].ToMont();
            }

            pkpv.Add(e);
            pkpv.Reduce();

            _PackSecretKey(out sk, skpv);
            _PackPublicKey(out pk, pkpv, PublicSeed);
        }

        internal void Decrypt(byte[] m, byte[] c, byte[] sk)
        {
            PolyVec bp = new PolyVec(_rKyberEngine), skpv = new PolyVec(_rKyberEngine);
            Poly v = new Poly(_rKyberEngine), mp = new Poly(_rKyberEngine);

            _UnpackCipherText(bp, v, c);
            _UnpackSecretKey(skpv, sk);

            bp.Ntt();

            PolyVec.PointwiseAccountMontgomery(mp, skpv, bp, _rKyberEngine);

            mp.PolyInverseNttToMont();
            mp.Subtract(v);
            mp.PolyReduce();
            mp.ToMsg(m);
        }

        private void _GenerateMatrix(PolyVec[] a, byte[] seed, bool transposed)
        {
            int K = _rKyberEngine.K;

            byte[] buf = new byte[_GenerateMatrixNBlocks * _rSymmetric.rXofBlockBytes + 2];
            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < K; j++)
                {
                    if (transposed)
                        _rSymmetric.XofAbsorb(seed, (byte)i, (byte)j);
                    else
                        _rSymmetric.XofAbsorb(seed, (byte)j, (byte)i);

                    _rSymmetric.XofSqueezeBlocks(buf, 0, _GenerateMatrixNBlocks * _rSymmetric.rXofBlockBytes);
                    int buflen = _GenerateMatrixNBlocks * _rSymmetric.rXofBlockBytes;
                    int ctr = _RejectionSampling(a[i].rVector[j].Coeffs, 0, KyberEngine.N, buf, buflen);

                    while (ctr < KyberEngine.N)
                    {
                        int off = buflen % 3;
                        for (int k = 0; k < off; k++)
                            buf[k] = buf[buflen - off + k];

                        _rSymmetric.XofSqueezeBlocks(buf, off, _rSymmetric.rXofBlockBytes * 2);
                        buflen = off + _rSymmetric.rXofBlockBytes;
                        ctr += _RejectionSampling(a[i].rVector[j].Coeffs, ctr, KyberEngine.N - ctr, buf, buflen);
                    }
                }
            }

            return;
        }

        private int _RejectionSampling(short[] r, int off, int len, byte[] buf, int buflen)
        {
            int ctr = 0, pos = 0;
            while (ctr < len && pos + 3 <= buflen)
            {
                ushort val0 = (ushort)((((ushort)(buf[pos + 0] & 0xFF) >> 0) | ((ushort)(buf[pos + 1] & 0xFF) << 8)) & 0xFFF);
                ushort val1 = (ushort)((((ushort)(buf[pos + 1] & 0xFF) >> 4) | ((ushort)(buf[pos + 2] & 0xFF) << 4)) & 0xFFF);
                pos += 3;

                if (val0 < KyberEngine.Q)
                    r[off + ctr++] = (short)val0;

                if (ctr < len && val1 < KyberEngine.Q)
                    r[off + ctr++] = (short)val1;
            }

            return ctr;
        }

        private void _PackSecretKey(out byte[] sk, PolyVec skpv)
        {
            sk = new byte[_rKyberEngine.PolyVecBytes];
            skpv.ToBytes(sk);
        }

        private void _UnpackSecretKey(PolyVec skpv, byte[] sk)
            => skpv.FromBytes(sk);

        private void _PackPublicKey(out byte[] pk, PolyVec pkpv, byte[] seed)
        {
            pk = new byte[_rKyberEngine.IndCpaPublicKeyBytes];
            pkpv.ToBytes(pk);

            Array.Copy(seed, 0, pk, _rKyberEngine.PolyVecBytes, KyberEngine.SymBytes);
        }

        private void _UnpackPublicKey(PolyVec pkpv, byte[] seed, byte[] pk)
        {
            pkpv.FromBytes(pk);
            Array.Copy(pk, _rKyberEngine.PolyVecBytes, seed, 0, KyberEngine.SymBytes);
        }

        private void _PackCipherText(byte[] r, PolyVec b, Poly v)
        {
            b.CompressPolyVec(r);
            v.CompressPoly(r, _rKyberEngine.PolyVecCompressedBytes);
        }

        private void _UnpackCipherText(PolyVec b, Poly v, byte[] c)
        {
            b.DecompressPolyVec(c);
            v.DecompressPoly(c, _rKyberEngine.PolyVecCompressedBytes);
        }
    }
}
