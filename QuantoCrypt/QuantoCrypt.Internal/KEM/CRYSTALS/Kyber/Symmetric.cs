using QuantoCrypt.Infrastructure.Common.BlockCipher;
using QuantoCrypt.Infrastructure.Common.Digest;
using QuantoCrypt.Infrastructure.Common.Parameters;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Implementations of the symmetric algos needed for Kyber.
    /// </summary>
    internal abstract class Symmetric
    {
        internal readonly int rXofBlockBytes;

        Symmetric(int xofBlockBytes)
        {
            rXofBlockBytes = xofBlockBytes;
        }

        internal abstract void Hash_h(byte[] output, byte[] input, int outOffset);
        internal abstract void Hash_g(byte[] output, byte[] input);
        internal abstract void XofAbsorb(byte[] seed, byte x, byte y);
        internal abstract void XofSqueezeBlocks(byte[] output, int outOffset, int outLen);
        internal abstract void Prf(byte[] output, byte[] key, byte nonce);
        internal abstract void Kdf(byte[] output, byte[] input);

        internal class ShakeSymmetric : Symmetric
        {
            private readonly ShakeDigest _rXof;
            private readonly Sha3Digest _rSha3Digest256;
            private readonly Sha3Digest _rSha3Digest512;
            private readonly ShakeDigest _rShakeDigest;

            internal ShakeSymmetric() : base(164)
            {
                _rXof = new ShakeDigest(128);
                _rShakeDigest = new ShakeDigest(256);
                _rSha3Digest256 = new Sha3Digest(256);
                _rSha3Digest512 = new Sha3Digest(512);
            }

            internal override void Hash_h(byte[] output, byte[] input, int outOffset)
            {
                _rSha3Digest256.BlockUpdate(input, 0, input.Length);
                _rSha3Digest256.DoFinal(output, outOffset);
            }

            internal override void Hash_g(byte[] output, byte[] input)
            {
                _rSha3Digest512.BlockUpdate(input, 0, input.Length);
                _rSha3Digest512.DoFinal(output, 0);
            }

            internal override void XofAbsorb(byte[] seed, byte x, byte y)
            {
                _rXof.Reset();
                byte[] buf = new byte[seed.Length + 2];
                Array.Copy(seed, 0, buf, 0, seed.Length);

                buf[seed.Length] = x;
                buf[seed.Length + 1] = y;

                _rXof.BlockUpdate(buf, 0, seed.Length + 2);
            }

            internal override void XofSqueezeBlocks(byte[] output, int outOffset, int outLen)
                => _rXof.Output(output, outOffset, outLen);

            internal override void Prf(byte[] output, byte[] seed, byte nonce)
            {
                byte[] extSeed = new byte[seed.Length + 1];

                Array.Copy(seed, 0, extSeed, 0, seed.Length);
                extSeed[seed.Length] = nonce;

                _rShakeDigest.BlockUpdate(extSeed, 0, extSeed.Length);
                _rShakeDigest.OutputFinal(output, 0, output.Length);
            }

            internal override void Kdf(byte[] output, byte[] input)
            {
                _rShakeDigest.BlockUpdate(input, 0, input.Length);
                _rShakeDigest.OutputFinal(output, 0, output.Length);
            }
        }

        internal class AesSymmetric : Symmetric
        {
            private readonly Sha256Digest _rSha256Digest;
            private readonly Sha512Digest _rSha512Digest;
            private readonly SicBlockCipher _rCipher;

            internal AesSymmetric() : base(64)
            {
                _rSha256Digest = new Sha256Digest();
                _rSha512Digest = new Sha512Digest();
                _rCipher = new SicBlockCipher(AesUtilities.CreateEngine());
            }

            internal override void Hash_h(byte[] output, byte[] input, int outOffset)
                => _DoDigest(_rSha256Digest, output, input, outOffset);

            internal override void Hash_g(byte[] output, byte[] input)
                => _DoDigest(_rSha512Digest, output, input, 0);

            internal override void XofAbsorb(byte[] key, byte x, byte y)
            {
                byte[] expnonce = new byte[12];
                expnonce[0] = x;
                expnonce[1] = y;

                ParametersWithIV kp = new ParametersWithIV(new KeyParameter(key, 0, 32), expnonce);
                _rCipher.Init(true, kp);
            }

            internal override void XofSqueezeBlocks(byte[] output, int outOffset, int outLen)
                => _Aes128(output, outOffset, outLen);

            internal override void Prf(byte[] output, byte[] key, byte nonce)
            {
                byte[] expnonce = new byte[12];
                expnonce[0] = nonce;

                ParametersWithIV kp = new ParametersWithIV(new KeyParameter(key, 0, 32), expnonce);
                _rCipher.Init(true, kp);

                _Aes128(output, 0, output.Length);
            }

            internal override void Kdf(byte[] output, byte[] input)
            {
                byte[] buf = new byte[32];
                _DoDigest(_rSha256Digest, buf, input, 0);

                Array.Copy(buf, 0, output, 0, output.Length);
            }

            private void _DoDigest(IDigest digest, byte[] output, byte[] input, int outOffset)
            {
                digest.BlockUpdate(input, 0, input.Length);
                digest.DoFinal(output, outOffset);
            }

            private void _Aes128(byte[] output, int offset, int size)
            {
                byte[] buf = new byte[size + offset];

                for (int i = 0; i < size; i += 16)
                    _rCipher.ProcessBlock(buf, i + offset, output, i + offset);
            }
        }
    }
}
