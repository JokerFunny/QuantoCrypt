using QuantoCrypt.Infrastructure.Common.BlockCipher;
using QuantoCrypt.Infrastructure.Common.Digest;
using QuantoCrypt.Infrastructure.Common.Parameters;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Implementations of the symmetric algos needed for Dilithium.
    /// </summary>
    internal abstract class Symmetric
    {
        public readonly int rStream128BlockBytes;
        public readonly int rStream256BlockBytes;

        Symmetric(int stream128, int stream256)
        {
            rStream128BlockBytes = stream128;
            rStream256BlockBytes = stream256;
        }

        internal abstract void Stream128Init(byte[] seed, ushort nonce);
        internal abstract void Stream256Init(byte[] seed, ushort nonce);
        internal abstract void Stream128SqueezeBlocks(byte[] output, int offset, int size);
        internal abstract void Stream256SqueezeBlocks(byte[] output, int offset, int size);

        internal class ShakeSymmetric : Symmetric
        {
            private readonly ShakeDigest _rShakeDigest128;
            private readonly ShakeDigest _rShakeDigest256;

            public ShakeSymmetric() : base(168, 136)
            {
                _rShakeDigest128 = new ShakeDigest(128);
                _rShakeDigest256 = new ShakeDigest(256);
            }

            internal override void Stream128Init(byte[] seed, ushort nonce)
                => _StreamInit(_rShakeDigest128, seed, nonce);

            internal override void Stream256Init(byte[] seed, ushort nonce)
                => _StreamInit(_rShakeDigest256, seed, nonce);

            internal override void Stream128SqueezeBlocks(byte[] output, int offset, int size)
                => _rShakeDigest128.Output(output, offset, size);

            internal override void Stream256SqueezeBlocks(byte[] output, int offset, int size)
                => _rShakeDigest256.Output(output, offset, size);

            private void _StreamInit(ShakeDigest digest, byte[] seed, ushort nonce)
            {
                digest.Reset();
                byte[] temp = new byte[2];
                temp[0] = (byte)nonce;
                temp[1] = (byte)(nonce >> 8);

                digest.BlockUpdate(seed, 0, seed.Length);
                digest.BlockUpdate(temp, 0, temp.Length);
            }
        }

        internal class AesSymmetric : Symmetric
        {
            private readonly SicBlockCipher _rCipher;

            public AesSymmetric() : base(64, 64)
            {
                _rCipher = new SicBlockCipher(AesUtilities.CreateEngine());
            }

            internal override void Stream128Init(byte[] seed, ushort nonce)
                => _StreamInit(seed, nonce);

            internal override void Stream256Init(byte[] seed, ushort nonce)
                => _StreamInit(seed, nonce);

            internal override void Stream128SqueezeBlocks(byte[] output, int offset, int size)
                => _Aes128(output, offset, size);

            internal override void Stream256SqueezeBlocks(byte[] output, int offset, int size)
                => _Aes128(output, offset, size);

            private void _Aes128(byte[] output, int offset, int size)
            {
                byte[] buf = new byte[size];

                for (int i = 0; i < size; i += 16)
                    _rCipher.ProcessBlock(buf, i + offset, output, i + offset);
            }

            private void _StreamInit(byte[] key, ushort nonce)
            {
                byte[] expnonce = new byte[12];
                expnonce[0] = (byte)nonce;
                expnonce[1] = (byte)(nonce >> 8);

                ParametersWithIV kp = new ParametersWithIV(new KeyParameter(key, 0, 32), expnonce);
                _rCipher.Init(true, kp);
            }
        }
    }
}
