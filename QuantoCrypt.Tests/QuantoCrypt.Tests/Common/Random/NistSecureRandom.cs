using QuantoCrypt.Common;
using QuantoCrypt.Common.BlockCipher;
using QuantoCrypt.Common.Parameters;

namespace QuantoCrypt.Tests.Common.Random
{
    /// <summary>
    /// Implementation of the <see cref="SecureRandom"/> to sutisfy NIST requirements and be able to work with postquantum algorithms.
    /// </summary>
    /// <remarks>
    ///     Needed for tests to get the same outpur by seed.
    /// </remarks>
    public class NistSecureRandom : SecureRandom
    {
        private readonly byte[] _rSeed;
        private readonly byte[] _rPersonalization;
        private byte[] _key;
        private byte[] _v;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="seed">Target seed to be used.</param>
        /// <param name="personalization">Target personalization.</param>
        public NistSecureRandom(byte[] seed, byte[] personalization)
            : base(null)
        {
            _rSeed = seed;
            _rPersonalization = personalization;
            _Init(256);
        }

        public override void NextBytes(byte[] buf)
            => NextBytes(buf, 0, buf.Length);

        public override void NextBytes(byte[] buf, int off, int len)
        {
            byte[] block = new byte[16];
            int i = 0;

            while (len > 0)
            {
                for (int j = 15; j >= 0; j--)
                {
                    if (++_v[j] != 0x00)
                        break;
                }

                _AES256_ECB(_key, _v, block, 0);

                if (len > 15)
                {
                    Array.Copy(block, 0, buf, off + i, block.Length);
                    i += 16;
                    len -= 16;
                }
                else
                {
                    Array.Copy(block, 0, buf, off + i, len);
                    len = 0;
                }
            }

            _AES256_CTR_DRBG_Update(null, _key, _v);
        }

        private void _Init(int strength)
            => _RandomBytesInit(_rSeed, _rPersonalization, strength);

        private void _AES256_ECB(byte[] _key, byte[] ctr, byte[] buffer, int startPosition)
        {
            try
            {
                IBlockCipher blockCipher = AesUtilities.CreateEngine();
                IBlockCipherMode blockCipherMode = EcbBlockCipher.GetBlockCipherMode(blockCipher);

                IBufferedCipher cipher = new BufferedBlockCipher(blockCipherMode);

                var keyParameter = new KeyParameter(_key, 0, _key.Length);
                cipher.Init(true, keyParameter);

                cipher.DoFinal(ctr, 0, ctr.Length, buffer, startPosition);
            }
            catch (Exception ex)
            {
                Console.Write(ex.StackTrace);
            }
        }

        private void _AES256_CTR_DRBG_Update(byte[] entropy_input, byte[] _key, byte[] _v)
        {
            byte[] tmp = new byte[48];

            for (int i = 0; i < 3; i++)
            {
                //increment V
                for (int j = 15; j >= 0; j--)
                {
                    if (++_v[j] != 0x00)
                        break;
                }

                _AES256_ECB(_key, _v, tmp, 16 * i);
            }

            if (entropy_input != null)
            {
                for (int i = 0; i < 48; i++)
                {
                    tmp[i] ^= entropy_input[i];
                }
            }

            Array.Copy(tmp, 0, _key, 0, _key.Length);
            Array.Copy(tmp, 32, _v, 0, _v.Length);
        }

        private void _RandomBytesInit(byte[] entropyInput, byte[] personalization, int strength)
        {
            byte[] seedMaterial = new byte[48];

            Array.Copy(entropyInput, 0, seedMaterial, 0, seedMaterial.Length);
            if (personalization != null)
            {
                for (int i = 0; i < 48; i++)
                {
                    seedMaterial[i] ^= personalization[i];
                }
            }

            _key = new byte[32];
            _v = new byte[16];

            _AES256_CTR_DRBG_Update(seedMaterial, _key, _v);
        }
    }
}
