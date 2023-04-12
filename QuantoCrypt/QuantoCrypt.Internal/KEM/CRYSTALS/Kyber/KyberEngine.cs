using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Engine to work with Kyber.
    /// </summary>
    internal class KyberEngine
    {
        private SecureRandom _random;
        private readonly KyberIndCpa _rIndCpa;

        // Constant Parameters
        public const int N = 256;
        public const int Q = 3329;
        public const int QInv = 62209;
        public const int SymBytes = 32;
        public const int PolyBytes = 384;
        public const int Eta2 = 2;

        private const int SharedSecretBytes = 32;

        internal Symmetric Symmetric { get; private set; }

        // Parameters
        internal int K { get; private set; }
        internal int PolyVecBytes { get; private set; }
        internal int PolyCompressedBytes { get; private set; }
        internal int PolyVecCompressedBytes { get; private set; }
        internal int Eta1 { get; private set; }
        internal int IndCpaPublicKeyBytes { get; private set; }
        internal int IndCpaSecretKeyBytes { get; private set; }
        internal int IndCpaBytes { get; private set; }
        internal int PublicKeyBytes { get; private set; }
        internal int SecretKeyBytes { get; private set; }
        internal int CipherTextBytes { get; private set; }

        // Crypto
        internal int CryptoBytes { get; private set; }
        internal int CryptoSecretKeyBytes { get; private set; }
        internal int CryptoPublicKeyBytes { get; private set; }
        internal int CryptoCipherTextBytes { get; private set; }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="k">Use matrices and vectors of small dimension k × l over Zq[X]/(X^256 + 1) as a part of the SIS.</param>
        /// <param name="usingAes">If AES should be used.</param>
        internal KyberEngine(int k, bool usingAes)
        {
            K = k;
            switch (k)
            {
                case 2:
                    Eta1 = 3;
                    PolyCompressedBytes = 128;
                    PolyVecCompressedBytes = K * 320;
                    break;
                case 3:
                    Eta1 = 2;
                    PolyCompressedBytes = 128;
                    PolyVecCompressedBytes = K * 320;
                    break;
                case 4:
                    Eta1 = 2;
                    PolyCompressedBytes = 160;
                    PolyVecCompressedBytes = K * 352;
                    break;
            }

            PolyVecBytes = k * PolyBytes;
            IndCpaPublicKeyBytes = PolyVecBytes + SymBytes;
            IndCpaSecretKeyBytes = PolyVecBytes;
            IndCpaBytes = PolyVecCompressedBytes + PolyCompressedBytes;
            PublicKeyBytes = IndCpaPublicKeyBytes;
            SecretKeyBytes = IndCpaSecretKeyBytes + IndCpaPublicKeyBytes + 2 * SymBytes;
            CipherTextBytes = IndCpaBytes;

            // Define Crypto Params
            CryptoBytes = SharedSecretBytes;
            CryptoSecretKeyBytes = SecretKeyBytes;
            CryptoPublicKeyBytes = PublicKeyBytes;
            CryptoCipherTextBytes = CipherTextBytes;

            if (usingAes)
                Symmetric = new Symmetric.AesSymmetric();
            else
                Symmetric = new Symmetric.ShakeSymmetric();

            _rIndCpa = new KyberIndCpa(this);
        }

        internal void Init(SecureRandom random)
        {
            _random = random;
        }

        internal void GenerateKemKeyPair(out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk, out byte[] nonce)
        {
            byte[] pk, sk;
            _rIndCpa.GenerateKeyPair(out pk, out sk);
            s = ArrayUtilities.CopyOfRange(sk, 0, IndCpaSecretKeyBytes);

            hpk = new byte[32];
            Symmetric.Hash_h(hpk, pk, 0);

            nonce = new byte[SymBytes];
            _random.NextBytes(nonce);

            t = ArrayUtilities.CopyOfRange(pk, 0, IndCpaPublicKeyBytes - 32);
            rho = ArrayUtilities.CopyOfRange(pk, IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes);

        }

        internal void KemEncrypt(byte[] cipherText, byte[] sharedSecret, byte[] pk)
        {
            byte[] randBytes = new byte[SymBytes];
            byte[] buf = new byte[2 * SymBytes];
            byte[] kr = new byte[2 * SymBytes];

            _random.NextBytes(randBytes, 0, SymBytes);

            Symmetric.Hash_h(randBytes, randBytes, 0);
            Array.Copy(randBytes, 0, buf, 0, SymBytes);

            Symmetric.Hash_h(buf, pk, SymBytes);
            Symmetric.Hash_g(kr, buf);
            _rIndCpa.Encrypt(cipherText, ArrayUtilities.CopyOfRange(buf, 0, SymBytes), pk, ArrayUtilities.CopyOfRange(kr, SymBytes, 2 * SymBytes));
            Symmetric.Hash_h(kr, cipherText, SymBytes);

            Symmetric.Kdf(sharedSecret, kr);
        }

        internal void KemDecrypt(byte[] sharedSecret, byte[] cipherText, byte[] secretKey)
        {
            byte[] buf = new byte[2 * SymBytes], kr = new byte[2 * SymBytes], cmp = new byte[CipherTextBytes];
            byte[] pk = ArrayUtilities.CopyOfRange(secretKey, IndCpaSecretKeyBytes, secretKey.Length);
            _rIndCpa.Decrypt(buf, cipherText, secretKey);

            Array.Copy(secretKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);
            Symmetric.Hash_g(kr, buf);
            _rIndCpa.Encrypt(cmp, ArrayUtilities.CopyOf(buf, SymBytes), pk, ArrayUtilities.CopyOfRange(kr, SymBytes, kr.Length));

            bool fail = !ArrayUtilities.FixedTimeEquals(cipherText, cmp);
            Symmetric.Hash_h(kr, cipherText, SymBytes);

            _CMov(kr, ArrayUtilities.CopyOfRange(secretKey, SecretKeyBytes - SymBytes, SecretKeyBytes), SymBytes, fail);

            Symmetric.Kdf(sharedSecret, kr);
        }

        internal void RandomBytes(byte[] buf, int len)
            => _random.NextBytes(buf, 0, len);

        private void _CMov(byte[] r, byte[] x, int len, bool b)
        {
            if (b)
                Array.Copy(x, 0, r, 0, len);
            else
                Array.Copy(r, 0, r, 0, len);
        }
    }
}
