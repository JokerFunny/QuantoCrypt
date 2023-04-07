using QuantoCrypt.Infrastructure.Symmetric;
using System.Security.Cryptography;

namespace QuantoCrypt.Internal.Symmetric
{
    /// <summary>
    /// Implementation of the <see cref="ISymmetricAlgorithm"/> that work over <see cref="Aes"/>.
    /// </summary>
    /// <remarks>
    ///     Uses <see cref="CipherMode.CBC"/>, decrypt fix message size in case if it is not x*16 length.
    /// </remarks>
    public sealed class AesAlgorithm : ISymmetricAlgorithm
    {
        private byte[] _rKey;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="key">Target key.</param>
        /// <remarks>
        ///     <paramref name="key"/> should be 16, 24 or 32 bytes.
        /// </remarks>
        public AesAlgorithm(byte[] key) 
        {
            _rKey = key;
        }

        public byte[] Encrypt(byte[] plainText)
        {
            // fix message size.
            if (plainText.Length % 16 != 0) 
            {
                int targetLength = plainText.Length + plainText.Length % 16;
                Span<byte> data = targetLength <= 128
                    ? stackalloc byte[targetLength]
                    : new byte[targetLength];

                plainText.CopyTo(data);

                plainText = data.ToArray();
            }

            using (Aes aes = Aes.Create())
            {
                aes.Padding = PaddingMode.Zeros;
                aes.Key = _rKey;
                aes.IV = new byte[16];

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using MemoryStream memoryStream = new MemoryStream();
                using CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                {
                    cryptoStream.Write(plainText, 0, plainText.Length);
                    cryptoStream.FlushFinalBlock();

                    return memoryStream.ToArray();
                }
            }
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Padding = PaddingMode.Zeros;
                aes.Key = _rKey;
                aes.IV = new byte[16];

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using MemoryStream memoryStream = new MemoryStream();
                using CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write);
                {
                    cryptoStream.Write(cipherText, 0, cipherText.Length);
                    cryptoStream.FlushFinalBlock();

                    return memoryStream.ToArray();
                }
            }
        }

        public void Dispose()
        {
            _rKey = null;

            GC.SuppressFinalize(this);
        }
    }
}
