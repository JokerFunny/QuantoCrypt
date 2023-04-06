using QuantoCrypt.Infrastructure.Symmetric;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace QuantoCrypt.Internal.Symmetric
{
    public sealed class AesGcmAlgorithm : ISymmetricAlgorithm
    {
        private readonly AesGcm _rAesGcm;

        public AesGcmAlgorithm(byte[] key)
        {
            // Initialize AES implementation
            _rAesGcm = new AesGcm(key);
        }

        public byte[] Encrypt(byte[] plainBytes)
            => Encrypt(plainBytes.AsSpan());

        public byte[] Encrypt(Span<byte> plainBytes)
        {
            // Get parameter sizes
            int nonceSize = AesGcm.NonceByteSizes.MaxSize;
            int tagSize = AesGcm.TagByteSizes.MaxSize;
            int cipherSize = plainBytes.Length;

            // We write everything into one big array for easier encoding
            int encryptedDataLength = 4 + nonceSize + 4 + tagSize + cipherSize;
            Span<byte> encryptedData = encryptedDataLength < 1024 ? stackalloc byte[encryptedDataLength] : new byte[encryptedDataLength].AsSpan();

            // Copy parameters
            BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(0, 4), nonceSize);
            BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4), tagSize);
            var nonce = encryptedData.Slice(4, nonceSize);
            var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
            var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

            // Generate secure nonce
            RandomNumberGenerator.Fill(nonce);

            // Encrypt
            _rAesGcm.Encrypt(nonce, plainBytes, cipherBytes, tag);

            return encryptedData.ToArray();
        }

        public byte[] Decrypt(byte[] cipher)
        {
            // Decode
            Span<byte> encryptedData = cipher.AsSpan();

            // Extract parameter sizes
            int nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(0, 4));
            int tagSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4));
            int cipherSize = encryptedData.Length - 4 - nonceSize - 4 - tagSize;

            // Extract parameters
            var nonce = encryptedData.Slice(4, nonceSize);
            var tag = encryptedData.Slice(4 + nonceSize + 4, tagSize);
            var cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize);

            // Decrypt
            Span<byte> plainBytes = cipherSize < 1024 ? stackalloc byte[cipherSize] : new byte[cipherSize];
            _rAesGcm.Decrypt(nonce, cipherBytes, tag, plainBytes);

            return plainBytes.ToArray();
        }

        public void Dispose() => _rAesGcm.Dispose();
    }
}
