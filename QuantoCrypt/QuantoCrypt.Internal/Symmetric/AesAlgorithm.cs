using QuantoCrypt.Infrastructure.Symmetric;
using System.Security.Cryptography;
using System.Text;

namespace QuantoCrypt.Internal.Symmetric
{
    public class AesAlgorithm : ISymmetricAlgorithm
    {
        private byte[] _rKey;

        public AesAlgorithm(byte[] key) 
        {
            _rKey = key;
        }

        public byte[] Encrypt(byte[] plainText)
        {
            byte[] iv = new byte[16];
            byte[] result;

            using (Aes aes = Aes.Create())
            {
                aes.Key = _rKey;
                aes.IV = iv;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using MemoryStream memoryStream = new MemoryStream();
                using CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(Encoding.UTF8.GetString(plainText));
                }
                result = memoryStream.ToArray();
            }

            return result;
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            byte[] iv = new byte[16];

            using (Aes aes = Aes.Create())
            {
                aes.Key = _rKey;
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream encryptedStream = new MemoryStream(cipherText))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(encryptedStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var decryptedStream = new MemoryStream())
                        {
                            cryptoStream.CopyTo(decryptedStream);

                            return decryptedStream.ToArray();
                        }
                    }
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
