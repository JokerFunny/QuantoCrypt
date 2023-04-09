using FluentAssertions;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.Symmetric;
using System.Security.Cryptography;

namespace QuantoCrypt.Internal.Tests.Symmetric
{
    public class AesGcmAlgorithmTests
    {
        [Theory]
        [MemberData(nameof(InvalidKeysParams))]
        public void AesGcmAlgorithm_Should_Throw_On_Incorrect_Key_Size(byte[] key)
        {
            Action incorrectKeySizeCreation = () => new AesGcmAlgorithm(key);
            incorrectKeySizeCreation.Should().Throw<CryptographicException>().WithMessage("*Specified key is not a valid size for this algorithm.*");
        }

        [Theory]
        [MemberData(nameof(AesGcmAlgorithmParams))]
        public void AesGcmAlgorithmExecutor(byte[] key, byte[] data)
        {
            AesGcmAlgorithm service = new AesGcmAlgorithm(key);

            var encrypted = service.Encrypt(data);

            var decrypted = service.Decrypt(encrypted);

            data.Should().BeEquivalentTo(decrypted);
        }

        public static IEnumerable<object[]> InvalidKeysParams()
        {
            for (int i = 1; i < 100; i += 4)
                yield return new object[] { new byte[i] };
        }

        public static IEnumerable<object[]> AesGcmAlgorithmParams()
        {
            SecureRandom secureRandom = new SecureRandom();
            int lengthMultiplicator = 16;

            List<Tuple<byte[], byte[]>> data = new();
            byte[] key, testData;
            for (int i = 0; i < 3; i++)
            {
                key = secureRandom.GenerateSeed(lengthMultiplicator);

                for (int j = 0; j < 30; j++)
                {
                    testData = secureRandom.GenerateSeed(lengthMultiplicator * (j + 1));

                    data.Add(new Tuple<byte[], byte[]>(key, testData));
                }

                lengthMultiplicator += 8;
            }

            foreach (var item in data)
                yield return new object[] { item.Item1, item.Item2 };
        }
    }
}
