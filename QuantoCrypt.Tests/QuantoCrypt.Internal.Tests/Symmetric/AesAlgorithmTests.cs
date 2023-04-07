using FluentAssertions;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Internal.Tests.Symmetric
{
    public class AesAlgorithmTests
    {
        [Theory]
        [MemberData(nameof(AesAlgorithmParams))]
        public void AesAlgorithmExecutor(byte[] key, byte[] data)
        {
            AesAlgorithm service = new AesAlgorithm(key);

            var encrypted = service.Encrypt(data);

            var decrypted = service.Decrypt(encrypted);

            if (decrypted.Length != data.Length)
                data.Should().BeEquivalentTo(decrypted[..data.Length]);
            else
                data.Should().BeEquivalentTo(decrypted);
        }

        public static IEnumerable<object[]> AesAlgorithmParams()
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
