using FluentAssertions;
using QuantoCrypt.Common;
using QuantoCrypt.Common.Utilities;
using QuantoCrypt.Internal.Symmetric;
using System.Security.Cryptography;

namespace QuantoCrypt.Tests.Symmetric
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

        [Fact]
        public void AesGcmAlgorithm_Work_Over_500MB()
        {
            var random = new SecureRandom();
            byte[] textToProceed = random.GenerateSeed(524288000);

            for (int i = 0; i < 50; i++)
            {
                AesGcmAlgorithm service = new AesGcmAlgorithm(random.GenerateSeed(32));

                var encrypted = service.Encrypt(textToProceed);

                var decrypted = service.Decrypt(encrypted);
            }
        }

        [Fact]
        public void AesGcmAlgorithm_Encrypt_Work_Over_500MB()
        {
            var random = new SecureRandom();
            byte[] textToProceed = random.GenerateSeed(524288000);

            for (int i = 0; i < 50; i++)
            {
                AesGcmAlgorithm service = new AesGcmAlgorithm(random.GenerateSeed(32));

                var encrypted = service.Encrypt(textToProceed);
            }
        }

        [Theory]
        [InlineData(8)]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        [InlineData(128)]
        public async Task AesGcmAlgorithm_Work_Over_500MB_Parallel(int workerThreadsCount)
        {
            var random = new SecureRandom();
            byte[] textToProceed = random.GenerateSeed(524288000);

            for (int i = 0; i < 10; i++)
            {
                AesGcmAlgorithm service = new AesGcmAlgorithm(random.GenerateSeed(32));

                ThreadPool.SetMinThreads(workerThreadsCount, workerThreadsCount);
                ThreadPool.SetMaxThreads(workerThreadsCount, workerThreadsCount);

                List<byte[]> resultsOfAes = new();

                int chunkSize = textToProceed.Length / workerThreadsCount;

                var chunksToProceed = Enumerable.Range(0, workerThreadsCount).Select(el =>
                    _GetChunkToProceed(el, chunkSize, textToProceed, workerThreadsCount)).ToList();

                Task<byte[]>[] tasksToProceed = new Task<byte[]>[workerThreadsCount];

                for (int j = 0; j < chunksToProceed.Count; j++)
                {
                    var chuckTextToProceed = chunksToProceed[j];

                    tasksToProceed[j] = new Task<byte[]>(() => service.Encrypt(chuckTextToProceed));
                }
                foreach (var task in tasksToProceed)
                    task.Start();

                var results = await Task.WhenAll(tasksToProceed);

                for (int j = 0; j < results.Length; j++)
                    resultsOfAes.Add(results[j]);

                for (int j = 0; j < resultsOfAes.Count; j++)
                {
                    var chuckTextToProceed = resultsOfAes[j];

                    tasksToProceed[j] = new Task<byte[]>(() => service.Decrypt(chuckTextToProceed));
                }
                foreach (var task in tasksToProceed)
                    task.Start();

                results = await Task.WhenAll(tasksToProceed);

                resultsOfAes.Clear();
                for (int j = 0; j < results.Length; j++)
                    resultsOfAes.Add(results[j]);

                byte[] decrypted = ArrayUtilities.Combine(resultsOfAes.ToArray());
            }
        }

        static byte[] _GetChunkToProceed(int elementIndex, int chunkSize, byte[] textToProceed, int numberOfGrains)
        {
            IEnumerable<byte> chunk = textToProceed.Skip(chunkSize * elementIndex);

            return (elementIndex++ != numberOfGrains ? chunk.Take(chunkSize) : chunk).ToArray();
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
