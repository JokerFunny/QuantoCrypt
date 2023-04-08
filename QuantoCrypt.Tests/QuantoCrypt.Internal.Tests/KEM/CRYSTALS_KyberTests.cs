using FluentAssertions;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Internal.KEM.CRYSTALS.Kyber;
using QuantoCrypt.Internal.Tests.Common.Random;
using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Internal.Tests.KEM
{
    public class CRYSTALS_KyberTests
    {
        private const int _testInputFileChuckSize = 6;

        [Theory]
        [MemberData(nameof(KYBER512InputParams))]
        public void KYBER512Executor(TestDataInput testData)
        {
            KyberParameters kyberparameters = KyberParameters.KYBER512;

            _ExecuteTest(testData, kyberparameters);
        }

        [Theory]
        [MemberData(nameof(KYBER768InputParams))]
        public void KYBER768Executor(TestDataInput testData)
        {
            KyberParameters kyberparameters = KyberParameters.KYBER768;

            _ExecuteTest(testData, kyberparameters);
        }

        [Theory]
        [MemberData(nameof(KYBER1024InputParams))]
        public void KYBER1024Executor(TestDataInput testData)
        {
            KyberParameters kyberparameters = KyberParameters.KYBER1024;

            _ExecuteTest(testData, kyberparameters);
        }

        [Theory]
        [MemberData(nameof(KYBER512_AESInputParams))]
        public void KYBER512_AESExecutor(TestDataInput testData)
        {
            KyberParameters kyberparameters = KyberParameters.KYBER512_AES;

            _ExecuteTest(testData, kyberparameters);
        }

        [Theory]
        [MemberData(nameof(KYBER768_AESInputParams))]
        public void KYBER768_AESExecutor(TestDataInput testData)
        {
            KyberParameters kyberparameters = KyberParameters.KYBER768_AES;

            _ExecuteTest(testData, kyberparameters);
        }

        [Theory]
        [MemberData(nameof(KYBER1024_AESInputParams))]
        public void KYBER1024_AESExecutor(TestDataInput testData)
        {
            KyberParameters kyberparameters = KyberParameters.KYBER1024_AES;

            _ExecuteTest(testData, kyberparameters);
        }

        [Theory]
        [MemberData(nameof(KYBERInputParams))]
        public void KyberAlgorithmxecutor(KyberParameters kyberParams)
        {
            KyberAlgorithm kyberAlgorithm = new KyberAlgorithm(kyberParams);

            // Generate keys and test.
            AsymmetricKeyPair generatedKeyPair = kyberAlgorithm.KeyGen();

            KyberPublicKey pubKey = (KyberPublicKey)generatedKeyPair.Public;
            KyberPrivateKey privKey = (KyberPrivateKey)generatedKeyPair.Private;

            // KEM Enc
            ISecretWithEncapsulation secretWithIncapsulation = kyberAlgorithm.Encaps(pubKey.GetEncoded());

            byte[] generatedCipherText = secretWithIncapsulation.GetEncapsulation();
            byte[] secret = secretWithIncapsulation.GetSecret();

            // KEM Dec
            byte[] decriptedSecret = kyberAlgorithm.Decaps(generatedCipherText);

            secret.Should().BeEquivalentTo(decriptedSecret);
        }

        private void _ExecuteTest(TestDataInput testData, KyberParameters kyberParameters)
        {
            byte[] seed = ArrayUtilities.HexStringToByteArrayOptimized(testData.Seed);
            byte[] publicKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.PublicKey);
            byte[] privateKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.PrivateKey);
            byte[] ciphertext = ArrayUtilities.HexStringToByteArrayOptimized(testData.Ciphertext);
            byte[] sessionKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.SessionKey);

            NistSecureRandom random = new NistSecureRandom(seed, null);

            KyberKeyGenerationParameters keyGenerationParameters = new KyberKeyGenerationParameters(random, kyberParameters);
            KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator(keyGenerationParameters);

            // Generate keys and test.
            AsymmetricKeyPair generatedKeyPair = keyPairGenerator.GenerateKeyPair();

            KyberPublicKey pubKey = (KyberPublicKey)generatedKeyPair.Public;
            KyberPrivateKey privKey = (KyberPrivateKey)generatedKeyPair.Private;

            publicKey.Should().BeEquivalentTo(pubKey.GetEncoded());
            privateKey.Should().BeEquivalentTo(privKey.GetEncoded());

            // KEM Enc
            KyberKemGenerator kemGenerator = new KyberKemGenerator(random);
            ISecretWithEncapsulation secretWithIncapsulation = kemGenerator.GenerateEncapsulated(pubKey);

            byte[] generatedCipherText = secretWithIncapsulation.GetEncapsulation();
            byte[] secret = secretWithIncapsulation.GetSecret();
            ciphertext.Should().BeEquivalentTo(generatedCipherText);
            sessionKey.Should().BeEquivalentTo(secret);

            // KEM Dec
            KyberKemExtractor kemExtractor = new KyberKemExtractor(privKey);
            byte[] decriptedSessionKey = kemExtractor.ExtractSecret(generatedCipherText);

            sessionKey.Should().BeEquivalentTo(decriptedSessionKey);
        }
        
        public static IEnumerable<object[]> KYBER512InputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\KYBER\\KYBER512.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }
        
        public static IEnumerable<object[]> KYBER768InputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\KYBER\\KYBER768.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }
        
        public static IEnumerable<object[]> KYBER1024InputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\KYBER\\KYBER1024.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }
        
        public static IEnumerable<object[]> KYBER512_AESInputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\KYBER\\KYBER512_AES.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }
        
        public static IEnumerable<object[]> KYBER768_AESInputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\KYBER\\KYBER768_AES.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }
        
        public static IEnumerable<object[]> KYBER1024_AESInputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\KYBER\\KYBER1024_AES.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }

        public static IEnumerable<object[]> KYBERInputParams()
        {
            yield return new object[] { KyberParameters.KYBER512 }; 
            yield return new object[] { KyberParameters.KYBER768 }; 
            yield return new object[] { KyberParameters.KYBER1024 }; 
            yield return new object[] { KyberParameters.KYBER512_AES };
            yield return new object[] { KyberParameters.KYBER768_AES };
            yield return new object[] { KyberParameters.KYBER1024_AES };
        }

        private static IEnumerable<TestDataInput> _GetTestData(string[] fileContent)
        {
            var result = new List<TestDataInput>();

            if (fileContent.Length < 1 || (fileContent.Length + 1) % _testInputFileChuckSize != 0)
                throw new ArgumentException("Input file has incorrect structure!");

            TestDataInput testDataInput = new TestDataInput();
            for (int i = 0; i < fileContent.Length; i += _testInputFileChuckSize)
            {
                for (int j = 0; j < _testInputFileChuckSize; j++)
                {
                    if (j == 0)
                    {
                        testDataInput = new TestDataInput();
                        testDataInput.Seed = fileContent[i + j];
                    }
                    else if (j == 1)
                        testDataInput.PublicKey = fileContent[i + j];
                    else if (j == 2)
                        testDataInput.PrivateKey = fileContent[i + j];
                    else if (j == 3)
                        testDataInput.Ciphertext = fileContent[i + j];
                    else if (j == 4)
                        testDataInput.SessionKey = fileContent[i + j];
                    else
                        result.Add(testDataInput);
                }
            }

            return result;
        }

        public class TestDataInput
        {
            public string Seed { get; set; }
            public string PublicKey { get; set; }
            public string PrivateKey { get; set; }
            public string Ciphertext { get; set; }
            public string SessionKey { get; set; }
        }
    }
}
