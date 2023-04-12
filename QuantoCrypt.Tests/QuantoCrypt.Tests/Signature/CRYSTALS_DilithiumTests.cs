using FluentAssertions;
using QuantoCrypt.Common;
using QuantoCrypt.Common.Utilities;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium;
using QuantoCrypt.Tests.Common.Random;

namespace QuantoCrypt.Tests.Signature
{
    public class CRYSTALS_DilithiumTests
    {
        private const int _testInputFileChuckSize = 6;

        [Theory]
        [MemberData(nameof(DILITHIUM2InputParams))]
        public void DILITHIUM2Executor(TestDataInput testData)
        {
            DilithiumParameters dilithiumParameters = DilithiumParameters.DILITHIUM2;

            _ExecuteTest(testData, dilithiumParameters);
        }

        [Theory]
        [MemberData(nameof(DILITHIUM3InputParams))]
        public void DILITHIUM3Executor(TestDataInput testData)
        {
            DilithiumParameters dilithiumParameters = DilithiumParameters.DILITHIUM3;

            _ExecuteTest(testData, dilithiumParameters);
        }

        [Theory]
        [MemberData(nameof(DILITHIUM5InputParams))]
        public void DILITHIUM5Executor(TestDataInput testData)
        {
            DilithiumParameters dilithiumParameters = DilithiumParameters.DILITHIUM5;

            _ExecuteTest(testData, dilithiumParameters);
        }

        [Theory]
        [MemberData(nameof(DILITHIUM2_AESInputParams))]
        public void DILITHIUM2_AESExecutor(TestDataInput testData)
        {
            DilithiumParameters dilithiumParameters = DilithiumParameters.DILITHIUM2_AES;

            _ExecuteTest(testData, dilithiumParameters);
        }

        [Theory]
        [MemberData(nameof(DILITHIUM3_AESInputParams))]
        public void DILITHIUM3_AESExecutor(TestDataInput testData)
        {
            DilithiumParameters dilithiumParameters = DilithiumParameters.DILITHIUM3_AES;

            _ExecuteTest(testData, dilithiumParameters);
        }

        [Theory]
        [MemberData(nameof(DILITHIUM5_AESInputParams))]
        public void DILITHIUM5_AESExecutor(TestDataInput testData)
        {
            DilithiumParameters dilithiumParameters = DilithiumParameters.DILITHIUM5_AES;

            _ExecuteTest(testData, dilithiumParameters);
        }

        [Theory]
        [MemberData(nameof(DILITHIUMInputParams))]
        public void DilithiumAlgorithmxecutor(DilithiumParameters dilithiumParameters)
        {
            SecureRandom random = new SecureRandom();
            byte[] message = random.GenerateSeed(512);

            DilithiumAlgorithm dilithiumAlgorithmForSign = new DilithiumAlgorithm(dilithiumParameters, true);

            // Generate keys and test.
            AsymmetricKeyPair generatedKeyPair = dilithiumAlgorithmForSign.KeyGen();

            DilithiumPublicKey pubKey = (DilithiumPublicKey)generatedKeyPair.Public;
            DilithiumPrivateKey privKey = (DilithiumPrivateKey)generatedKeyPair.Private;

            // Sign message.
            byte[] signature = dilithiumAlgorithmForSign.Sign(message);

            // Verify message.
            DilithiumAlgorithm dilithiumAlgorithmForVerify = new DilithiumAlgorithm(dilithiumParameters, false);

            byte[] publicKey = pubKey.GetEncoded();
            bool successfullyVerified = dilithiumAlgorithmForVerify.Verify(publicKey, message, signature);

            // changing the signature by 1 byte should cause it to fail.
            signature[3]++;
            bool failedToVerify = dilithiumAlgorithmForVerify.Verify(publicKey, message, signature);

            successfullyVerified.Should().BeTrue();
            failedToVerify.Should().BeFalse();
        }

        private void _ExecuteTest(TestDataInput testData, DilithiumParameters dilithiumParameters)
        {
            byte[] seed = ArrayUtilities.HexStringToByteArrayOptimized(testData.Seed);
            byte[] message = ArrayUtilities.HexStringToByteArrayOptimized(testData.Message);
            byte[] publicKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.PublicKey);
            byte[] privateKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.PrivateKey);
            byte[] attachedSignature = ArrayUtilities.HexStringToByteArrayOptimized(testData.AttachedSignature);

            NistSecureRandom random = new NistSecureRandom(seed, null);

            DilithiumKeyGenerationParameters keyGenerationParameters = new DilithiumKeyGenerationParameters(random, dilithiumParameters);
            DilithiumKeyPairGenerator keyPairGenerator = new DilithiumKeyPairGenerator(keyGenerationParameters);

            // Generate keys and test.
            AsymmetricKeyPair generatedKeyPair = keyPairGenerator.GenerateKeyPair();

            DilithiumPublicKey pubKey = (DilithiumPublicKey)generatedKeyPair.Public;
            DilithiumPrivateKey privKey = (DilithiumPrivateKey)generatedKeyPair.Private;

            publicKey.Should().BeEquivalentTo(pubKey.GetEncoded());
            privateKey.Should().BeEquivalentTo(privKey.GetEncoded());

            // Generate signature.
            DilithiumSigner signer = new DilithiumSigner(true, privKey);
            byte[] generatedSignature = signer.GenerateSignature(message);
            byte[] generatedSignatureWithAttachedMessage = ArrayUtilities.Combine(generatedSignature, message);

            generatedSignatureWithAttachedMessage.Should().BeEquivalentTo(attachedSignature);

            // Verify generated signature.
            DilithiumSigner verifier = new DilithiumSigner(false, pubKey);
            bool successfullyVerified = verifier.VerifySignature(message, generatedSignature);

            // changing the signature by 1 byte should cause it to fail.
            generatedSignature[3]++;
            bool failedToVerify = verifier.VerifySignature(message, generatedSignature);

            successfullyVerified.Should().BeTrue();
            failedToVerify.Should().BeFalse();
        }
        
        public static IEnumerable<object[]> DILITHIUM2InputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\DILITHIUM\\DILITHIUM2.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }
        
        public static IEnumerable<object[]> DILITHIUM3InputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\DILITHIUM\\DILITHIUM3.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }
        
        public static IEnumerable<object[]> DILITHIUM5InputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\DILITHIUM\\DILITHIUM5.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }

        public static IEnumerable<object[]> DILITHIUM2_AESInputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\DILITHIUM\\DILITHIUM2_AES.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }

        public static IEnumerable<object[]> DILITHIUM3_AESInputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\DILITHIUM\\DILITHIUM3_AES.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }

        public static IEnumerable<object[]> DILITHIUM5_AESInputParams()
        {
            string[] fileContent = File.ReadAllLines("TestData\\DILITHIUM\\DILITHIUM5_AES.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return new object[] { item };
        }

        public static IEnumerable<object[]> DILITHIUMInputParams()
        {
            yield return new object[] { DilithiumParameters.DILITHIUM2 };
            yield return new object[] { DilithiumParameters.DILITHIUM3 };
            yield return new object[] { DilithiumParameters.DILITHIUM5 };
            yield return new object[] { DilithiumParameters.DILITHIUM2_AES };
            yield return new object[] { DilithiumParameters.DILITHIUM3_AES };
            yield return new object[] { DilithiumParameters.DILITHIUM5_AES };
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
                        testDataInput.Message = fileContent[i + j];
                    else if (j == 2)
                        testDataInput.PublicKey = fileContent[i + j];
                    else if (j == 3)
                        testDataInput.PrivateKey = fileContent[i + j];
                    else if (j == 4)
                        testDataInput.AttachedSignature = fileContent[i + j];
                    else
                        result.Add(testDataInput);
                }
            }

            return result;
        }

        public class TestDataInput
        {
            public string Seed { get; set; }
            public string Message { get; set; }
            public string PublicKey { get; set; }
            public string PrivateKey { get; set; }
            public string AttachedSignature { get; set; }
        }
    }
}
