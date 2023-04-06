using BenchmarkDotNet.Attributes;
using FluentAssertions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using QuantoCrypt.Infrastructure.Common;
using QuantoCrypt.Internal.KEM.CRYSTALS.Kyber;
using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Benchmarks.KEM
{
    [MemoryDiagnoser]
    public class CRYSTALS_KyberBenchmark
    {
        private const int _testInputFileChuckSize = 6;

        private static TestDataInputBytes _sDefaultTestData = new TestDataInputBytes()
        {
            Seed = ArrayUtilities.HexStringToByteArrayOptimized("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1")
        };

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(KYBERInputParams))]
        public void KYBERExecutor(string name, Internal.KEM.CRYSTALS.Kyber.KyberParameters kyberParameters)
        {
            //byte[] seed = _sDefaultTestData.Seed;

            //NistSecureRandom random = new NistSecureRandom(seed, null);

            for (int i = 0; i < 10; i++)
            {
                SecureRandom random = new SecureRandom();

                Internal.KEM.CRYSTALS.Kyber.KyberKeyGenerationParameters genParam = new Internal.KEM.CRYSTALS.Kyber.KyberKeyGenerationParameters(random, kyberParameters);
                Internal.KEM.CRYSTALS.Kyber.KyberKeyPairGenerator kpGen = new Internal.KEM.CRYSTALS.Kyber.KyberKeyPairGenerator(genParam);

                // Generate keys and test.
                AsymmetricKeyPair ackp = kpGen.GenerateKeyPair();

                KyberPublicKey pubKey = (KyberPublicKey)ackp.Public;
                KyberPrivateKey privKey = (KyberPrivateKey)ackp.Private;

                // KEM Enc
                Internal.KEM.CRYSTALS.Kyber.KyberKemGenerator KyberEncCipher = new Internal.KEM.CRYSTALS.Kyber.KyberKemGenerator(random);
                Infrastructure.KEM.ISecretWithEncapsulation secWenc = KyberEncCipher.GenerateEncapsulated(pubKey);

                byte[] generated_cipher_text = secWenc.GetEncapsulation();
                byte[] secret = secWenc.GetSecret();

                // KEM Dec
                Internal.KEM.CRYSTALS.Kyber.KyberKemExtractor KyberDecCipher = new Internal.KEM.CRYSTALS.Kyber.KyberKemExtractor(privKey);
                byte[] dec_key = KyberDecCipher.ExtractSecret(generated_cipher_text);

                secret.Should().BeEquivalentTo(dec_key);
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(BouncyCastleKYBEREInputParams))]
        public void BouncyCastleKYBERExecutor(string name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters kyberParameters)
        {
            for (int i = 0; i < 10; i++)
            {
                Org.BouncyCastle.Security.SecureRandom random = new Org.BouncyCastle.Security.SecureRandom();

                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyPairGenerator kpGen = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyPairGenerator();
                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyGenerationParameters genParam = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKeyGenerationParameters(random, kyberParameters);

                // Generate keys and test.
                kpGen.Init(genParam);
                AsymmetricCipherKeyPair ackp = kpGen.GenerateKeyPair();

                KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)ackp.Public;
                KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)ackp.Private;

                // KEM Enc
                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemGenerator KyberEncCipher = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemGenerator(random);
                Org.BouncyCastle.Crypto.ISecretWithEncapsulation secWenc = KyberEncCipher.GenerateEncapsulated(pubParams);

                byte[] generated_cipher_text = secWenc.GetEncapsulation();
                byte[] secret = secWenc.GetSecret();

                // KEM Dec
                Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemExtractor KyberDecCipher = new Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberKemExtractor(privParams);
                byte[] dec_key = KyberDecCipher.ExtractSecret(generated_cipher_text);

                secret.Should().BeEquivalentTo(dec_key);
            }
        }

        public IEnumerable<object[]> KYBERInputParams()
        {
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512 };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768 };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024 };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512_AES.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER512_AES };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768_AES.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER768_AES };
            yield return new object[] { Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024_AES.Name, Internal.KEM.CRYSTALS.Kyber.KyberParameters.KYBER1024_AES };
        }

        public IEnumerable<object[]> BouncyCastleKYBEREInputParams()
        {
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512 };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768 };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024 };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512_aes.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber512_aes };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768_aes.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber768_aes };
            yield return new object[] { Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024_aes.Name, Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber.KyberParameters.kyber1024_aes };
        }

        /*[Benchmark]
        [ArgumentsSource(nameof(KYBER512InputParams))]
        public void KYBER512Executor(TestDataInput testData)
        {
            byte[] seed = ArrayUtilities.HexStringToByteArrayOptimized(testData.Seed);
            byte[] publicKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.PublicKey);
            byte[] privateKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.PrivateKey);
            byte[] ciphertext = ArrayUtilities.HexStringToByteArrayOptimized(testData.Ciphertext);
            byte[] sessionKey = ArrayUtilities.HexStringToByteArrayOptimized(testData.SessionKey);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            KyberParameters kyberparameters = KyberParameters.KYBER512;

            KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(random, kyberparameters);
            KyberKeyPairGenerator kpGen = new KyberKeyPairGenerator(genParam);

            // Generate keys and test.
            AsymmetricKeyPair ackp = kpGen.GenerateKeyPair();

            KyberPublicKey pubKey = (KyberPublicKey)ackp.Public;
            KyberPrivateKey privKey = (KyberPrivateKey)ackp.Private;

            publicKey.Should().BeEquivalentTo(pubKey.GetEncoded());
            privateKey.Should().BeEquivalentTo(privKey.GetEncoded());

            // KEM Enc
            KyberKemGenerator KyberEncCipher = new KyberKemGenerator(random);
            ISecretWithEncapsulation secWenc = KyberEncCipher.GenerateEncapsulated(pubKey);

            byte[] generated_cipher_text = secWenc.GetEncapsulation();
            byte[] secret = secWenc.GetSecret();
            ciphertext.Should().BeEquivalentTo(generated_cipher_text);
            sessionKey.Should().BeEquivalentTo(secret);

            // KEM Dec
            KyberKemExtractor KyberDecCipher = new KyberKemExtractor(privKey);
            byte[] dec_key = KyberDecCipher.ExtractSecret(generated_cipher_text);

            sessionKey.Should().BeEquivalentTo(dec_key);
        }*/

        /*public IEnumerable<TestDataInput> KYBER512InputParams()
        {
            string[] fileContent = File.ReadAllLines("Benchmarks\\TestData\\KYBER512.txt");

            var result = _GetTestData(fileContent);

            foreach (var item in result)
                yield return item;
        }

        private IEnumerable<TestDataInput> _GetTestData(string[] fileContent)
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
        }*/

        public class TestDataInputBytes
        {
            public byte[] Seed { get; set; }
        }
    }
}
