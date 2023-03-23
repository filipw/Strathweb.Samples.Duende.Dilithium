using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

public class DilithiumCredentials
{
    public DilithiumCredentials()
    {
        var random = new SecureRandom();
        var keyGenParameters = new DilithiumKeyGenerationParameters(random, DilithiumParameters.Dilithium3);
        var dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
        dilithiumKeyPairGenerator.Init(keyGenParameters);

        var keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();

        // get and view the keys
        PublicKey = (DilithiumPublicKeyParameters)keyPair.Public;
        PrivateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
        //KeyId = CryptoRandom.CreateUniqueId(16, CryptoRandom.OutputFormat.Hex)
        KeyId = BitConverter.ToString(SecureRandom.GetNextBytes(random, 16)).Replace("-", "");
    }

    public DilithiumPublicKeyParameters PublicKey { get; }
    public DilithiumPrivateKeyParameters PrivateKey { get; }
    public string KeyId { get; }
    public string Alg { get; } = "CRYDI3";
}