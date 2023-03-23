using System.Text;
using IdentityModel;
using IdentityModel.Client;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;

var client = new HttpClient();

var req = new ClientCredentialsTokenRequest
{
    Address = "https://localhost:5001/connect/token",
    ClientId = "client",
    ClientSecret = "secret"
};

var token = await client.RequestClientCredentialsTokenAsync(req);
Console.WriteLine($"Fetched Access Token:");
Console.WriteLine($"{token.AccessToken}{Environment.NewLine}{Environment.NewLine}");

var jsonWebKeySetResponse = await client.GetJsonWebKeySetAsync("https://localhost:5001/.well-known/openid-configuration/jwks");

Console.WriteLine($"Fetched JSON web keys:");
foreach (var key in jsonWebKeySetResponse.KeySet.Keys)
{
    Console.WriteLine($"kid: {key.Kid}");
    Console.WriteLine($"alg: {key.Alg}");
    Console.WriteLine($"x: {key.X}");
    Console.WriteLine($"kty: {key.Kty}");
    Console.WriteLine();
}

// verify signature
// parts 1+2 are what was signed, part 3 is the signature
var splitToken = token.AccessToken.Split('.');
if (splitToken.Length != 3) {
    throw new Exception("Invalid JWT token length!");
}

var signer = new DilithiumSigner();
var encodedKey = jsonWebKeySetResponse.KeySet.Keys.FirstOrDefault(k => k.Alg == "CRYDI3")?.X ?? throw new Exception("No CRYDI3 key found in JWKS!");

var publicKey = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium3, Base64Url.Decode(encodedKey));

signer.Init(false, publicKey);

var jwt = $"{splitToken[0]}.{splitToken[1]}";
Console.WriteLine($"Validating: {jwt}");
var verified = signer.VerifySignature(Encoding.UTF8.GetBytes(jwt), Base64Url.Decode(splitToken[2]));
Console.WriteLine($"Successfully verified? {verified}");
Console.WriteLine("");