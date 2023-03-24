using System.IdentityModel.Tokens.Jwt;
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
Console.WriteLine($"Fetched Access Token!");
Console.WriteLine($"{token.AccessToken}");
Console.WriteLine();

var parsedToken = new JwtSecurityToken(token.AccessToken);
var jsonWebKeySetResponse = await client.GetJsonWebKeySetAsync("https://localhost:5001/.well-known/openid-configuration/jwks");
var key = jsonWebKeySetResponse.KeySet.Keys.FirstOrDefault(k => k.Kid == parsedToken.Header["kid"]?.ToString()) ?? throw new Exception("No matching key found in JWKS!");

Console.WriteLine($"Found matching JSON web key!");
Console.WriteLine($"kid: {key.Kid}");
Console.WriteLine($"alg: {key.Alg}");
Console.WriteLine($"x: {key.X}");
Console.WriteLine($"kty: {key.Kty}");
Console.WriteLine();

// verify signature
var signer = new DilithiumSigner();
var publicKey = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium3, Base64Url.Decode(key.X));

signer.Init(false, publicKey);

var signedPart = $"{parsedToken.RawHeader}.{parsedToken.RawPayload}";
var verified = signer.VerifySignature(Encoding.UTF8.GetBytes(signedPart), Base64Url.Decode(parsedToken.RawSignature));
Console.WriteLine($"Successfully verified? {verified}");