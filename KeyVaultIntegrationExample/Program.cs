using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace KeyVaultIntegrationExample
{
	public class Program
	{
		private static async Task MainAsync(string[] args)
		{
			Console.WriteLine("Application started...");
			
			const string clientId = "{appId}";
			const string clientSecret = "{appSecret}";
			const string keyIdentifier = "{keyIdentifier}";

			Console.WriteLine("Configuration built...");
			
			var kv = new KeyVaultClient(async (authority, resource, scope) =>
			{
				var authContext = new AuthenticationContext(authority);
				var clientCred = new ClientCredential(clientId, clientSecret);
				var result = await authContext.AcquireTokenAsync(resource, clientCred);
				return result.AccessToken;
			});

			Console.WriteLine("KeyVaultClient created...");

			const string data = "digest";
			var byteData = Encoding.UTF8.GetBytes(data);

			var hasher = new SHA256CryptoServiceProvider();
			var digest = hasher.ComputeHash(byteData);

			var signResult = await kv.SignAsync(
				keyIdentifier: keyIdentifier,
				algorithm: JsonWebKeySignatureAlgorithm.RS256,
				digest: digest
			);
			
			Console.WriteLine("Data signed...");

			var signature = Convert.ToBase64String(signResult.Result);

			var verifyResult = await kv.VerifyAsync(
				keyIdentifier: keyIdentifier,
				algorithm: JsonWebKeySignatureAlgorithm.RS256,
				digest: digest,
				signature: Convert.FromBase64String(signature)
			);

			Console.WriteLine("Data verified...");

			Console.ReadKey();
		}

		public static void Main(string[] args)
		{
			MainAsync(args).GetAwaiter().GetResult();
		}
	}
}
