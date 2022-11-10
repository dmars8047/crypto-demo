using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DSM.Crypto.PasswordHashing;

// Make sure users.json exists as our user store and pull store into memory
const string usersJsonFilePath = "./users.json";

if (!File.Exists(usersJsonFilePath))
{
    await File.WriteAllTextAsync(usersJsonFilePath, "[]");
}

string usersJsonString = await File.ReadAllTextAsync("./Users.json");

if (string.IsNullOrWhiteSpace(usersJsonString))
{
    throw new Exception("Error: users.json is not initialized properly. 🔥");
}

List<UserInfo>? Users = JsonSerializer.Deserialize<List<UserInfo>>(usersJsonString);

if (Users == null)
{
    throw new Exception("Error: Could not deserialize value from users.json. 🔥");
}

// Prompt for credentials
Console.WriteLine("Enter a username: 👾");

string? input = string.Empty;

while (string.IsNullOrWhiteSpace(input))
{
    input = Console.ReadLine();
}

string userName = input;
bool returningUser = false;

// If the user already exists, greet accordingly
if (Users.Any(u => u.UserName.Equals(userName)))
{
    returningUser = true;
    Console.WriteLine("Welcome back {0} 👋, please enter your password: 🔐", userName);
}
else
{
    Console.WriteLine("Enter a password: 🔐");
}

input = string.Empty;

// Get password in secure way
while (true)
{
    var key = Console.ReadKey(true);

    if (key.Key == ConsoleKey.Enter || key.Key == ConsoleKey.Escape)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new Exception("Error: Password input is invalid. 🔥");
        }

        break;
    }
    else if (key.Key == ConsoleKey.Backspace)
    {
        if (input != null && input.Length > 0)
        {
            input = input[..^1];
        }
    }
    else
    {
        input += key.KeyChar;
    }
}

string rawPassword = input;

Console.WriteLine();

using SHA256 sha256Hash = SHA256.Create();

if (returningUser) // Check the password the user provided is correct
{
    var user = Users.Single(u => u.UserName.Equals(userName));

    if (await CheckPassword(sha256Hash, rawPassword, user.PasswordHash, user.PasswordSalt))
    {
        Console.WriteLine("Password correct! 😁\n");
    }
    else
    {
        Console.WriteLine("Password incorrect! 😭\n");
    }
}
else // Generate user info (salt and hash) and save user info.
{
    string salt = GetSalt();

    Console.WriteLine("Generated Salt 🧂: {0}", salt);

    string hash = await GeneratePasswordHash(sha256Hash, rawPassword, salt);

    Console.WriteLine("Generated SHA256 Salted Hash #️⃣: {0}.", hash);

    Users.Add(new UserInfo(userName, hash, salt));

    var serializedUsers = JsonSerializer.Serialize(Users);

    Console.WriteLine("Saving user '{0}' to {1}\n", userName, usersJsonFilePath);

    await File.WriteAllTextAsync(usersJsonFilePath, serializedUsers);
}

/// <summary>
/// Generates a salt and returns it as a base64 encoded string.
/// </summary>
static string GetSalt()
{
    var data = new byte[32];

    using var generator = RandomNumberGenerator.Create();

    generator.GetBytes(data);

    return Convert.ToBase64String(data);
}

/// <summary>
/// Generates a hash and returns it as a base64 encoded string.
/// </summary>
static async Task<string> GeneratePasswordHash(HashAlgorithm hashAlgorithm, string password, string salt)
{
    var saltedInput = $"{salt}:{password}";

    using var stream = new MemoryStream(Encoding.UTF8.GetBytes(saltedInput));

    // Convert the input string to a byte array and compute the hash.
    byte[] data = await hashAlgorithm.ComputeHashAsync(stream);

    // Return the base 64 string.
    return Convert.ToBase64String(data);
}

/// <summary>
/// Checks to see if the provided password matches the hash value.
/// </summary>
static async Task<bool> CheckPassword(HashAlgorithm hashAlgorithm, string input, string hash, string salt)
{
    // Hash the input.
    string hashOfInput = await GeneratePasswordHash(hashAlgorithm, input, salt);

    // Create a StringComparer an compare the hashes.
    StringComparer comparer = StringComparer.OrdinalIgnoreCase;

    return comparer.Compare(hashOfInput, hash) == 0;
}