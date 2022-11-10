namespace DSM.Crypto.PasswordHashing;

public class UserInfo
{
    public UserInfo(string userName,
        string passwordHash,
        string passwordSalt)
    {
        UserName = userName;
        PasswordHash = passwordHash;
        PasswordSalt = passwordSalt;
    }

    public string UserName { get; }
    public string PasswordHash { get; }
    public string PasswordSalt { get; }
}