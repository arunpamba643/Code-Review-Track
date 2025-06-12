# Credential Management — SAST Description

## Description:
Credential Management issues arise when applications improperly store, transmit, or handle sensitive information like usernames, passwords, API keys, tokens, or cryptographic keys. Hardcoded credentials or insecure handling of secrets can lead to severe breaches and unauthorized access.

## How SAST Detects Credential Issues:
SAST tools scan the source code for:\
Hardcoded secrets (e.g., passwords, tokens, API keys).\
Insecure storage (e.g., writing credentials to plaintext files or logs).\
Use of outdated or weak encryption algorithms.\
Misuse of authentication libraries or insecure configuration of credential storage.

## Example of Vulnerability:

### Vulnerable Code
public class InsecureDatabaseConnection\
{\
 public void Connect()\
 {\
 string connectionString = "Server=myServer;Database=myDB;User Id=admin;Password=12345;";\
 // Hardcoded credentials - BAD practice!\
 }\
}

### Mitigation code:
Secure Credential Management Using Environment Variables\
public class SecureDatabaseConnection\
{\
 public void Connect()\
 {\
 string connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING");\
 
 if (string.IsNullOrEmpty(connectionString))\
 {\
 throw new InvalidOperationException("Database connection string is missing.");\
 }\
 }\
}


### Secure Credential Storage Using Azure Key Vault
 Azure Key Vault is a secure way to store and retrieve credentials dynamically.\
using Azure.Identity;\
using Azure.Security.KeyVault.Secrets;\
public class AzureKeyVaultExample\
{\
 public async Task<string> GetSecretAsync(string secretName)\
 {\
 string keyVaultUrl = "https://myvault.vault.azure.net/";\
 var client = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());\
 KeyVaultSecret secret = await client.GetSecretAsync(secretName);\
 return secret.Value;\
 }\
}