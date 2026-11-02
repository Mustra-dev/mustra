# Certificates
<!-- group: Secure; order: 48; pages: /certificates -->

See every certificate in your fleet and when it expires, and have mustra renew and install the ones you choose, from its own private CA, Let's Encrypt, Cloudflare, Active Directory Certificate Services or Tailscale.

## Before you start

- Reading certificates needs **See the fleet**. Managing and trusting them needs **Deploy software and run actions** (`deploy.manage`). Expiry alerts need **Manage settings**, and connecting a certificate authority needs **Manage integrations**.

## See what expires

**Certificate Manager → Overview** lists what expires next across files, the Windows certificate store, the macOS System keychain and the certificates endpoints serve on their TLS ports. **Inventory** lists them all.

Set **Alerts** to be told 60, 30, 14, 7 and 1 days before expiry, by email or webhook. **Send a test** checks the destination.

## Have mustra manage a certificate

1. **Certificate Manager → New Certificate**.
2. **Where it goes**: the endpoint, and the file paths for the certificate and key (or one combined file).
3. **What it covers and who signs it**: the DNS names, and the CA.
4. **Renewal**: how many days before expiry to renew, whether each renewal needs approval, a command to reload the service (for example `systemctl reload nginx`) and a port to check afterwards.
5. Choose **Create and install now**, or **Save without installing**.

On renewal, the endpoint creates the new key itself (it never leaves the machine), the CA signs it, and the endpoint backs up the old files, writes the new ones, reloads the service and checks the port. If anything fails, it puts the old certificate back.

## Use the private CA

mustra has its own certificate authority for internal services. Under **Trusted Roots**, choose which endpoints should trust it; mustra adds it to their trust stores. **Revoke** revokes a certificate it issued; the revocation list is published at `/pki/mustra-ca.crl`.

## Connect another CA

Under **Authorities**, set up Let's Encrypt (with a Cloudflare API token for DNS validation), Cloudflare Origin CA, Active Directory Certificate Services (through a Windows endpoint in the domain) or Tailscale.

## Application credentials

**App Credentials** tracks client secrets and certificates of cloud app registrations (Microsoft Entra ID, Google, Authentik and others), so their expiry is not a surprise either.
