// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.Identity.Client.PoP
{
    /// <summary>
    /// An abstraction over an the asymmetric key operations needed by POP, that encapsulates a pair of 
    /// public and private keys and some typical crypto operations.
    /// </summary>
    /// <remarks>
    /// There should be a single public / private key pair associated with a machine. 
    /// </remarks>
    internal interface IPoPCryptoProvider
    {
        /// <summary>
        /// A key ID that uniquely describes a public / private key pair. Format is not specified, 
        /// it can be anything as long as distinguish between several key pairs. 
        /// </summary>
        /// <remarks>
        /// For an X509 certificate, this is usually the certificate thumbprint.
        /// </remarks>
        string KeyId { get; }

        /// <summary>
        /// The name of the encryption algorithm, as described by the JWS RFC
        /// https://tools.ietf.org/html/rfc7515
        /// Values are from https://www.iana.org/assignments/jose/jose.xhtml
        /// </summary>
        string Algorithm { get; }

        /// <summary>
        /// Gets a JSON representation of the public key material as described by https://tools.ietf.org/html/rfc7517.
        /// For example: 
        ///  {"kty":"RSA",
        ///  "n": "0vx7ag...",
        ///  "e":"AQAB",
        ///  "alg":"RS256",
        ///  "kid":"2011-04-29"}
        /// </summary>
        /// <returns></returns>
        string GetPublicKeyJwk();

        /// <summary>
        /// Sings the byte array using the private key
        /// </summary>
        byte[] Sign(byte[] payload);
    }
}
