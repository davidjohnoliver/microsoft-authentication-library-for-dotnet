using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Identity.Client.Cache.Items;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Client.Utils;
using Microsoft.Identity.Json.Linq;

namespace Microsoft.Identity.Client.PoP
{
    internal class PoPAuthenticationScheme : IAuthenticationScheme
    {
        private static readonly DateTime s_jwtBaselineTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly Uri _uriToBind;
        private readonly IPoPCryptoProvider _popCryptoProvider;

        /// <summary>
        /// Creates POP tokens, i.e. tokens that are bound to an HTTP request and are digitally signed.
        /// </summary>
        /// <param name="uriToBind">Uri describing the HTTP request</param>
        /// <param name="popCryptoProvider">Crypto used to sign the POP token</param>
        public PoPAuthenticationScheme(Uri uriToBind, IPoPCryptoProvider popCryptoProvider)
        {
            _uriToBind = uriToBind;
            _popCryptoProvider = popCryptoProvider ??
                throw new ArgumentNullException(nameof(popCryptoProvider));
        }

        public string AuthorizationHeaderPrefix { get { return "PoP"; } }

        public string KeyId => _popCryptoProvider.KeyId;

        public IDictionary<string, string> GetTokenRequestParams()
        {
            return new Dictionary<string, string>() {
                { OAuth2Parameter.TokenType, PopRequest.PoPTokenType},
                { PopRequest.RequestConfirmation, _popCryptoProvider.GetPublicKeyJwk()}
            };
        }

        public string FormatAccessToken(MsalAccessTokenCacheItem atItem)
        {
            var header = new JObject
            {
                { JsonWebTokenConstants.ReservedHeaderParameters.Algorithm, _popCryptoProvider.Algorithm },
                { JsonWebTokenConstants.ReservedHeaderParameters.KeyId, _popCryptoProvider.KeyId },
                { JsonWebTokenConstants.ReservedHeaderParameters.Type, JsonWebTokenConstants.JWTHeaderType}
            };

            var payload = new JObject
                {
                    { HttpPopClaimTypes.At, atItem.Secret},
                    { HttpPopClaimTypes.Ts, (long)(DateTime.UtcNow - s_jwtBaselineTime).TotalSeconds },
                    // { HttpPopClaimTypes.M,  httpMethod}, - //TODO: add optional support for M (currently under discussion)
                    { HttpPopClaimTypes.U, _uriToBind.Host},
                    { HttpPopClaimTypes.P, _uriToBind.AbsolutePath }
                };

            return CreateJWS(payload.ToString(Json.Formatting.None), header.ToString(Json.Formatting.None));
        }

        /// <summary>
        /// Creates a JWS (json web signature) as per: https://tools.ietf.org/html/rfc7515
        /// Format: header.payload.signed_payload
        /// </summary>
        private string CreateJWS(string payload, string header)
        {
            var message = Base64UrlHelpers.Encode(Encoding.UTF8.GetBytes(header)) + "." + Base64UrlHelpers.Encode(payload);
            return message + "." + Base64UrlHelpers.Encode(_popCryptoProvider.Sign(Encoding.UTF8.GetBytes(message)));
        }
    }
}
