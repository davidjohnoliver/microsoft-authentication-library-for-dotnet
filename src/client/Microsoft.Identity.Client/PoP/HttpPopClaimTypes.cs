namespace Microsoft.Identity.Client.PoP
{
    internal static class HttpPopClaimTypes
    {
        #region JSON keys for Http request

        /// <summary>
        /// Access token with response cnf
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
        /// </summary>
        public const string At = "at";

        /// <summary>
        /// Http method (GET or POST)
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
        /// </summary>
        public const string M = "m";

        /// <summary>
        /// Timestamp
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
        /// </summary>
        public const string Ts = "ts";

        /// <summary>
        /// Uri host
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
        /// </summary>
        public const string U = "u";

        /// <summary>
        /// Uri path
        /// https://tools.ietf.org/html/draft-ietf-oauth-signed-http-request-03#section-3
        /// </summary>
        public const string P = "p";

        #endregion
    }

    internal static class PopRequest
    {
        public const string PoPTokenType = "pop";
        public const string RequestConfirmation = "req_cnf";
    }
}
