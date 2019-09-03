// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client.ApiConfig.Executors;
using Microsoft.Identity.Client.PoP;
using Microsoft.Identity.Client.TelemetryCore.Internal.Events;

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// Base class for public client application token request builders
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public abstract class AbstractPublicClientAcquireTokenParameterBuilder<T>
        : AbstractAcquireTokenParameterBuilder<T>
        where T : AbstractAcquireTokenParameterBuilder<T>
    {
        internal AbstractPublicClientAcquireTokenParameterBuilder(IPublicClientApplicationExecutor publicClientApplicationExecutor)
        {
            PublicClientApplicationExecutor = publicClientApplicationExecutor;
        }

        public AbstractPublicClientAcquireTokenParameterBuilder<T> WithPoPAuthenticationScheme(Uri uri) // TODO: naming and comments
        {
            CommonParameters.AddApiTelemetryFeature(ApiTelemetryFeature.WithScheme);
            CommonParameters.AuthenticationScheme = new PoPAuthenticationScheme(uri, null); // TODO add a default crypto provider

            return this;
        }

        // Allows testing the PoP flow with any crypto. Consider making this public.
        internal AbstractPublicClientAcquireTokenParameterBuilder<T> WithPoPAuthenticationScheme(Uri protectedUri, IPoPCryptoProvider popCryptoProvider) 
        {
            CommonParameters.AddApiTelemetryFeature(ApiTelemetryFeature.WithScheme);
            CommonParameters.AuthenticationScheme = new PoPAuthenticationScheme(protectedUri, popCryptoProvider); 

            return this;
        }

        internal abstract Task<AuthenticationResult> ExecuteInternalAsync(CancellationToken cancellationToken);

        /// <inheritdoc />
        public override Task<AuthenticationResult> ExecuteAsync(CancellationToken cancellationToken)
        {
            ValidateAndCalculateApiId();
            return ExecuteInternalAsync(cancellationToken);
        }

        /// <summary>
        /// </summary>
        internal IPublicClientApplicationExecutor PublicClientApplicationExecutor { get; }
    }
}
