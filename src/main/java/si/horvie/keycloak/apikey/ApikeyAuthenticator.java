package si.horvie.keycloak.apikey;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Authenticate by preshared API key. User must have this key stored in
 * attribute with name 'apikey'.
 *
 */
public class ApikeyAuthenticator extends AbstractClientAuthenticator {
	private static final Logger LOG = Logger.getLogger(ApikeyAuthenticator.class);

	public static final String PROVIDER_ID = "api-key";
	public static final String AUTH_METHOD = "api_key";

	private static final String PARAMETER = "apikey";
	private static final String HEADER = "Apikey";
	private static final String HEADER_PREFIX = HEADER + " ";

	@Override
	public void authenticateClient(ClientAuthenticationFlowContext context) {
		String apikey = null;

		String authorizationHeader = context.getHttpRequest().getHttpHeaders().getRequestHeaders()
				.getFirst(HttpHeaders.AUTHORIZATION);

		if (authorizationHeader != null && authorizationHeader.startsWith(HEADER_PREFIX)) {
			apikey = extractApikey(authorizationHeader);
		} else {
			MultivaluedMap<String, String> queryParams = context.getHttpRequest().getUri().getQueryParameters(true);
			if (queryParams != null && queryParams.containsKey(PARAMETER)) {
				apikey = queryParams.getFirst(PARAMETER);
			} else {
				MediaType mediaType = context.getHttpRequest().getHttpHeaders().getMediaType();
				boolean hasFormData = mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
				MultivaluedMap<String, String> formData = hasFormData ? context.getHttpRequest().getDecodedFormParameters()
						: null;

				if (formData != null && formData.containsKey(PARAMETER)) {
					apikey = formData.getFirst(PARAMETER);
				}
			}
		}

		if (apikey == null) {
			Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
					"unauthorized_client", "Apikey not provided in request");
			context.challenge(challengeResponse);
			return;
		}

		try {
			RealmModel realm = context.getRealm();
			List<UserModel> users = context.getSession().users().searchForUserByUserAttribute("apikey", apikey, realm);

			int usersSize = users.size();
			if (usersSize == 0) {
				Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
						"unauthorized_client", "Apikey not found");
				context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
				return;
			} else if (users.size() > 1) {
				Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
						"unauthorized_client", "Apikey mapped to multiple subjects");
				context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
				return;
			} else {
				UserModel user = users.get(0);
				if (!user.isEnabled()) {
					Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
							"unauthorized_client", "Apikey is disabled");
					context.failure(AuthenticationFlowError.USER_DISABLED, challengeResponse);
					return;
				}
			}
		} catch (Throwable e) {
			LOG.error(e.getMessage(), e);
			Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
					"unauthorized_client", "Apikey error");
			context.failure(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
			return;
		}

		context.success();
	}

	@Override
	public String getDisplayType() {
		return "Preshared API key";
	}

	@Override
	public boolean isConfigurable() {
		return false;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public String getHelpText() {
		return "Validates client based on API key sent either in 'Authorization: Apikey' header or 'apikey' request parameter (query or form)";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return new LinkedList<>();
	}

	@Override
	public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
		return Collections.emptyList();
	}

	@Override
	public Map<String, Object> getAdapterConfiguration(ClientModel client) {
		return Collections.emptyMap();
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
		if (loginProtocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
			Set<String> results = new LinkedHashSet<>();
			results.add(AUTH_METHOD);
			return results;
		} else {
			return Collections.emptySet();
		}
	}

	private String extractApikey(String authorizationHeader) {
		String[] split = authorizationHeader.trim().split("\\s+");
		if (split.length != 2) {
			return null;
		}

		return split[1];
	}
}