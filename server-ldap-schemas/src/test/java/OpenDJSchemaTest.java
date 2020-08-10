import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

import static org.junit.Assert.*;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.StaticUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


/**
 * Tests the OpenDJ schema.
 */
public class OpenDJSchemaTest {


	/**
	 * The test in-memory LDAP server.
	 */
	private InMemoryDirectoryServer testLDAPServer;


	/**
	 * The base DN for client entries.
	 */
	private DN clientsBaseDN;


	/**
	 * The base DN for authorisation entries.
	 */
	private DN authzBaseDN;
	
	
	/**
	 * The base DN for authorisation revocation entries.
	 */
	private DN authzRevocationsBaseDN;
	
	
	/**
	 * The base DN for identifier-based access tokens.
	 */
	private DN idAccessTokensBaseDN;
	
	
	/**
	 * The base DN for subject sessions.
	 */
	private DN sessionBaseDN;
	
	
	/**
	 * The base DN for the subject index.
	 */
	private DN subjectIndexDN;


	@Before
	public void setUp()
		throws Exception {

		// Set test LDAP server port
		InMemoryListenerConfig listenerConfig = InMemoryListenerConfig.createLDAPConfig("test-ldap");

		// Set test LDAP server context, user
		InMemoryDirectoryServerConfig dirConfig = new InMemoryDirectoryServerConfig("dc=wonderland,dc=net");
		dirConfig.setListenerConfigs(listenerConfig);
		DN adminDN = new DN("cn=Directory Manager");
		String adminPassword = "secret";
		dirConfig.addAdditionalBindCredentials(adminDN.toString(), adminPassword);
		dirConfig.setEnforceAttributeSyntaxCompliance(true);

		// Set test LDAP server schema
		Schema baseSchema = dirConfig.getSchema();
		Schema clientRegSchema = Schema.getSchema("src/main/resources/oidc-client-schema-opendj.ldif");
		Schema authzSchema = Schema.getSchema("src/main/resources/oidc-authz-schema-opendj.ldif");
		Schema sessionSchema = Schema.getSchema("src/main/resources/oidc-session-schema-opendj.ldif");
		dirConfig.setSchema(Schema.mergeSchemas(baseSchema, clientRegSchema, authzSchema, sessionSchema));

		// Start test LDAP server
		testLDAPServer = new InMemoryDirectoryServer(dirConfig);
		testLDAPServer.startListening();

		// Populate initial ldapDirectory
		testLDAPServer.bind(adminDN.toString(), adminPassword);

		final DN suffix = new DN("dc=wonderland,dc=net");
		Entry entry = new Entry(suffix);
		entry.addAttribute("objectClass", "top", "domain");
		entry.addAttribute("dc", "wonderland");
		testLDAPServer.add(entry);

		clientsBaseDN = new DN(new RDN("ou", "clients"), suffix);
		entry = new Entry(clientsBaseDN);
		entry.addAttribute("objectClass", "top", "organizationalUnit");
		testLDAPServer.add(entry);

		authzBaseDN = new DN(new RDN("ou", "authorizations,"), suffix);
		entry = new Entry(authzBaseDN);
		entry.addAttribute("objectClass", "top", "organizationalUnit");
		testLDAPServer.add(entry);
		
		authzRevocationsBaseDN = new DN(new RDN("ou", "revocations"), suffix);
		entry = new Entry(authzRevocationsBaseDN);
		entry.addAttribute("objectClass", "top", "organizationalUnit");
		testLDAPServer.add(entry);
		
		idAccessTokensBaseDN = new DN(new RDN("ou", "idAccessTokens"), suffix);
		entry = new Entry(idAccessTokensBaseDN);
		entry.addAttribute("objectClass", "top", "organizationalUnit");
		testLDAPServer.add(entry);
		
		sessionBaseDN = new DN(new RDN("ou", "sessions"), suffix);
		entry = new Entry(sessionBaseDN);
		entry.addAttribute("objectClass", "top", "organizationalUnit");
		testLDAPServer.add(entry);
		
		subjectIndexDN = new DN(new RDN("ou", "subjectIndex"), suffix);
		entry = new Entry(subjectIndexDN);
		entry.addAttribute("objectClass", "top", "organizationalUnit");
		testLDAPServer.add(entry);

		assertEquals(7, testLDAPServer.countEntries());
	}


	@After
	public void tearDown() {

		if (testLDAPServer != null) {
			testLDAPServer.shutDown(true);
		}
	}


	@Test
	public void testFullClientRegEntry()
		throws Exception {

		DN dn = new DN(new RDN("oauthClientID=123"), clientsBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oauthClientIdentity", "oauthClientMetadata", "oidcRelyingParty");
		entry.setAttribute("oauthClientIDIssueTime", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.setAttribute("oauthClientSecret", "secret");
		entry.setAttribute("oauthClientSecretExp", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.setAttribute("oauthClientRegistrationAccessToken", "security-token");
		entry.setAttribute("oauthClientRegistrationURI", "https://c2id.com/clients/123");
		entry.setAttribute("oauthRedirectURI", "https://example.com/in", "https://example.com/in-2");
		entry.setAttribute("oauthClientName", "Test Client");
		entry.setAttribute("oauthClientName;lang-de", "Test-Client");
		entry.setAttribute("oauthClientURI", "https://example.com");
		entry.setAttribute("oauthClientURI;lang-de", "https://example.com/de");
		entry.setAttribute("oauthLogoURI", "https://example.com/logo.png");
		entry.setAttribute("oauthLogoURI;lang-de", "https://example.com/de/logo.png");
		entry.setAttribute("oauthTermsOfServiceURI", "https://example.com/tos.html");
		entry.setAttribute("oauthTermsOfServiceURI;lang-de", "https://example.com/de/tos.html");
		entry.setAttribute("oauthPolicyURI", "https://example.com/privacy.html");
		entry.setAttribute("oauthPolicyURI;lang-de", "https://example.com/de/privacy.html");
		entry.setAttribute("oauthTokenEndpointAuthMethod", "client_secret_basic");
		entry.setAttribute("oauthTokenEndpointJWSAlg", "HS256");
		entry.setAttribute("oauthScopeValue", "openid", "email", "profile");
		entry.setAttribute("oauthGrantType", "authorization_code", "password", "implicit");
		entry.setAttribute("oauthResponseType", "code", "id_token");
		entry.setAttribute("oauthJWKSetURI", "https://example.com/jwks.json");
		entry.setAttribute("oauthJWKSet", "{}");
		entry.setAttribute("oauthSoftwareID", "1.0");
		entry.setAttribute("oauthSoftwareVersion", "1.0");
		entry.setAttribute("oauthClientData", "x-data");
		entry.setAttribute("oidcAppType", "web");
		entry.setAttribute("oidcSectorIdentifierURI", "https://example.com/sector_id");
		entry.setAttribute("oidcSubjectType", "pairwise");
		entry.setAttribute("oidcRequestJWSAlg", "HS256");
		entry.setAttribute("oidcRequestJWEAlg", "RSA-OAEP");
		entry.setAttribute("oidcRequestJWEEnc", "A128GCM");
		entry.setAttribute("oidcRequestURI", "https://example.com/request.jwt", "https://example.com/request-alt.jwt");
		entry.setAttribute("oidcIDTokenJWSAlg", "RS256");
		entry.setAttribute("oidcIDTokenJWEAlg", "RSA-OAEP");
		entry.setAttribute("oidcIDTokenJWEEnc", "A128GCM");
		entry.setAttribute("oidcUserInfoJWSAlg", "RS256");
		entry.setAttribute("oidcUserInfoJWEAlg", "RSA-OAEP");
		entry.setAttribute("oidcUserInfoJWEEnc", "A128GCM");
		entry.setAttribute("oidcDefaultMaxAge", "3600");
		entry.setAttribute("oidcRequireAuthTime", "FALSE");
		entry.setAttribute("oidcDefaultACR", "urn:c2id:acr:strong", "urn:c2id:acr:weak");
		entry.setAttribute("oidcInitiateLoginURI", "https://example.com/start-login");
		entry.setAttribute("oidcPostLogoutRedirectURI", "https://example.com/post-logout-1", "https://example.com/post-logout-2");
		entry.setAttribute("oidcFrontChannelLogoutURI", "https://rp.example.org/frontchannel_logout");
		entry.setAttribute("oidcFrontChannelLogoutSessionRequired", "TRUE");
		entry.setAttribute("oidcBackChannelLogoutURI", "https://rp.example.org/backchannel_logout");
		entry.setAttribute("oidcBackChannelLogoutSessionRequired", "TRUE");
		entry.setAttribute("mail", "admin@example.com", "webmaster@example.com");

		testLDAPServer.add(entry);

		Entry out = testLDAPServer.getEntry(entry.getDN());

		assertNotNull(out);

		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttribute("objectClass"), out.getAttribute("objectClass"));
		assertEquals(entry.getAttribute("oauthClientIDIssueTime"), out.getAttribute("oauthClientIDIssueTime"));
		assertEquals(entry.getAttribute("oauthClientSecret"), out.getAttribute("oauthClientSecret"));
		assertEquals(entry.getAttribute("oauthClientSecretExp"), out.getAttribute("oauthClientSecretExp"));
		assertEquals(entry.getAttribute("oauthClientRegistrationAccessToken"), out.getAttribute("oauthClientRegistrationAccessToken"));
		assertEquals(entry.getAttribute("oauthClientRegistrationURI"), out.getAttribute("oauthClientRegistrationURI"));
		assertEquals(entry.getAttribute("oauthRedirectURI"), out.getAttribute("oauthRedirectURI"));
		assertEquals(entry.getAttribute("oauthClientName"), out.getAttribute("oauthClientName"));
		assertEquals(entry.getAttribute("oauthClientName;lang-de"), out.getAttribute("oauthClientName;lang-de"));
		assertEquals(entry.getAttribute("oauthClientURI"), out.getAttribute("oauthClientURI"));
		assertEquals(entry.getAttribute("oauthClientURI;lang-de"), out.getAttribute("oauthClientURI;lang-de"));
		assertEquals(entry.getAttribute("oauthTermsOfServiceURI"), out.getAttribute("oauthTermsOfServiceURI"));
		assertEquals(entry.getAttribute("oauthTermsOfServiceURI;lang-de"), out.getAttribute("oauthTermsOfServiceURI;lang-de"));
		assertEquals(entry.getAttribute("oauthPolicyURI"), out.getAttribute("oauthPolicyURI"));
		assertEquals(entry.getAttribute("oauthPolicyURI;lang-de"), out.getAttribute("oauthPolicyURI;lang-de"));
		assertEquals(entry.getAttribute("oauthTokenEndpointAuthMethod"), out.getAttribute("oauthTokenEndpointAuthMethod"));
		assertEquals(entry.getAttribute("oauthTokenEndpointJWSAlg"), out.getAttribute("oauthTokenEndpointJWSAlg"));
		assertEquals(entry.getAttribute("oidcRequestJWEAlg"), out.getAttribute("oidcRequestJWEAlg"));
		assertEquals(entry.getAttribute("oauthScopeValue"), out.getAttribute("oauthScopeValue"));
		assertEquals(entry.getAttribute("oauthGrantType"), out.getAttribute("oauthGrantType"));
		assertEquals(entry.getAttribute("oauthResponseType"), out.getAttribute("oauthResponseType"));
		assertEquals(entry.getAttribute("oauthJWKSetURI"), out.getAttribute("oauthJWKSetURI"));
		assertEquals(entry.getAttribute("oauthJWKSet"), out.getAttribute("oauthJWKSet"));
		assertEquals(entry.getAttribute("oauthSoftwareID"), out.getAttribute("oauthSoftwareID"));
		assertEquals(entry.getAttribute("oauthSoftwareVersion"), out.getAttribute("oauthSoftwareVersion"));
		assertEquals(entry.getAttribute("oauthClientData"), out.getAttribute("oauthClientData"));
		assertEquals(entry.getAttribute("oidcAppType"), out.getAttribute("oidcAppType"));
		assertEquals(entry.getAttribute("oidcSectorIdentifierURI"), out.getAttribute("oidcSectorIdentifierURI"));
		assertEquals(entry.getAttribute("oidcSubjectType"), out.getAttribute("oidcSubjectType"));
		assertEquals(entry.getAttribute("oidcRequestJWSAlg"), out.getAttribute("oidcRequestJWSAlg"));
		assertEquals(entry.getAttribute("oidcRequestJWEAlg"), out.getAttribute("oidcRequestJWEAlg"));
		assertEquals(entry.getAttribute("oidcRequestJWEEnc"), out.getAttribute("oidcRequestJWEEnc"));
		assertEquals(entry.getAttribute("oidcRequestURI"), out.getAttribute("oidcRequestURI"));
		assertEquals(entry.getAttribute("oidcIDTokenJWSAlg"), out.getAttribute("oidcIDTokenJWSAlg"));
		assertEquals(entry.getAttribute("oidcIDTokenJWEAlg"), out.getAttribute("oidcIDTokenJWEAlg"));
		assertEquals(entry.getAttribute("oidcIDTokenJWEEnc"), out.getAttribute("oidcIDTokenJWEEnc"));
		assertEquals(entry.getAttribute("oidcUserInfoJWSAlg"), out.getAttribute("oidcUserInfoJWSAlg"));
		assertEquals(entry.getAttribute("oidcUserInfoJWEAlg"), out.getAttribute("oidcUserInfoJWEAlg"));
		assertEquals(entry.getAttribute("oidcUserInfoJWEEnc"), out.getAttribute("oidcUserInfoJWEEnc"));
		assertEquals(entry.getAttribute("oidcDefaultMaxAge"), out.getAttribute("oidcDefaultMaxAge"));
		assertEquals(entry.getAttribute("oidcDefaultMaxAge"), out.getAttribute("oidcDefaultMaxAge"));
		assertEquals(entry.getAttribute("oidcRequireAuthTime"), out.getAttribute("oidcRequireAuthTime"));
		assertEquals(entry.getAttribute("oidcDefaultACR"), out.getAttribute("oidcDefaultACR"));
		assertEquals(entry.getAttribute("oidcInitiateLoginURI"), out.getAttribute("oidcInitiateLoginURI"));
		assertEquals(entry.getAttribute("oidcPostLogoutRedirectURI"), out.getAttribute("oidcPostLogoutRedirectURI"));
		assertEquals(entry.getAttribute("oidcFrontChannelLogoutURI"), out.getAttribute("oidcFrontChannelLogoutURI"));
		assertEquals(entry.getAttribute("oidcFrontChannelLogoutSessionRequired"), out.getAttribute("oidcFrontChannelLogoutSessionRequired"));
		assertEquals(entry.getAttribute("oidcBackChannelLogoutURI"), out.getAttribute("oidcBackChannelLogoutURI"));
		assertEquals(entry.getAttribute("oidcBackChannelLogoutSessionRequired"), out.getAttribute("oidcBackChannelLogoutSessionRequired"));
		assertEquals(entry.getAttribute("mail"), out.getAttribute("mail"));
	}


	@Test
	public void testMinimalClientRegEntry()
		throws Exception {

		DN dn = new DN(new RDN("oauthClientID=123"), clientsBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcRelyingParty");

		testLDAPServer.add(entry);

		assertNotNull(testLDAPServer.getEntry(entry.getDN()));
	}


	@Test
	public void testSingleValuedClientID()
		throws Exception {

		DN dn = new DN(new RDN("oauthClientID=123"), clientsBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcRelyingParty");
		entry.addAttribute("oauthClientID", "123");
		entry.addAttribute("oauthClientID", "456");

		try {
			testLDAPServer.add(entry);
			fail();
		} catch (LDAPException e) {
			assertEquals(65, e.getResultCode().intValue());
		}
	}


	@Test
	public void testFullAuthorizationRegEntry()
		throws Exception {

		DN dn = new DN(new RDN("authzSubject=alice+authzClientID=123"), authzBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oauth2Authz", "oidcAuthz");
		entry.addAttribute("authzAccessToken", "token");
		entry.addAttribute("authzAccessTokenLifetime", "3600");
		entry.addAttribute("authzAccessTokenEncoding", "SELF_CONTAINED");
		entry.addAttribute("authzAccessTokenEncrypt", "TRUE");
		entry.addAttribute("authzRefreshToken", "refresh_token");
		entry.addAttribute("authzRefreshTokenSalt", "refresh_token_salt");
		entry.addAttribute("authzIssueRefreshToken", "TRUE");
		entry.addAttribute("authzRefreshTokenLifetime", "72000");
		String tokenIssueDate = StaticUtils.encodeGeneralizedTime(new Date());
		entry.addAttribute("authzRefreshTokenIssueDate", tokenIssueDate);
		entry.addAttribute("authzIssuer", "https://c2id.com");
		String issueDate = StaticUtils.encodeGeneralizedTime(new Date());
		entry.addAttribute("authzIssueDate", issueDate);
		String updateDate = StaticUtils.encodeGeneralizedTime(new Date());
		entry.addAttribute("authzUpdateDate", updateDate);
		entry.addAttribute("authzAudience", "https://api1.com", "https://api2.com", "https://api3.com");
		entry.addAttribute("authzScopeValue", "openid", "email", "profile");
		entry.addAttribute("authzSavedScopeValue", "address", "read", "write");
		entry.addAttribute("authzActor", "bob");
		entry.addAttribute("authzData", "{}");
		String accessDate = StaticUtils.encodeGeneralizedTime(new Date());
		entry.addAttribute("authzLastAccessDate", accessDate);
		entry.addAttribute("oidcIDToken", "id_token");
		entry.addAttribute("oidcClaimName", "sub", "email", "email_verified");
		entry.addAttribute("oidcSavedClaimName", "address", "given_name");
		entry.addAttribute("oidcClaimsLocales", "en de fr");
		entry.addAttribute("oidcClaimsData", "{\"trust_framework\":\"eidas_ial_high\"}");
		entry.addAttribute("oidcSessionID", "123");
		entry.addAttribute("authzDetails","{\"iban\":\"BG18RZBB91550123456789\"}");
		entry.addAttribute("authzSavedDetails","{\"txn\":\"123\"}");

		testLDAPServer.add(entry);

		entry = testLDAPServer.getEntry(entry.getDN());

		assertEquals(Arrays.asList("top", "oauth2Authz", "oidcAuthz"), Arrays.asList(entry.getAttributeValues("objectClass")));
		assertEquals("alice", entry.getAttributeValue("authzSubject"));
		assertEquals("123", entry.getAttributeValue("authzClientID"));
		assertEquals("token", entry.getAttributeValue("authzAccessToken"));
		assertEquals(3600, entry.getAttributeValueAsInteger("authzAccessTokenLifetime").intValue());
		assertEquals("SELF_CONTAINED", entry.getAttributeValue("authzAccessTokenEncoding"));
		assertTrue(entry.getAttributeValueAsBoolean("authzAccessTokenEncrypt"));
		assertEquals("refresh_token", entry.getAttributeValue("authzRefreshToken"));
		assertEquals("refresh_token_salt", entry.getAttributeValue("authzRefreshTokenSalt"));
		assertTrue(entry.getAttributeValueAsBoolean("authzIssueRefreshToken"));
		assertEquals(72000, entry.getAttributeValueAsInteger("authzRefreshTokenLifetime").intValue());
		assertEquals(tokenIssueDate, entry.getAttributeValue("authzRefreshTokenIssueDate"));
		assertEquals("https://c2id.com", entry.getAttributeValue("authzIssuer"));
		assertEquals(issueDate, entry.getAttributeValue("authzIssueDate"));
		assertEquals(updateDate, entry.getAttributeValue("authzUpdateDate"));
		assertEquals(Arrays.asList("https://api1.com", "https://api2.com", "https://api3.com"), Arrays.asList(entry.getAttributeValues("authzAudience")));
		assertEquals(Arrays.asList("openid", "email", "profile"), Arrays.asList(entry.getAttributeValues("authzScopeValue")));
		assertEquals(Arrays.asList("address", "read", "write"), Arrays.asList(entry.getAttributeValues("authzSavedScopeValue")));
		assertEquals("bob", entry.getAttributeValue("authzActor"));
		assertEquals("{}", entry.getAttributeValue("authzData"));
		assertEquals(accessDate, entry.getAttributeValue("authzLastAccessDate"));
		assertEquals("id_token", entry.getAttributeValue("oidcIDToken"));
		assertEquals(Arrays.asList("sub", "email", "email_verified"), Arrays.asList(entry.getAttributeValues("oidcClaimName")));
		assertEquals(Arrays.asList("address", "given_name"), Arrays.asList(entry.getAttributeValues("oidcSavedClaimName")));
		assertEquals("en de fr", entry.getAttributeValue("oidcClaimsLocales"));
		assertEquals("{\"trust_framework\":\"eidas_ial_high\"}", entry.getAttributeValue("oidcClaimsData"));
		assertEquals("123", entry.getAttributeValue("oidcSessionID"));
		assertEquals("{\"iban\":\"BG18RZBB91550123456789\"}", entry.getAttributeValue("authzDetails"));
		assertEquals("{\"txn\":\"123\"}", entry.getAttributeValue("authzSavedDetails"));

		assertEquals(29, entry.getAttributes().size());
	}


	@Test
	public void testFullAuthorizationRegEntryAlt()
		throws Exception {

		DN dn = new DN(new RDN("authzSubject=alice+authzClientID=123"), authzBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcAuthz");
		entry.addAttribute("authzAccessToken", "token");
		entry.addAttribute("authzAccessTokenLifetime", "3600");
		entry.addAttribute("authzAccessTokenEncoding", "SELF_CONTAINED");
		entry.addAttribute("authzAccessTokenEncrypt", "TRUE");
		entry.addAttribute("authzRefreshToken", "refresh_token");
		entry.addAttribute("authzRefreshTokenSecret", "refresh_token_secret");
		entry.addAttribute("authzIssueRefreshToken", "TRUE");
		entry.addAttribute("authzRefreshTokenLifetime", "72000");
		String tokenIssueDate = StaticUtils.encodeGeneralizedTime(new Date());
		entry.addAttribute("authzRefreshTokenIssueDate", tokenIssueDate);
		entry.addAttribute("authzIssuer", "https://c2id.com");
		entry.addAttribute("authzIssueDate", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.addAttribute("authzUpdateDate", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.addAttribute("authzAudience", "https://api1.com", "https://api2.com", "https://api3.com");
		entry.addAttribute("authzScopeValue", "openid", "email", "profile");
		entry.addAttribute("authzSavedScopeValue", "address", "read", "write");
		entry.addAttribute("authzData", "{}");
		entry.addAttribute("authzLastAccessDate", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.addAttribute("oidcIDToken", "id_token");
		entry.addAttribute("oidcClaimName", "sub", "email", "email_verified");
		entry.addAttribute("oidcSavedClaimName", "address", "given_name");
		entry.addAttribute("oidcClaimsLocales", "en de fr");
		entry.addAttribute("oidcSessionID", "123");

		testLDAPServer.add(entry);

		assertNotNull(testLDAPServer.getEntry(entry.getDN()));

	}


	@Test
	public void testAuthorizationActorInRDN()
		throws Exception {

		DN dn = new DN(new RDN("authzSubject=alice+authzActor=bob+authzClientID=123"), authzBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcAuthz");
		entry.addAttribute("authzAccessToken", "token");
		entry.addAttribute("authzAccessTokenLifetime", "3600");
		entry.addAttribute("authzAccessTokenEncoding", "SELF_CONTAINED");
		entry.addAttribute("authzAccessTokenEncrypt", "TRUE");
		entry.addAttribute("authzRefreshToken", "refresh_token");
		entry.addAttribute("authzRefreshTokenSecret", "refresh_token_secret");
		entry.addAttribute("authzIssueRefreshToken", "TRUE");
		entry.addAttribute("authzRefreshTokenLifetime", "72000");
		String tokenIssueDate = StaticUtils.encodeGeneralizedTime(new Date());
		entry.addAttribute("authzRefreshTokenIssueDate", tokenIssueDate);
		entry.addAttribute("authzIssuer", "https://c2id.com");
		entry.addAttribute("authzIssueDate", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.addAttribute("authzUpdateDate", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.addAttribute("authzAudience", "https://api1.com", "https://api2.com", "https://api3.com");
		entry.addAttribute("authzScopeValue", "openid", "email", "profile");
		entry.addAttribute("authzSavedScopeValue", "address", "read", "write");
		entry.addAttribute("authzData", "{}");
		entry.addAttribute("authzLastAccessDate", StaticUtils.encodeGeneralizedTime(new Date()));
		entry.addAttribute("oidcIDToken", "id_token");
		entry.addAttribute("oidcClaimName", "sub", "email", "email_verified");
		entry.addAttribute("oidcSavedClaimName", "address", "given_name");
		entry.addAttribute("oidcClaimsLocales", "en de fr");
		entry.addAttribute("oidcSessionID", "123");

		testLDAPServer.add(entry);

		entry = testLDAPServer.getEntry(entry.getDN());

		assertEquals("alice", entry.getAttributeValue("authzSubject"));
		assertEquals("bob", entry.getAttributeValue("authzActor"));
		assertEquals("123", entry.getAttributeValue("authzClientID"));
	}


	@Test
	public void testMinimalAuthorizationRegEntry()
		throws Exception {

		DN dn = new DN(new RDN("authzSubject=alice+authzClientID=123"), authzBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcAuthz");

		testLDAPServer.add(entry);

		assertNotNull(testLDAPServer.getEntry(entry.getDN()));
	}


	@Test
	public void testSingleValuedAuthzClientID()
		throws Exception {

		DN dn = new DN(new RDN("authzSubject=alice+authzClientID=123"), authzBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcRelyingParty");
		entry.addAttribute("authzClientID", "123");
		entry.addAttribute("authzClientID", "456");

		try {
			testLDAPServer.add(entry);
			fail();
		} catch (LDAPException e) {
			assertEquals(65, e.getResultCode().intValue());
		}
	}


	@Test
	public void testSingleValuedAuthzSubject()
		throws Exception {

		DN dn = new DN(new RDN("authzSubject=alice+authzClientID=123"), authzBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcRelyingParty");
		entry.addAttribute("authzSubject", "alice");
		entry.addAttribute("authzSubject", "bob");

		try {
			testLDAPServer.add(entry);
			fail();
		} catch (LDAPException e) {
			assertEquals(65, e.getResultCode().intValue());
		}
	}


	@Test
	public void testSingleValuedAuthzActor()
		throws Exception {

		DN dn = new DN(new RDN("authzSubject=alice+authzActor=bob+authzClientID=123"), authzBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oidcRelyingParty");
		entry.addAttribute("authzActor", "claire");

		try {
			testLDAPServer.add(entry);
			fail();
		} catch (LDAPException e) {
			assertEquals(65, e.getResultCode().intValue());
		}
	}
	
	
	@Test
	public void testAuthzRevocation_subjectOnly()
		throws Exception {
		
		Date now = new Date();
		String revocationTs = StaticUtils.encodeGeneralizedTime(now);
		
		DN dn = new DN(new RDN("authzSubject=alice"), clientsBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oauth2AuthzRevocation");
		entry.addAttribute("authzRevocationDate", revocationTs);
		entry.addAttribute("authzSubject", "alice");
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttributeValue("authzSubject"), out.getAttributeValue("authzSubject"));
		assertEquals(entry.getAttributeValue("authzRevocationDate"), out.getAttributeValue("authzRevocationDate"));
	}
	
	
	@Test
	public void testAuthzRevocation_actorOnly()
		throws Exception {
		
		Date now = new Date();
		String revocationTs = StaticUtils.encodeGeneralizedTime(now);
		
		DN dn = new DN(new RDN("authzActor=claire"), clientsBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oauth2AuthzRevocation");
		entry.addAttribute("authzRevocationDate", revocationTs);
		entry.addAttribute("authzActor", "claire");
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttributeValue("authzActor"), out.getAttributeValue("authzActor"));
		assertEquals(entry.getAttributeValue("authzRevocationDate"), out.getAttributeValue("authzRevocationDate"));
	}
	
	
	@Test
	public void testAuthzRevocation_clientOnly()
		throws Exception {
		
		Date now = new Date();
		String revocationTs = StaticUtils.encodeGeneralizedTime(now);
		
		DN dn = new DN(new RDN("authzClientID=123"), clientsBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oauth2AuthzRevocation");
		entry.addAttribute("authzClientID", "123");
		entry.addAttribute("authzRevocationDate", revocationTs);
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttributeValue("authzClientID"), out.getAttributeValue("authzClientID"));
		assertEquals(entry.getAttributeValue("authzRevocationDate"), out.getAttributeValue("authzRevocationDate"));
	}
	
	
	@Test
	public void testAuthzRevocation_allSet()
		throws Exception {
		
		Date now = new Date();
		String revocationTs = StaticUtils.encodeGeneralizedTime(now);
		
		DN dn = new DN(new RDN(new String[]{"authzSubject", "authzActor", "authzClientID"}, new String[]{"alice", "claire", "123"}), clientsBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oauth2AuthzRevocation");
		entry.addAttribute("authzSubject", "alice");
		entry.addAttribute("authzActor", "claire");
		entry.addAttribute("authzClientID", "123");
		entry.addAttribute("authzRevocationDate", revocationTs);
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttributeValue("authzSubject"), out.getAttributeValue("authzSubject"));
		assertEquals(entry.getAttributeValue("authzActor"), out.getAttributeValue("authzActor"));
		assertEquals(entry.getAttributeValue("authzClientID"), out.getAttributeValue("authzClientID"));
		assertEquals(entry.getAttributeValue("authzRevocationDate"), out.getAttributeValue("authzRevocationDate"));
	}
	
	
	@Test
	public void testIdBasedAccessToken()
		throws Exception {
		
		Date now = new Date();
		String issueTs = StaticUtils.encodeGeneralizedTime(now);
		
		DN dn = new DN(new RDN("authzAccessToken=abc"), idAccessTokensBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "oauth2IdAccessToken", "oidcIdAccessToken");
		entry.addAttribute("description", "Test access token");
		entry.addAttribute("authzAccessToken", "abc");
		entry.addAttribute("authzSubject", "alice");
		entry.addAttribute("authzActor", "claire");
		entry.addAttribute("authzClientID", "123");
		entry.addAttribute("authzAccessTokenIssueDate", issueTs);
		entry.addAttribute("authzAccessTokenLifetime", "3600");
		entry.addAttribute("authzIssuer", "https://c2id.com");
		entry.addAttribute("authzAudience", "A", "B");
		entry.addAttribute("authzScopeValue", "openid", "email");
		entry.addAttribute("authzData", "{\"ip\":\"10.20.30.40\"}");
		entry.addAttribute("oidcClaimName", "email", "email_verified");
		entry.addAttribute("oidcClaimsLocales", "en bg");
		entry.addAttribute("oidcClaimsData", "{\"trust_framework\":\"eidas_ial_high\"}");
		entry.addAttribute("oidcPresetUserInfoClaims", "{\"group\":\"admin\"}");
		entry.addAttribute("authzOtherTopLevelParams", "{\"patientId\":123}");
		entry.addAttribute("authzCnf", "{\"x5t#S256\":\"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"}");
		entry.addAttribute("authzDetails", "{\"iban\":\"BG18RZBB91550123456789\"}");
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		Assert.assertArrayEquals(entry.getObjectClassValues(), out.getObjectClassValues());
		assertEquals(entry.getAttributeValue("description"), out.getAttributeValue("description"));
		assertEquals(entry.getAttributeValue("authzAccessToken"), out.getAttributeValue("authzAccessToken"));
		assertEquals(entry.getAttributeValue("authzSubject"), out.getAttributeValue("authzSubject"));
		assertEquals(entry.getAttributeValue("authzActor"), out.getAttributeValue("authzActor"));
		assertEquals(entry.getAttributeValue("authzClientID"), out.getAttributeValue("authzClientID"));
		assertEquals(entry.getAttributeValue("authzAccessTokenIssueDate"), out.getAttributeValue("authzAccessTokenIssueDate"));
		assertEquals(entry.getAttributeValue("authzAccessTokenLifetime"), out.getAttributeValue("authzAccessTokenLifetime"));
		assertEquals(entry.getAttributeValue("authzIssuer"), out.getAttributeValue("authzIssuer"));
		Assert.assertArrayEquals(entry.getAttributeValues("authzAudience"), out.getAttributeValues("authzAudience"));
		Assert.assertArrayEquals(entry.getAttributeValues("authzScopeValue"), out.getAttributeValues("authzScopeValue"));
		assertEquals(entry.getAttributeValue("authzData"), out.getAttributeValue("authzData"));
		Assert.assertArrayEquals(entry.getAttributeValues("oidcClaimName"), out.getAttributeValues("oidcClaimName"));
		assertEquals(entry.getAttributeValue("oidcClaimsLocales"), out.getAttributeValue("oidcClaimsLocales"));
		assertEquals(entry.getAttributeValue("oidcClaimsData"), out.getAttributeValue("oidcClaimsData"));
		assertEquals(entry.getAttributeValue("oidcPresetUserInfoClaims"), out.getAttributeValue("oidcPresetUserInfoClaims"));
		assertEquals(entry.getAttributeValue("authzOtherTopLevelParams"), out.getAttributeValue("authzOtherTopLevelParams"));
		assertEquals(entry.getAttributeValue("authzCnf"), out.getAttributeValue("authzCnf"));
		assertEquals(entry.getAttributeValue("authzDetails"), out.getAttributeValue("authzDetails"));
	}
	
	
	@Test
	public void testSession_minimal()
		throws Exception {
		
		Instant now = Instant.ofEpochSecond(Instant.now().getEpochSecond());
		Instant authTs = now.minusSeconds(10L);
		Instant creationTs = now.minusSeconds(5L);
		Instant lastAccessTs = now;
		
		
		DN dn = new DN(new RDN("sessionKey", "123"), sessionBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "subjectSession");
		entry.addAttribute("sessionKey", "123");
		entry.addAttribute("sessionSubject", "alice");
		entry.addAttribute("sessionCreationDate", StaticUtils.encodeGeneralizedTime(Date.from(creationTs)));
		entry.addAttribute("sessionAuthDate", StaticUtils.encodeGeneralizedTime(Date.from(authTs)));
		entry.addAttribute("sessionLastAccessDate", StaticUtils.encodeGeneralizedTime(Date.from(lastAccessTs)));
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttributeValue("sessionKey"), out.getAttributeValue("sessionKey"));
		assertEquals(entry.getAttributeValue("sessionSubject"), out.getAttributeValue("sessionSubject"));
		assertEquals(entry.getAttributeValue("sessionCreationDate"), out.getAttributeValue("sessionCreationDate"));
		assertEquals(entry.getAttributeValue("sessionAuthDate"), out.getAttributeValue("sessionAuthDate"));
		assertEquals(entry.getAttributeValue("sessionLastAccessDate"), out.getAttributeValue("sessionLastAccessDate"));
	}
	
	
	@Test
	public void testSession_complete()
		throws Exception {
		
		Instant now = Instant.ofEpochSecond(Instant.now().getEpochSecond());
		Instant authTs = now.minusSeconds(10L);
		Instant creationTs = now.minusSeconds(5L);
		Instant lastAccessTs = now;
		
		
		DN dn = new DN(new RDN("sessionKey", "123"), sessionBaseDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "subjectSession");
		entry.addAttribute("sessionKey", "123");
		entry.addAttribute("description", "Session description");
		entry.addAttribute("sessionSubject", "alice");
		entry.addAttribute("sessionCreationDate", StaticUtils.encodeGeneralizedTime(Date.from(creationTs)));
		entry.addAttribute("sessionAuthDate", StaticUtils.encodeGeneralizedTime(Date.from(authTs)));
		entry.addAttribute("sessionLastAccessDate", StaticUtils.encodeGeneralizedTime(Date.from(lastAccessTs)));
		entry.addAttribute("sessionACR", "https://acr.c2id.com/highsec");
		entry.addAttribute("sessionAMR", "pwd", "otp", "mfa");
		entry.addAttribute("sessionMaxLife", "1000");
		entry.addAttribute("sessionAuthLife", "100");
		entry.addAttribute("sessionMaxIdle", "10");
		entry.addAttribute("sessionClaims", "{\"role\":\"admin\"}");
		entry.addAttribute("sessionRelyingParty", "client-1", "client-2", "client-3");
		entry.addAttribute("sessionData", "{\"ip\":\"127.0.0.1\"}");
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttributeValue("sessionKey"), out.getAttributeValue("sessionKey"));
		assertEquals(entry.getAttributeValue("description"), out.getAttributeValue("description"));
		assertEquals(entry.getAttributeValue("sessionSubject"), out.getAttributeValue("sessionSubject"));
		assertEquals(entry.getAttributeValue("sessionCreationDate"), out.getAttributeValue("sessionCreationDate"));
		assertEquals(entry.getAttributeValue("sessionAuthDate"), out.getAttributeValue("sessionAuthDate"));
		assertEquals(entry.getAttributeValue("sessionLastAccessDate"), out.getAttributeValue("sessionLastAccessDate"));
		assertEquals(entry.getAttributeValue("sessionACR"), out.getAttributeValue("sessionACR"));
		assertArrayEquals(entry.getAttributeValues("sessionAMR"), out.getAttributeValues("sessionAMR"));
		assertEquals(entry.getAttributeValueAsInteger("sessionMaxLife"), out.getAttributeValueAsInteger("sessionMaxLife"));
		assertEquals(entry.getAttributeValueAsInteger("sessionAuthLife"), out.getAttributeValueAsInteger("sessionAuthLife"));
		assertEquals(entry.getAttributeValueAsInteger("sessionMaxIdle"), out.getAttributeValueAsInteger("sessionMaxIdle"));
		assertEquals(entry.getAttributeValue("sessionClaims"), out.getAttributeValue("sessionClaims"));
		assertArrayEquals(entry.getAttributeValues("sessionRelyingParty"), out.getAttributeValues("sessionRelyingParty"));
		assertEquals(entry.getAttributeValue("sessionData"), out.getAttributeValue("sessionData"));
	}
	
	
	@Test
	public void testSessionIndex()
		throws Exception {
		
		DN dn = new DN(new RDN(new String[]{"sessionSubject", "sessionN"}, new String[]{"alice", "1"}), subjectIndexDN);
		Entry entry = new Entry(dn);
		entry.addAttribute("objectClass", "top", "subjectIndex");
		entry.addAttribute("description", "Subject index description");
		entry.addAttribute("sessionSubject", "alice");
		entry.addAttribute("sessionN", "1");
		entry.addAttribute("sessionKey", "abc");
		
		testLDAPServer.add(entry);
		
		Entry out = testLDAPServer.getEntry(dn.toString());
		
		assertEquals(entry.getDN(), out.getDN());
		assertEquals(entry.getAttributeValue("sessionSubject"), out.getAttributeValue("sessionSubject"));
		assertEquals(entry.getAttributeValue("sessionN"), out.getAttributeValue("sessionN"));
		assertEquals(entry.getAttributeValue("sessionKey"), out.getAttributeValue("sessionKey"));
	}
}