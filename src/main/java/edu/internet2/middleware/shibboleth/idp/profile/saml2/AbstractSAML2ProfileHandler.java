/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile.saml2;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.ProxyRestriction;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.KeyAlgorithmCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.Pair;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncodingException;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.SAML2NameIDEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.log.AuditLogEntry;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.CryptoOperationRequirementLevel;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AbstractSAML2ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;

/** Common implementation details for profile handlers. */
public abstract class AbstractSAML2ProfileHandler extends AbstractSAMLProfileHandler {

    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_20;

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(AbstractSAML2ProfileHandler.class);

    /** For building response. */
    private SAMLObjectBuilder<Response> responseBuilder;

    /** For building status. */
    private SAMLObjectBuilder<Status> statusBuilder;

    /** For building statuscode. */
    private SAMLObjectBuilder<StatusCode> statusCodeBuilder;

    /** For building StatusMessages. */
    private SAMLObjectBuilder<StatusMessage> statusMessageBuilder;

    /** For building assertion. */
    private SAMLObjectBuilder<Assertion> assertionBuilder;

    /** For building issuer. */
    private SAMLObjectBuilder<Issuer> issuerBuilder;

    /** For building subject. */
    private SAMLObjectBuilder<Subject> subjectBuilder;

    /** For building subject confirmation. */
    private SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;

    /** For building subject confirmation data. */
    private SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder;

    /** For building conditions. */
    private SAMLObjectBuilder<Conditions> conditionsBuilder;

    /** For building audience restriction. */
    private SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder;

    /** For building proxy restrictions. */
    private SAMLObjectBuilder<ProxyRestriction> proxyRestrictionBuilder;

    /** For building audience. */
    private SAMLObjectBuilder<Audience> audienceBuilder;

    /** For building signature. */
    private XMLObjectBuilder<Signature> signatureBuilder;

    /** Constructor. */
    @SuppressWarnings("unchecked")
    protected AbstractSAML2ProfileHandler() {
        super();

        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(
                StatusMessage.DEFAULT_ELEMENT_NAME);
        issuerBuilder = (SAMLObjectBuilder<Issuer>) getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) getBuilderFactory().getBuilder(
                SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) getBuilderFactory().getBuilder(
                SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) getBuilderFactory().getBuilder(
                AudienceRestriction.DEFAULT_ELEMENT_NAME);
        proxyRestrictionBuilder = (SAMLObjectBuilder<ProxyRestriction>) getBuilderFactory().getBuilder(
                ProxyRestriction.DEFAULT_ELEMENT_NAME);
        audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        signatureBuilder = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
    }

    /** {@inheritDoc} */
    protected void populateRequestContext(BaseSAMLProfileRequestContext requestContext) throws ProfileException {
        BaseSAML2ProfileRequestContext saml2Request = (BaseSAML2ProfileRequestContext) requestContext;
        try {
            super.populateRequestContext(requestContext);
        } catch (ProfileException e) {
            if (saml2Request.getFailureStatus() == null) {
                saml2Request.setFailureStatus(buildStatus(StatusCode.REQUESTER_URI, null, e.getMessage()));
            }
            throw e;
        }
    }

    /**
     * Populates the request context with the information about the user.
     * 
     * This method requires the the following request context properties to be populated: inbound message transport,
     * relying party ID
     * 
     * This methods populates the following request context properties: user's session, user's principal name, and
     * service authentication method
     * 
     * @param requestContext current request context
     */
    protected void populateUserInformation(BaseSAMLProfileRequestContext requestContext) {
        Session userSession = getUserSession(requestContext.getInboundMessageTransport());
        if (userSession == null) {
            NameID subject = (NameID) requestContext.getSubjectNameIdentifier();
            if (subject != null && subject.getValue() != null) {
                userSession = getUserSession(subject.getValue());
            }
        }

        if (userSession != null) {
            requestContext.setUserSession(userSession);
            requestContext.setPrincipalName(userSession.getPrincipalName());
            ServiceInformation serviceInfo = userSession.getServicesInformation().get(
                    requestContext.getInboundMessageIssuer());
            if (serviceInfo != null) {
                requestContext.setPrincipalAuthenticationMethod(serviceInfo.getAuthenticationMethod()
                        .getAuthenticationMethod());
            }
        }
    }

    /**
     * Checks that the SAML major version for a request is 2.
     * 
     * @param requestContext current request context containing the SAML message
     * 
     * @throws ProfileException thrown if the major version of the SAML request is not 2
     */
    protected void checkSamlVersion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        SAMLVersion version = requestContext.getInboundSAMLMessage().getVersion();
        if (version.getMajorVersion() < 2) {
            requestContext.setFailureStatus(buildStatus(StatusCode.VERSION_MISMATCH_URI,
                    StatusCode.REQUEST_VERSION_TOO_LOW_URI, null));
            throw new ProfileException("SAML request version too low");
        } else if (version.getMajorVersion() > 2 || version.getMinorVersion() > 0) {
            requestContext.setFailureStatus(buildStatus(StatusCode.VERSION_MISMATCH_URI,
                    StatusCode.REQUEST_VERSION_TOO_HIGH_URI, null));
            throw new ProfileException("SAML request version too high");
        }
    }

    /**
     * Builds a response to the attribute query within the request context.
     * 
     * @param requestContext current request context
     * @param subjectConfirmationMethod confirmation method used for the subject
     * @param statements the statements to include in the response
     * 
     * @return the built response
     * 
     * @throws ProfileException thrown if there is a problem creating the SAML response
     */
    protected Response buildResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext,
            String subjectConfirmationMethod, List<Statement> statements) throws ProfileException {

        DateTime issueInstant = new DateTime();

        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, samlResponse);

        Assertion assertion = null;
        if (statements != null && !statements.isEmpty()) {
            assertion = buildAssertion(requestContext, issueInstant);
            assertion.getStatements().addAll(statements);
            assertion.setSubject(buildSubject(requestContext, subjectConfirmationMethod, issueInstant));

            postProcessAssertion(requestContext, assertion);

            signAssertion(requestContext, assertion);
            
            if (isEncryptAssertion(requestContext)) {
                if (log.isDebugEnabled()) {
                    log.debug("Attempting to encrypt assertion to relying party '{}'",
                            requestContext.getInboundMessageIssuer());
                    try {
                        Element assertionDOM = 
                            Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
                        log.debug("Assertion to be encrypted is:\n{}", XMLHelper.prettyPrintXML(assertionDOM)); 
                    } catch (MarshallingException e) {
                        log.warn("Error attempting to marshall Assertion for debug log", e);
                    }
                }

                try {
                    Encrypter encrypter = getEncrypter(requestContext.getInboundMessageIssuer());
                    samlResponse.getEncryptedAssertions().add(encrypter.encrypt(assertion));
                } catch (SecurityException e) {
                    log.error("Unable to construct encrypter", e);
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                            "Unable to encrypt assertion"));
                    throw new ProfileException("Unable to construct encrypter", e);
                } catch (EncryptionException e) {
                    log.error("Unable to encrypt assertion", e);
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                            "Unable to encrypt assertion"));
                    throw new ProfileException("Unable to encrypt assertion", e);
                }
            } else {
                samlResponse.getAssertions().add(assertion);
            }
        }

        Status status = buildStatus(StatusCode.SUCCESS_URI, null, null);
        samlResponse.setStatus(status);

        postProcessResponse(requestContext, samlResponse);

        return samlResponse;
    }

    /**
     * Determine whether issued assertions should be encrypted.
     * 
     * @param requestContext the current request context
     * @return true if assertions should be encrypted, false otherwise
     * @throws ProfileException if there is a problem determining whether assertions should be encrypted
     */
    protected boolean isEncryptAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {

        SAMLMessageEncoder encoder = getOutboundMessageEncoder(requestContext);
        try {
            return requestContext.getProfileConfiguration().getEncryptAssertion() == CryptoOperationRequirementLevel.always
                    || (requestContext.getProfileConfiguration().getEncryptAssertion() == CryptoOperationRequirementLevel.conditional && !encoder
                            .providesMessageConfidentiality(requestContext));
        } catch (MessageEncodingException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Unable to determine if assertions should be encrypted"));
            log.error("Unable to determine if outbound encoding '{}' can provide confidentiality",
                    encoder.getBindingURI());
            throw new ProfileException("Unable to determine if assertions should be encrypted");
        }
    }

    /**
     * Extension point for for subclasses to post-process the Response before it is signed and encoded.
     * 
     * @param requestContext the current request context
     * @param samlResponse the SAML Response being built
     * 
     * @throws ProfileException if there was an error processing the response
     */
    protected void postProcessResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, Response samlResponse)
            throws ProfileException {
    }

    /**
     * Extension point for for subclasses to post-process the Assertion before it is signed and encrypted.
     * 
     * @param requestContext the current request context
     * @param assertion the SAML Assertion being built
     * 
     * @throws ProfileException if there is an error processing the assertion
     */
    protected void postProcessAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, Assertion assertion)
            throws ProfileException {
    }

    /**
     * Builds a basic assertion with its id, issue instant, SAML version, issuer, subject, and conditions populated.
     * 
     * @param requestContext current request context
     * @param issueInstant time to use as assertion issue instant
     * 
     * @return the built assertion
     */
    protected Assertion buildAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(buildEntityIssuer(requestContext));

        Conditions conditions = buildConditions(requestContext, issueInstant);
        assertion.setConditions(conditions);

        return assertion;
    }

    /**
     * Creates an {@link Issuer} populated with information about the relying party.
     * 
     * @param requestContext current request context
     * 
     * @return the built issuer
     */
    protected Issuer buildEntityIssuer(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) {
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(requestContext.getLocalEntityId());

        return issuer;
    }

    /**
     * Builds a SAML assertion condition set. The following fields are set; not before, not on or after, audience
     * restrictions, and proxy restrictions.
     * 
     * @param requestContext current request context
     * @param issueInstant timestamp the assertion was created
     * 
     * @return constructed conditions
     */
    protected Conditions buildConditions(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        AbstractSAML2ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plus(profileConfig.getAssertionLifetime()));

        Collection<String> audiences;

        // add audience restrictions
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();
        // TODO we should only do this for certain outgoing bindings, not globally
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(requestContext.getInboundMessageIssuer());
        audienceRestriction.getAudiences().add(audience);
        audiences = profileConfig.getAssertionAudiences();
        if (audiences != null && audiences.size() > 0) {
            for (String audienceUri : audiences) {
                audience = audienceBuilder.buildObject();
                audience.setAudienceURI(audienceUri);
                audienceRestriction.getAudiences().add(audience);
            }
        }
        conditions.getAudienceRestrictions().add(audienceRestriction);

        // add proxy restrictions
        audiences = profileConfig.getProxyAudiences();
        if (audiences != null && audiences.size() > 0) {
            ProxyRestriction proxyRestriction = proxyRestrictionBuilder.buildObject();
            for (String audienceUri : audiences) {
                audience = audienceBuilder.buildObject();
                audience.setAudienceURI(audienceUri);
                proxyRestriction.getAudiences().add(audience);
            }

            proxyRestriction.setProxyCount(profileConfig.getProxyCount());
            conditions.getConditions().add(proxyRestriction);
        }

        return conditions;
    }

    /**
     * Populates the response's id, in response to, issue instant, version, and issuer properties.
     * 
     * @param requestContext current request context
     * @param response the response to populate
     */
    protected void populateStatusResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext,
            StatusResponseType response) {
        response.setID(getIdGenerator().generateIdentifier());

        response.setInResponseTo(requestContext.getInboundSAMLMessageId());
        response.setIssuer(buildEntityIssuer(requestContext));

        response.setVersion(SAMLVersion.VERSION_20);
    }

    /**
     * Resolves the attributes for the principal.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if there is a problem resolved attributes
     */
    protected void resolveAttributes(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML2ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();
        try {
            log.debug("Resolving attributes for principal '{}' for SAML request from relying party '{}'",
                    requestContext.getPrincipalName(), requestContext.getInboundMessageIssuer());
            Map<String, BaseAttribute> principalAttributes = attributeAuthority.getAttributes(requestContext);

            requestContext.setAttributes(principalAttributes);
        } catch (AttributeRequestException e) {
            log.warn(
                    "Error resolving attributes for principal '{}'.  No name identifier or attribute statement will be included in response",
                    requestContext.getPrincipalName());
        }
    }

    /**
     * Executes a query for attributes and builds a SAML attribute statement from the results.
     * 
     * @param requestContext current request context
     * 
     * @return attribute statement resulting from the query
     * 
     * @throws ProfileException thrown if there is a problem making the query
     */
    protected AttributeStatement buildAttributeStatement(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {
        if (requestContext.getAttributes() == null) {
            return null;
        }

        log.debug("Creating attribute statement in response to SAML request '{}' from relying party '{}'",
                requestContext.getInboundSAMLMessageId(), requestContext.getInboundMessageIssuer());

        AbstractSAML2ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();
        try {
            if (requestContext.getInboundSAMLMessage() instanceof AttributeQuery) {
                return attributeAuthority.buildAttributeStatement((AttributeQuery) requestContext
                        .getInboundSAMLMessage(), requestContext.getAttributes().values());
            } else {
                return attributeAuthority.buildAttributeStatement(null, requestContext.getAttributes().values());
            }
        } catch (AttributeRequestException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Error resolving attributes"));
            String msg = "Error encoding attributes for principal " + requestContext.getPrincipalName();
            log.error(msg, e);
            throw new ProfileException(msg, e);
        }
    }

    /**
     * Resolves the principal name of the subject of the request.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the principal name can not be resolved
     */
    protected void resolvePrincipal(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML2ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        if (profileConfiguration == null) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.REQUEST_DENIED_URI,
                    "Error resolving principal"));
            String msg = "Unable to resolve principal, no SAML 2 profile configuration for relying party "
                    + requestContext.getInboundMessageIssuer();
            log.warn(msg);
            throw new ProfileException(msg);
        }
        SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();
        log.debug("Resolving principal name for subject of SAML request '{}' from relying party '{}'",
                requestContext.getInboundSAMLMessageId(), requestContext.getInboundMessageIssuer());

        try {
            String principal = attributeAuthority.getPrincipal(requestContext);
            requestContext.setPrincipalName(principal);
        } catch (AttributeRequestException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI,
                    "Error resolving principal"));
            String msg = "Error resolving principal name for SAML request '" + requestContext.getInboundSAMLMessageId()
                    + "' from relying party '" + requestContext.getInboundMessageIssuer() + "'. Cause: "
                    + e.getMessage();
            log.warn(msg);
            throw new ProfileException(msg, e);
        }
    }

    /**
     * Signs the given assertion if either the current profile configuration or the relying party configuration contains
     * signing credentials.
     * 
     * @param requestContext current request context
     * @param assertion assertion to sign
     * 
     * @throws ProfileException thrown if the metadata can not be located for the relying party or, if signing is
     *             required, if a signing credential is not configured
     */
    protected void signAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, Assertion assertion)
            throws ProfileException {
        log.debug("Determining if SAML assertion to relying party '{}' should be signed",
                requestContext.getInboundMessageIssuer());

        boolean signAssertion = isSignAssertion(requestContext);

        if (!signAssertion) {
            return;
        }

        AbstractSAML2ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        log.debug("Determining signing credntial for assertion to relying party '{}'",
                requestContext.getInboundMessageIssuer());
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
        }

        if (signatureCredential == null) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "No signing credential available"));
            String msg = "No signing credential is specified for relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getProviderId();
            log.warn(msg);
            throw new ProfileException(msg);
        }

        log.debug("Signing assertion to relying party {}", requestContext.getInboundMessageIssuer());
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signatureCredential);
        try {
            // TODO pull SecurityConfiguration from SAMLMessageContext? needs to be added
            // TODO how to pull what keyInfoGenName to use?
            SecurityHelper.prepareSignatureParams(signature, signatureCredential, null, null);
        } catch (SecurityException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Unable to prepare assertion for signing"));
            String msg = "Error preparing signature for signing";
            log.error(msg);
            throw new ProfileException(msg, e);
        }

        assertion.setSignature(signature);

        Marshaller assertionMarshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
        try {
            assertionMarshaller.marshall(assertion);
            Signer.signObject(signature);
        } catch (MarshallingException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Unable to marshall assertion for signing"));
            String errMsg = "Unable to marshall assertion for signing";
            log.error(errMsg, e);
            throw new ProfileException(errMsg, e);
        } catch (SignatureException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Unable to sign assertion"));
            String msg = "Unable to sign assertion";
            log.error(msg, e);
            throw new ProfileException(msg, e);
        }
    }

    /**
     * Determine whether issued assertions should be signed.
     * 
     * @param requestContext the current request context
     * @return true if assertions should be signed, false otherwise
     * @throws ProfileException if there is a problem determining whether assertions should be signed
     */
    protected boolean isSignAssertion(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {

        SAMLMessageEncoder encoder = getOutboundMessageEncoder(requestContext);
        AbstractSAML2ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        try {
            boolean signAssertion = profileConfig.getSignAssertions() == CryptoOperationRequirementLevel.always
                    || (profileConfig.getSignAssertions() == CryptoOperationRequirementLevel.conditional && !encoder
                            .providesMessageIntegrity(requestContext));

            log.debug("IdP relying party configuration '{}' indicates to sign assertions: {}", requestContext
                    .getRelyingPartyConfiguration().getRelyingPartyId(), signAssertion);

            if (!signAssertion && requestContext.getPeerEntityRoleMetadata() instanceof SPSSODescriptor) {
                SPSSODescriptor ssoDescriptor = (SPSSODescriptor) requestContext.getPeerEntityRoleMetadata();
                if (ssoDescriptor.getWantAssertionsSigned() != null) {
                    signAssertion = ssoDescriptor.getWantAssertionsSigned().booleanValue();
                    log.debug("Entity metadata for relying party '{} 'indicates to sign assertions: {}",
                            requestContext.getInboundMessageIssuer(), signAssertion);
                }
            }

            return signAssertion;
        } catch (MessageEncodingException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Unable to determine if outbound assertion should be signed"));
            log.error("Unable to determine if outbound encoding '{}' provides message integrity protection",
                    encoder.getBindingURI());
            throw new ProfileException("Unable to determine if outbound assertion should be signed");
        }
    }

    /**
     * Build a status message, with an optional second-level failure message.
     * 
     * @param topLevelCode The top-level status code. Should be from saml-core-2.0-os, sec. 3.2.2.2
     * @param secondLevelCode An optional second-level failure code. Should be from saml-core-2.0-is, sec 3.2.2.2. If
     *            null, no second-level Status element will be set.
     * @param failureMessage An optional second-level failure message
     * 
     * @return a Status object.
     */
    protected Status buildStatus(String topLevelCode, String secondLevelCode, String failureMessage) {
        Status status = statusBuilder.buildObject();

        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(DatatypeHelper.safeTrimOrNullString(topLevelCode));
        status.setStatusCode(statusCode);

        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = statusCodeBuilder.buildObject();
            secondLevelStatusCode.setValue(DatatypeHelper.safeTrimOrNullString(secondLevelCode));
            statusCode.setStatusCode(secondLevelStatusCode);
        }

        if (failureMessage != null) {
            StatusMessage msg = statusMessageBuilder.buildObject();
            msg.setMessage(failureMessage);
            status.setStatusMessage(msg);
        }

        return status;
    }

    /**
     * Builds the SAML subject for the user for the service provider.
     * 
     * @param requestContext current request context
     * @param confirmationMethod subject confirmation method used for the subject
     * @param issueInstant instant the subject confirmation data should reflect for issuance
     * 
     * @return SAML subject for the user for the service provider
     * 
     * @throws ProfileException thrown if a NameID can not be created either because there was a problem encoding the
     *             name ID attribute or because there are no supported name formats
     */
    protected Subject buildSubject(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext, String confirmationMethod,
            DateTime issueInstant) throws ProfileException {
        Subject subject = subjectBuilder.buildObject();
        subject.getSubjectConfirmations().add(
                buildSubjectConfirmation(requestContext, confirmationMethod, issueInstant));

        NameID nameID = buildNameId(requestContext);
        if (nameID == null) {
            return subject;
        }

        requestContext.setSubjectNameIdentifier(nameID);

        if (isEncryptNameID(requestContext)) {
            log.debug("Attempting to encrypt NameID to relying party '{}'", requestContext.getInboundMessageIssuer());
            try {
                Encrypter encrypter = getEncrypter(requestContext.getInboundMessageIssuer());
                subject.setEncryptedID(encrypter.encrypt(nameID));
            } catch (SecurityException e) {
                log.error("Unable to construct encrypter", e);
                requestContext
                        .setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Unable to encrypt NameID"));
                throw new ProfileException("Unable to construct encrypter", e);
            } catch (EncryptionException e) {
                log.error("Unable to encrypt NameID", e);
                requestContext
                        .setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Unable to encrypt NameID"));
                throw new ProfileException("Unable to encrypt NameID", e);
            }
        } else {
            subject.setNameID(nameID);
        }

        return subject;
    }

    /**
     * Determine whether NameID's should be encrypted.
     * 
     * @param requestContext the current request context
     * @return true if NameID's should be encrypted, false otherwise
     * @throws ProfileException if there is a problem determining whether NameID's should be encrypted
     */
    protected boolean isEncryptNameID(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {

        boolean nameIdEncRequiredByAuthnRequest = isRequestRequiresEncryptNameID(requestContext);

        SAMLMessageEncoder encoder = getOutboundMessageEncoder(requestContext);
        boolean nameIdEncRequiredByConfig = false;
        try {
            nameIdEncRequiredByConfig = requestContext.getProfileConfiguration().getEncryptNameID() == CryptoOperationRequirementLevel.always
                    || (requestContext.getProfileConfiguration().getEncryptNameID() == CryptoOperationRequirementLevel.conditional && !encoder
                            .providesMessageConfidentiality(requestContext));
        } catch (MessageEncodingException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                    "Unable to determine if NameID should be encrypted"));
            String msg = "Unable to determine if outbound encoding '" + encoder.getBindingURI()
                    + "' provides message confidentiality protection";
            log.error(msg);
            throw new ProfileException(msg);
        }

        return nameIdEncRequiredByAuthnRequest || nameIdEncRequiredByConfig;
    }

    /**
     * Determine whether information in the SAML request requires the issued NameID to be encrypted.
     * 
     * @param requestContext the current request context
     * @return true if the request indicates NameID encryption is required, false otherwise
     */
    protected boolean isRequestRequiresEncryptNameID(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) {
        boolean nameIdEncRequiredByAuthnRequest = false;
        if (requestContext.getInboundSAMLMessage() instanceof AuthnRequest) {
            AuthnRequest authnRequest = (AuthnRequest) requestContext.getInboundSAMLMessage();
            NameIDPolicy policy = authnRequest.getNameIDPolicy();
            if (policy != null && DatatypeHelper.safeEquals(policy.getFormat(), NameID.ENCRYPTED)) {
                nameIdEncRequiredByAuthnRequest = true;
            }
        }
        return nameIdEncRequiredByAuthnRequest;
    }

    /**
     * Builds the SubjectConfirmation appropriate for this request.
     * 
     * @param requestContext current request context
     * @param confirmationMethod confirmation method to use for the request
     * @param issueInstant issue instant of the response
     * 
     * @return the constructed subject confirmation
     */
    protected SubjectConfirmation buildSubjectConfirmation(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext,
            String confirmationMethod, DateTime issueInstant) {
        SubjectConfirmationData confirmationData = subjectConfirmationDataBuilder.buildObject();
        HTTPInTransport inTransport = (HTTPInTransport) requestContext.getInboundMessageTransport();
        confirmationData.setAddress(inTransport.getPeerAddress());
        confirmationData.setInResponseTo(requestContext.getInboundSAMLMessageId());
        confirmationData.setNotOnOrAfter(issueInstant.plus(requestContext.getProfileConfiguration()
                .getAssertionLifetime()));

        Endpoint relyingPartyEndpoint = requestContext.getPeerEntityEndpoint();
        if (relyingPartyEndpoint != null) {
            if (relyingPartyEndpoint.getResponseLocation() != null) {
                confirmationData.setRecipient(relyingPartyEndpoint.getResponseLocation());
            } else {
                confirmationData.setRecipient(relyingPartyEndpoint.getLocation());
            }
        }

        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(confirmationMethod);
        subjectConfirmation.setSubjectConfirmationData(confirmationData);

        return subjectConfirmation;
    }

    /**
     * Builds a NameID appropriate for this request. NameIDs are built by inspecting the SAML request and metadata,
     * picking a name format that was requested by the relying party or is mutually supported by both the relying party
     * and asserting party as described in their metadata entries. Once a set of supported name formats is determined
     * the principals attributes are inspected for an attribute supported an attribute encoder whose category is one of
     * the supported name formats.
     * 
     * @param requestContext current request context
     * 
     * @return the NameID appropriate for this request
     * 
     * @throws ProfileException thrown if a NameID can not be created either because there was a problem encoding the
     *             name ID attribute or because there are no supported name formats
     */
    protected NameID buildNameId(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        Pair<BaseAttribute, SAML2NameIDEncoder> nameIdAttributeAndEncoder = null;
        try {
            nameIdAttributeAndEncoder = selectNameIDAttributeAndEncoder(SAML2NameIDEncoder.class, requestContext);
        } catch (ProfileException e) {
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, StatusCode.INVALID_NAMEID_POLICY_URI,
                    "Required NameID format not supported"));
            throw e;
        }

        if (nameIdAttributeAndEncoder == null) {
            return null;
        }

        BaseAttribute<?> nameIdAttribute = nameIdAttributeAndEncoder.getFirst();
        requestContext.setNameIdentifierAttribute(nameIdAttribute);
        SAML2NameIDEncoder nameIdEncoder = nameIdAttributeAndEncoder.getSecond();

        log.debug(
                "Using attribute '{}' supporting NameID format '{}' to create the NameID for relying party '{}'",
                new Object[] { nameIdAttribute.getId(), nameIdEncoder.getNameFormat(),
                        requestContext.getInboundMessageIssuer(), });
        try {
            // build the actual NameID
            NameID nameId = nameIdEncoder.encode(nameIdAttribute);
            if (nameId.getNameQualifier() == null) {
                nameId.setNameQualifier(requestContext.getRelyingPartyConfiguration().getProviderId());
            }
            return nameId;
        } catch (AttributeEncodingException e) {
            log.error("Unable to encode NameID attribute", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, "Unable to construct NameID"));
            throw new ProfileException("Unable to encode NameID attribute", e);
        }
    }

    /**
     * Constructs an SAML response message carrying a request error.
     * 
     * @param requestContext current request context
     * 
     * @return the constructed error response
     */
    protected Response buildErrorResponse(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) {
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(new DateTime());
        populateStatusResponse(requestContext, samlResponse);

        Status status = requestContext.getFailureStatus();
        if(status == null){
            status = buildStatus(StatusCode.RESPONDER_URI, null, null);
            requestContext.setFailureStatus(status);
        }
        samlResponse.setStatus(status);

        return samlResponse;
    }

    /**
     * Gets an encrypter that may be used encrypt content to a given peer.
     * 
     * @param peerEntityId entity ID of the peer
     * 
     * @return encrypter that may be used encrypt content to a given peer
     * 
     * @throws SecurityException thrown if there is a problem constructing the encrypter. This normally occurs if the
     *             key encryption credential for the peer can not be resolved or a required encryption algorithm is not
     *             supported by the VM's JCE.
     */
    protected Encrypter getEncrypter(String peerEntityId) throws SecurityException {
        SecurityConfiguration securityConfiguration = Configuration.getGlobalSecurityConfiguration();

        EncryptionParameters dataEncParams = SecurityHelper
                .buildDataEncryptionParams(null, securityConfiguration, null);

        Credential keyEncryptionCredential = getKeyEncryptionCredential(peerEntityId);
        if (keyEncryptionCredential == null) {
            log.error("Could not resolve a key encryption credential for peer entity: {}", peerEntityId);
            throw new SecurityException("Could not resolve key encryption credential");
        }
        String wrappedJCAKeyAlgorithm = SecurityHelper.getKeyAlgorithmFromURI(dataEncParams.getAlgorithm());
        KeyEncryptionParameters keyEncParams = SecurityHelper.buildKeyEncryptionParams(keyEncryptionCredential,
                wrappedJCAKeyAlgorithm, securityConfiguration, null, null);

        Encrypter encrypter = new Encrypter(dataEncParams, keyEncParams);
        encrypter.setKeyPlacement(KeyPlacement.INLINE);
        return encrypter;
    }

    /**
     * Gets the credential that can be used to encrypt encryption keys for a peer.
     * 
     * @param peerEntityId entity ID of the peer
     * 
     * @return credential that can be used to encrypt encryption keys for a peer
     * 
     * @throws SecurityException thrown if there is a problem resolving the credential from the peer's metadata
     */
    protected Credential getKeyEncryptionCredential(String peerEntityId) throws SecurityException {
        MetadataCredentialResolver kekCredentialResolver = getMetadataCredentialResolver();

        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(peerEntityId));
        criteriaSet.add(new MetadataCriteria(SPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
        criteriaSet.add(new UsageCriteria(UsageType.ENCRYPTION));
        
        // We practically speaking only support RSA keys for encryption.
        // DSA isn't defined for encryption and currently EC keys aren't supported
        // by the underlying libraries.  So in the case multiple keys are defined in metadata,
        // or are erroneously flagged for use='encryption', filter out those that wouldn't work.
        criteriaSet.add(new KeyAlgorithmCriteria("RSA"));

        return kekCredentialResolver.resolveSingle(criteriaSet);
    }

    /**
     * Writes an audit log entry indicating the successful response to the attribute request.
     * 
     * @param context current request context
     */
    protected void writeAuditLogEntry(BaseSAMLProfileRequestContext context) {
        SAML2AuditLogEntry auditLogEntry = new SAML2AuditLogEntry();
        auditLogEntry.setSAMLResponse((StatusResponseType) context.getOutboundSAMLMessage());
        auditLogEntry.setMessageProfile(getProfileId());
        auditLogEntry.setPrincipalAuthenticationMethod(context.getPrincipalAuthenticationMethod());
        auditLogEntry.setPrincipalName(context.getPrincipalName());
        auditLogEntry.setAssertingPartyId(context.getLocalEntityId());
        auditLogEntry.setRelyingPartyId(context.getInboundMessageIssuer());
        auditLogEntry.setRequestBinding(context.getMessageDecoder().getBindingURI());
        auditLogEntry.setRequestId(context.getInboundSAMLMessageId());
        auditLogEntry.setResponseBinding(context.getMessageEncoder().getBindingURI());
        auditLogEntry.setResponseId(context.getOutboundSAMLMessageId());
        if (context.getReleasedAttributes() != null) {
            auditLogEntry.getReleasedAttributes().addAll(context.getReleasedAttributes());
        }

        if (context.getNameIdentifierAttribute() != null) {
            Object idValue = context.getNameIdentifierAttribute().getValues().iterator().next();
            if(idValue != null){
                auditLogEntry.setNameIdValue(idValue.toString());
            }
        }

        getAduitLog().info(auditLogEntry.toString());
    }

    /** SAML 1 specific audit log entry. */
    protected class SAML2AuditLogEntry extends AuditLogEntry {

        /** The response to the SAML request. */
        private StatusResponseType samlResponse;

        /**
         * Gets the response to the SAML request.
         * 
         * @return the response to the SAML request
         */
        public StatusResponseType getSAMLResponse() {
            return samlResponse;
        }

        /**
         * Sets the response to the SAML request.
         * 
         * @param response the response to the SAML request
         */
        public void setSAMLResponse(StatusResponseType response) {
            samlResponse = response;
        }

        /** {@inheritDoc} */
        public String toString() {
            StringBuilder entryString = new StringBuilder(super.toString());

            StringBuilder assertionIds = new StringBuilder();

            if (samlResponse instanceof Response) {
                List<Assertion> assertions = ((Response) samlResponse).getAssertions();
                if (assertions != null && !assertions.isEmpty()) {
                    for (Assertion assertion : assertions) {
                        assertionIds.append(assertion.getID());
                        assertionIds.append(",");
                    }
                }
            }

            if (getNameIdValue() != null) {
                entryString.append(getNameIdValue());
            }
            entryString.append("|");

            entryString.append(assertionIds.toString());
            entryString.append("|");

            return entryString.toString();
        }
    }
}