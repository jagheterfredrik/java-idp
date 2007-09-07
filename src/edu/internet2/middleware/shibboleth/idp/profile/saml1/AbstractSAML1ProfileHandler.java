/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.idp.profile.saml1;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AttributeQuery;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.RequestAbstractType;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.ResponseAbstractType;
import org.opensaml.saml1.core.Statement;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.StatusMessage;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncodingException;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.SAML1NameIdentifierEncoder;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AbstractSAML1ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.AbstractSAMLProfileHandler;

/** Common implementation details for profile handlers. */
public abstract class AbstractSAML1ProfileHandler extends AbstractSAMLProfileHandler {

    /** SAML Version for this profile handler. */
    public static final SAMLVersion SAML_VERSION = SAMLVersion.VERSION_11;

    /** Class logger. */
    private static Logger log = Logger.getLogger(AbstractSAML1ProfileHandler.class);

    /** Builder of Response objects. */
    private SAMLObjectBuilder<Response> responseBuilder;

    /** Builder of Assertion objects. */
    private SAMLObjectBuilder<Assertion> assertionBuilder;

    /** Builder of Conditions objects. */
    private SAMLObjectBuilder<Conditions> conditionsBuilder;

    /** Builder of AudienceRestrictionCondition objects. */
    private SAMLObjectBuilder<AudienceRestrictionCondition> audienceRestrictionConditionBuilder;

    /** Builder of AudienceRestrictionCondition objects. */
    private SAMLObjectBuilder<Audience> audienceBuilder;

    /** Builder of SubjectConfirmation objects. */
    private SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder;

    /** Builder of ConfirmationMethod objects. */
    private SAMLObjectBuilder<ConfirmationMethod> confirmationMethodBuilder;

    /** Builder of Subject objects. */
    private SAMLObjectBuilder<Subject> subjectBuilder;

    /** Builder for Status objects. */
    private SAMLObjectBuilder<Status> statusBuilder;

    /** Builder for StatusCode objects. */
    private SAMLObjectBuilder<StatusCode> statusCodeBuilder;

    /** Builder for StatusMessage objects. */
    private SAMLObjectBuilder<StatusMessage> statusMessageBuilder;

    /** For building signature. */
    private XMLObjectBuilder<Signature> signatureBuilder;

    /**
     * Default constructor.
     */
    @SuppressWarnings("unchecked")
    public AbstractSAML1ProfileHandler() {
        super();
        responseBuilder = (SAMLObjectBuilder<Response>) getBuilderFactory().getBuilder(Response.DEFAULT_ELEMENT_NAME);
        assertionBuilder = (SAMLObjectBuilder<Assertion>) getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        conditionsBuilder = (SAMLObjectBuilder<Conditions>) getBuilderFactory().getBuilder(
                Conditions.DEFAULT_ELEMENT_NAME);
        audienceRestrictionConditionBuilder = (SAMLObjectBuilder<AudienceRestrictionCondition>) getBuilderFactory()
                .getBuilder(AudienceRestrictionCondition.DEFAULT_ELEMENT_NAME);
        audienceBuilder = (SAMLObjectBuilder<Audience>) getBuilderFactory().getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) getBuilderFactory().getBuilder(
                SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        confirmationMethodBuilder = (SAMLObjectBuilder<ConfirmationMethod>) getBuilderFactory().getBuilder(
                ConfirmationMethod.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (SAMLObjectBuilder<Subject>) getBuilderFactory().getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        statusBuilder = (SAMLObjectBuilder<Status>) getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
        statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) getBuilderFactory().getBuilder(
                StatusCode.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder = (SAMLObjectBuilder<StatusMessage>) getBuilderFactory().getBuilder(
                StatusMessage.DEFAULT_ELEMENT_NAME);
        signatureBuilder = (XMLObjectBuilder<Signature>) getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Checks that the SAML major version for a request is 1.
     * 
     * @param requestContext current request context containing the SAML message
     * 
     * @throws ProfileException thrown if the major version of the SAML request is not 1
     */
    protected void checkSamlVersion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        SAMLObject samlObject = requestContext.getInboundSAMLMessage();

        if (samlObject instanceof RequestAbstractType) {
            RequestAbstractType request = (RequestAbstractType) samlObject;
            if (request.getMajorVersion() < 1) {
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER, StatusCode.REQUEST_VERSION_TOO_LOW,
                        null));
                throw new ProfileException("SAML request major version too low");
            } else if (request.getMajorVersion() > 1) {
                requestContext.setFailureStatus(buildStatus(StatusCode.REQUESTER, StatusCode.REQUEST_VERSION_TOO_HIGH,
                        null));
                throw new ProfileException("SAML request major version too low");
            }
        }
    }

    /**
     * Builds a response to the attribute query within the request context.
     * 
     * @param requestContext current request context
     * @param statements the statements to include in the response
     * 
     * @return the built response
     * 
     * @throws ProfileException thrown if there is a problem creating the SAML response
     */
    protected Response buildResponse(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, List<Statement> statements)
            throws ProfileException {

        DateTime issueInstant = new DateTime();

        // create the assertion and add the attribute statement
        Assertion assertion = buildAssertion(requestContext, issueInstant);
        if (statements != null) {
            assertion.getStatements().addAll(statements);
        }

        // create the SAML response and add the assertion
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(issueInstant);
        populateStatusResponse(requestContext, samlResponse);

        samlResponse.getAssertions().add(assertion);

        // sign the assertion if it should be signed
        signAssertion(requestContext, assertion);

        Status status = buildStatus(StatusCode.SUCCESS, null, null);
        samlResponse.setStatus(status);

        return samlResponse;
    }

    /**
     * Builds a basic assertion with its id, issue instant, SAML version, issuer, subject, and conditions populated.
     * 
     * @param requestContext current request context
     * @param issueInstant time to use as assertion issue instant
     * 
     * @return the built assertion
     */
    protected Assertion buildAssertion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(getIdGenerator().generateIdentifier());
        assertion.setIssueInstant(issueInstant);
        assertion.setVersion(SAMLVersion.VERSION_11);
        assertion.setIssuer(requestContext.getLocalEntityId());

        Conditions conditions = buildConditions(requestContext, issueInstant);
        assertion.setConditions(conditions);

        return assertion;
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
    protected Conditions buildConditions(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, DateTime issueInstant) {
        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(issueInstant);
        conditions.setNotOnOrAfter(issueInstant.plus(profileConfig.getAssertionLifetime()));

        Collection<String> audiences;

        // add audience restrictions
        audiences = profileConfig.getAssertionAudiences();
        if (audiences != null && audiences.size() > 0) {
            AudienceRestrictionCondition audienceRestriction = audienceRestrictionConditionBuilder.buildObject();
            for (String audienceUri : audiences) {
                Audience audience = audienceBuilder.buildObject();
                audience.setUri(audienceUri);
                audienceRestriction.getAudiences().add(audience);
            }
            conditions.getAudienceRestrictionConditions().add(audienceRestriction);
        }

        return conditions;
    }

    /**
     * Builds the SAML subject for the user for the service provider.
     * 
     * @param requestContext current request context
     * @param confirmationMethod subject confirmation method used for the subject
     * 
     * @return SAML subject for the user for the service provider
     * 
     * @throws ProfileException thrown if a NameID can not be created either because there was a problem encoding the
     *             name ID attribute or because there are no supported name formats
     */
    protected Subject buildSubject(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, String confirmationMethod)
            throws ProfileException {
        NameIdentifier nameID = buildNameId(requestContext);
        requestContext.setSubjectNameIdentifier(nameID);

        ConfirmationMethod method = confirmationMethodBuilder.buildObject();
        method.setConfirmationMethod(confirmationMethod);

        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.getConfirmationMethods().add(method);

        Subject subject = subjectBuilder.buildObject();
        subject.setNameIdentifier(nameID);
        subject.setSubjectConfirmation(subjectConfirmation);

        return subject;
    }

    /**
     * Builds a NameIdentifier appropriate for this request. NameIdentifier are built by inspecting the SAML request and
     * metadata, picking a name format that was requested by the relying party or is mutually supported by both the
     * relying party and asserting party as described in their metadata entries. Once a set of supported name formats is
     * determined the principals attributes are inspected for an attribute supported an attribute encoder whose category
     * is one of the supported name formats.
     * 
     * @param requestContext current request context
     * 
     * @return the NameIdentifier appropriate for this request
     * 
     * @throws ProfileException thrown if a NameIdentifier can not be created either because there was a problem
     *             encoding the name ID attribute or because there are no supported name formats
     */
    protected NameIdentifier buildNameId(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Building assertion NameIdentifier to relying party " + requestContext.getInboundMessageIssuer()
                    + " for principal " + requestContext.getPrincipalName());
        }
        Map<String, BaseAttribute> principalAttributes = requestContext.getPrincipalAttributes();
        List<String> supportedNameFormats = getNameFormats(requestContext);

        if (log.isDebugEnabled()) {
            log.debug("Supported name formats: " + supportedNameFormats);
        }

        if (principalAttributes == null || supportedNameFormats == null) {
            log.error("No attributes for principal " + requestContext.getPrincipalName()
                    + " support constructions of NameIdentifier");
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Unable to construct NameIdentifier"));
            throw new ProfileException("No principal attributes support NameIdentifier construction");
        }

        try {
            SAML1NameIdentifierEncoder nameIdEncoder;

            for (BaseAttribute<?> attribute : principalAttributes.values()) {
                for (AttributeEncoder encoder : attribute.getEncoders()) {
                    if (encoder instanceof SAML1NameIdentifierEncoder) {
                        nameIdEncoder = (SAML1NameIdentifierEncoder) encoder;
                        if (supportedNameFormats.contains(nameIdEncoder.getNameFormat())) {
                            if (log.isDebugEnabled()) {
                                log.debug("Using attribute " + attribute.getId() + " suppoting name format "
                                        + nameIdEncoder.getNameFormat()
                                        + " to create the NameIdentifier for principal "
                                        + requestContext.getPrincipalName());
                            }
                            return nameIdEncoder.encode(attribute);
                        }
                    }
                }
            }
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Unable to construct NameIdentifier"));
            throw new ProfileException("No principal attribute supported encoding into the a supported name ID format.");
        } catch (AttributeEncodingException e) {
            log.error("Unable to construct NameIdentifier", e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null,
                    "Unable to construct NameIdentifier"));
            throw new ProfileException("Unable to encode NameIdentifier attribute", e);
        }

    }

    /**
     * Gets the NameIdentifier format to use when creating NameIdentifiers for the relying party.
     * 
     * @param requestContext current request context
     * 
     * @return list of formats that may be used with the relying party
     * 
     * @throws ProfileException thrown if there is a problem determing the NameIdentifier format to use
     */
    protected List<String> getNameFormats(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext)
            throws ProfileException {
        ArrayList<String> nameFormats = new ArrayList<String>();

        RoleDescriptor assertingPartyRole = requestContext.getLocalEntityRoleMetadata();
        List<String> assertingPartySupportedFormats = getEntitySupportedFormats(assertingPartyRole);

        if (nameFormats.isEmpty()) {
            RoleDescriptor relyingPartyRole = requestContext.getPeerEntityRoleMetadata();
            List<String> relyingPartySupportedFormats = getEntitySupportedFormats(relyingPartyRole);

            assertingPartySupportedFormats.retainAll(relyingPartySupportedFormats);
            nameFormats.addAll(assertingPartySupportedFormats);
        }
        if (nameFormats.isEmpty()) {
            nameFormats.add("urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified");
        }

        return nameFormats;
    }

    /**
     * Gets the list of NameIdentifier formats supported for a given role.
     * 
     * @param role the role to get the list of supported NameIdentifier formats
     * 
     * @return list of supported NameIdentifier formats
     */
    protected List<String> getEntitySupportedFormats(RoleDescriptor role) {
        List<NameIDFormat> nameIDFormats = null;

        if (role instanceof SSODescriptor) {
            nameIDFormats = ((SSODescriptor) role).getNameIDFormats();
        } else if (role instanceof AuthnAuthorityDescriptor) {
            nameIDFormats = ((AuthnAuthorityDescriptor) role).getNameIDFormats();
        } else if (role instanceof PDPDescriptor) {
            nameIDFormats = ((PDPDescriptor) role).getNameIDFormats();
        } else if (role instanceof AttributeAuthorityDescriptor) {
            nameIDFormats = ((AttributeAuthorityDescriptor) role).getNameIDFormats();
        }

        ArrayList<String> supportedFormats = new ArrayList<String>();
        if (nameIDFormats != null) {
            for (NameIDFormat format : nameIDFormats) {
                supportedFormats.add(format.getFormat());
            }
        }

        return supportedFormats;
    }

    /**
     * Constructs an SAML response message carrying a request error.
     * 
     * @param requestContext current request context containing the failure status
     * 
     * @return the constructed error response
     */
    protected Response buildErrorResponse(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) {
        Response samlResponse = responseBuilder.buildObject();
        samlResponse.setIssueInstant(new DateTime());
        populateStatusResponse(requestContext, samlResponse);

        samlResponse.setStatus(requestContext.getFailureStatus());

        return samlResponse;
    }

    /**
     * Populates the response's id, in response to, issue instant, version, and issuer properties.
     * 
     * @param requestContext current request context
     * @param response the response to populate
     */
    protected void populateStatusResponse(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext,
            ResponseAbstractType response) {
        response.setID(getIdGenerator().generateIdentifier());

        SAMLObject samlMessage = requestContext.getInboundSAMLMessage();
        if (samlMessage != null && samlMessage instanceof RequestAbstractType) {
            response.setInResponseTo(((RequestAbstractType) samlMessage).getID());
        }
        response.setVersion(SAMLVersion.VERSION_11);
    }

    /**
     * Build a status message, with an optional second-level failure message.
     * 
     * @param topLevelCode top-level status code
     * @param secondLevelCode second-level status code
     * @param failureMessage An optional second-level failure message
     * 
     * @return a Status object.
     */
    protected Status buildStatus(QName topLevelCode, QName secondLevelCode, String failureMessage) {
        Status status = statusBuilder.buildObject();

        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(topLevelCode);
        status.setStatusCode(statusCode);

        if (secondLevelCode != null) {
            StatusCode secondLevelStatusCode = statusCodeBuilder.buildObject();
            secondLevelStatusCode.setValue(secondLevelCode);
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
     * Resolved the attributes for the principal.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if attributes can not be resolved
     */
    protected void resolveAttributes(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        try {
            if (log.isDebugEnabled()) {
                log.debug("Resolving attributes for principal " + requestContext.getPrincipalName()
                        + " of SAML request from relying party " + requestContext.getInboundMessageIssuer());
            }
            Map<String, BaseAttribute> principalAttributes = attributeAuthority.getAttributes(requestContext);

            requestContext.setAttributes(principalAttributes);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error resolving attributes"));
            throw new ProfileException("Error resolving attributes for SAML request from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
        }
    }

    /**
     * Executes a query for attributes and builds a SAML attribute statement from the results.
     * 
     * @param requestContext current request context
     * @param subjectConfMethod subject confirmation method
     * 
     * @return attribute statement resulting from the query
     * 
     * @throws ProfileException thrown if there is a problem making the query
     */
    protected AttributeStatement buildAttributeStatement(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext,
            String subjectConfMethod) throws ProfileException {

        if (log.isDebugEnabled()) {
            log.debug("Creating attribute statement in response to SAML request from relying party "
                    + requestContext.getInboundMessageIssuer());
        }

        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        try {
            AttributeStatement statment;
            if (requestContext.getInboundSAMLMessage() instanceof AttributeQuery) {
                statment = attributeAuthority.buildAttributeStatement((AttributeQuery) requestContext
                        .getInboundSAMLMessage(), requestContext.getPrincipalAttributes().values());
            } else {
                statment = attributeAuthority.buildAttributeStatement(null, requestContext.getPrincipalAttributes()
                        .values());
            }

            Subject statementSubject = buildSubject(requestContext, subjectConfMethod);
            statment.setSubject(statementSubject);

            return statment;
        } catch (AttributeRequestException e) {
            log.error("Error encoding attributes for principal " + requestContext.getPrincipalName(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, null, "Error resolving attributes"));
            throw new ProfileException("Error encoding attributes for principal " + requestContext.getPrincipalName(),
                    e);
        }
    }

    /**
     * Resolves the principal name of the subject of the request.
     * 
     * @param requestContext current request context
     * 
     * @throws ProfileException thrown if the principal name can not be resolved
     */
    protected void resolvePrincipal(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML1ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML1AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();

        if (log.isDebugEnabled()) {
            log.debug("Resolving principal name for subject of SAML request from relying party "
                    + requestContext.getInboundMessageIssuer());
        }

        try {
            String principal = attributeAuthority.getPrincipal(requestContext);
            requestContext.setPrincipalName(principal);
        } catch (AttributeRequestException e) {
            log.error("Error resolving attributes for SAML request from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
            requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER, StatusCode.REQUEST_DENIED,
                    "Error resolving principal"));
            throw new ProfileException("Error resolving attributes for SAML request from relying party "
                    + requestContext.getInboundMessageIssuer(), e);
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
    protected void signAssertion(BaseSAML1ProfileRequestContext<?, ?, ?> requestContext, Assertion assertion)
            throws ProfileException {
        if (log.isDebugEnabled()) {
            log.debug("Determining if SAML assertion to relying party " + requestContext.getInboundMessageIssuer()
                    + " should be signed");
        }

        boolean signAssertion = false;

        RoleDescriptor relyingPartyRole = requestContext.getPeerEntityRoleMetadata();
        AbstractSAML1ProfileConfiguration profileConfig = requestContext.getProfileConfiguration();

        if (relyingPartyRole instanceof SPSSODescriptor) {
            SPSSODescriptor ssoDescriptor = (SPSSODescriptor) relyingPartyRole;
            if (ssoDescriptor.getWantAssertionsSigned() != null) {
                signAssertion = ssoDescriptor.getWantAssertionsSigned().booleanValue();
                if (log.isDebugEnabled()) {
                    log.debug("Entity metadata for relying party " + requestContext.getInboundMessageIssuer()
                            + " indicates to sign assertions: " + signAssertion);
                }
            }
        } else if (profileConfig.getSignAssertions()) {
            signAssertion = true;
            log.debug("IdP relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getRelyingPartyId()
                    + " indicates to sign assertions: " + signAssertion);
        }

        if (!signAssertion) {
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Determining signing credntial for assertion to relying party "
                    + requestContext.getInboundMessageIssuer());
        }
        Credential signatureCredential = profileConfig.getSigningCredential();
        if (signatureCredential == null) {
            signatureCredential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();
        }

        if (signatureCredential == null) {
            throw new ProfileException("No signing credential is specified for relying party configuration "
                    + requestContext.getRelyingPartyConfiguration().getProviderId()
                    + " or it's SAML2 attribute query profile configuration");
        }

        if (log.isDebugEnabled()) {
            log.debug("Signing assertion to relying party " + requestContext.getInboundMessageIssuer());
        }
        Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
        
        signature.setSigningCredential(signatureCredential);
        try {
            //TODO pull SecurityConfiguration from SAMLMessageContext?  needs to be added
            //TODO how to pull what keyInfoGenName to use?
            SecurityHelper.prepareSignatureParams(signature, signatureCredential, null, null);
        } catch (SecurityException e) {
            throw new ProfileException("Error preparing signature for signing", e);
        }
        
        assertion.setSignature(signature);

        Signer.signObject(signature);
    }
}