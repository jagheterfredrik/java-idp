/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
package edu.internet2.middleware.shibboleth.serviceprovider;

import java.io.BufferedReader;
import java.io.StringReader;
import java.net.MalformedURLException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.opensaml.BindingException;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLConfig;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.opensaml.XML;
import org.opensaml.provider.SOAPHTTPBindingProvider;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


/**
 *  This is a replacement for SOAPHTTPBindingProvider in OpenSAML. While that
 *  module builds a URL and URLConnection to send a request to a Web Server
 *  hosting the IdP, this code generates a direct call to the AA or Artifact
 *  Resolver through the IdP Servlet.
 *  
 *  <p>Call setDefaultBindingProvider() to change the SAML configuration
 *  to use this class to access the IdP.</p>
 *  
 *  <p>Sanity Check: In order for the AA or Artifact query to work, the IdP
 *  has to have received an SSO, and we have to go back to the same Servlet
 *  object with the same configuration and caches that vended the SSO. So
 *  this code must depend on a prior initialization of both the IdP and the
 *  testing environment generated by either a previous test or at least a 
 *  setup phase.<p>
 *  
 */
public class MockHTTPBindingProvider 
    extends SOAPHTTPBindingProvider {
    
    
	private static SAMLConfig config = SAMLConfig.instance();
    
    /**
     * Static initialization routine that must be called so OpenSAML uses
     * this class.
     */
    public static void setDefaultBindingProvider() {
        config.setDefaultBindingProvider(SAMLBinding.SOAP,"edu.internet2.middleware.shibboleth.serviceprovider.MockHTTPBindingProvider" );
    }
    
    public static IdpTestContext idp = null;
    
    /** OpenSAML will construct this object. */
    public MockHTTPBindingProvider(String binding, Element e) throws SAMLException {
        super(binding, e);
    }

    /**
     * Based on the Http version of this code, this method replaces the URL and
     * URLConnection with operations on the Mock HttpRequest.
     */
    public SAMLResponse send(String endpoint, SAMLRequest request, Object callCtx)
        throws SAMLException
    {
        try {
            Element envelope = sendRequest(request, callCtx);
            
            /*
             * Prepare the Mockrunner blocks for the Query
             */
            idp.request.setLocalPort(8443);
            idp.request.setRequestURI(endpoint);
            idp.request.setRequestURL(endpoint);
            if (endpoint.endsWith("/AA")) {
                idp.request.setServletPath("/shibboleth.idp/AA");
            } else {
                idp.request.setServletPath("/shibboleth.idp/Artifact");
            }

            idp.request.setContentType("text/xml; charset=UTF-8");
            idp.request.setHeader("SOAPAction","http://www.oasis-open.org/committees/security");
//            Code in the overridden method is left as commentary            
//            ((HttpURLConnection)conn).setRequestMethod("POST");
//            ((HttpURLConnection)conn).setRequestProperty("Content-Type","text/xml; charset=UTF-8");
//            ((HttpURLConnection)conn).setRequestProperty("SOAPAction","http://www.oasis-open.org/committees/security");
        
             
            
            Canonicalizer c = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
//            conn.getOutputStream().write(c.canonicalizeSubtree(envelope));
            byte[] bs = c.canonicalizeSubtree(envelope);
            idp.request.setBodyContent(bs);

            idp.testModule.doPost();
            
            String content_type=idp.response.getContentType();
            
            if (content_type == null || !content_type.startsWith("text/xml")) {
                String outputStreamContent = idp.response.getOutputStreamContent();
                StringReader outputreader = new StringReader(outputStreamContent);
                BufferedReader reader=new BufferedReader(outputreader);
//                BufferedReader reader=new BufferedReader(new InputStreamReader(conn.getInputStream()));
                throw new BindingException(
                	"MockHTTPBindingProvider.send() detected an invalid content type ("
                		+ (content_type!=null ? content_type : "none")
                		+ ") in the response.");
            }
            
            envelope=XML.parserPool.parse(
//                    new InputSource(conn.getInputStream()),
                    new InputSource(new StringReader(idp.response.getOutputStreamContent())),
                    (request.getMinorVersion()>0) ? XML.parserPool.getSchemaSAML11() : XML.parserPool.getSchemaSAML10()
                    ).getDocumentElement();
            
            SAMLResponse ret = recvResponse(envelope, callCtx);
           
            if (!ret.getInResponseTo().equals(request.getId())) {
            	throw new BindingException("MockHTTPBindingProvider.send() unable to match SAML InResponseTo value to request");
            }
            return ret;
        }
        catch (MalformedURLException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() detected a malformed URL in the binding provided", ex);
        }
        catch (SAXException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught an XML exception while parsing the response", ex);
        }
        catch (InvalidCanonicalizerException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught a C14N exception while serializing the request", ex);
        }
        catch (CanonicalizationException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught a C14N exception while serializing the request", ex);
        }
        catch (java.io.IOException ex) {
            throw new SAMLException("SAMLSOAPBinding.send() caught an I/O exception", ex);
        }
        finally {
        }
    }


}