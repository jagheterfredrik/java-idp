/*
 * SchemasDirectoryImpl.java
 * 
 * Find Schemas in a Resource directory
 * 
 * 
 */
package edu.internet2.middleware.shibboleth.xml;

import java.io.File;
import java.io.InputStream;
import java.net.URL;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

/**
 * @author Howard Gilbert
 */
public class SchemasDirectoryImpl extends SchemaStore {
    
    private static Logger log = Logger.getLogger(SchemasDirectoryImpl.class);
    
    private String resourcedir = "/schemas/";

	
    /**
     * Load the bucket initially from a supplied directory.
     * 
     * @param resourcedir
     */
    public SchemasDirectoryImpl(String resourcedir) {
        super();
        this.resourcedir = resourcedir;
        this.loadBucket();
    }
    
	private boolean loadBucket() {
		// for each .xsd file in the directory
        URL resource = Parser.class.getResource(resourcedir);
        String path = resource.getPath();
        File dir = new File(path);
        if (!dir.isDirectory()) {
            log.error("Cannot find the schemas resource directory");
            return false;
        }
        String[] filenames = dir.list();
		int nextsource=0;
		for (int i=0;i<filenames.length;i++) {
            String filename = filenames[i];
            if (!filename.endsWith(".xsd"))
                continue;
            InputStream inputStream =
                    Parser.class.getResourceAsStream(
                        "/schemas/" + filename);
            InputSource insrc = new InputSource(inputStream);
           
            // Non-validating parse to DOM
            Document xsddom;
			try {
				xsddom = Parser.loadDom(insrc,false);
			} catch (Exception e) {
				log.error("Error parsing XML schema (" + filename + "): " + e);
				continue;
			}
            
            // Get the target namespace from the root element
            Element ele = xsddom.getDocumentElement();
            if (!ele.getLocalName().equals("schema")) {
                log.error("Schema file wrong root element:"+filename);
                continue;
            }
            String targetNamespace = ele.getAttribute("targetNamespace");
            if (targetNamespace==null) {
                log.error("Schema has no targetNamespace: "+filename);
                continue;
            }
            
            // Put the DOM in the Bucket keyed by namespace
            if (bucket.containsKey(targetNamespace)) {
                log.debug("Replacing XSD for namespace: "+targetNamespace+" "+filename);
            } else {
                log.debug("Defining XSD for namespace:  "+targetNamespace+" "+filename);
            }
            bucket.put(targetNamespace,xsddom);
        }
		return true;
	}

}
