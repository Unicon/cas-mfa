package com.authy.api;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * 
 * @author Julian Camargo
 *
 */
@XmlRootElement(name="token")
public class Token extends Instance implements Response {
	boolean valid;

	public Token() {
		this.valid = false;
	}

	public Token(int status, String content) {
		super(status, content);
	}

	public boolean isValid() {
		return valid;
	}

	public void setValid(boolean valid) {
		this.valid = valid;
	}

	/**
	 * Map a Token instance to its XML representation.
	 * @return a String with the description of this object in XML.
	 */
	public String toXML() {
		Error error = getError();
		
		if(error != null) {
			return error.toXML();
		}
		
		StringWriter sw = new StringWriter();
		String xml = "";
		
		try {
			JAXBContext context = JAXBContext.newInstance(this.getClass());
			Marshaller marshaller = context.createMarshaller();
			
			marshaller.marshal(this, sw);
			xml = sw.toString();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		return xml;
	}

	/**
	 * Map a Token instance to its Java's Map representation.
	 * @return a Java's Map with the description of this object.
	 */
	public Map<String, String> toMap() {
		Map<String, String> map = new HashMap<String, String>();
		
		map.put("status", Integer.toString(status));
		map.put("content", content);
		
		return map;
	}
}
