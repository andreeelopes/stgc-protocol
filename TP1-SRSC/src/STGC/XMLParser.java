package STGC;

import java.io.File;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XMLParser {



	public static String[] getMultiCastConfig(String group) throws Exception {

		String macProvider = null;
		String cipherProvider = null;
		String cipherSuite = null;
		String macCipher = null;
		String cipherKeySize = null;
		String MACKeySize = null;


		File fXmlFile = new File("ciphersuite.xml");
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(fXmlFile);

		doc.getDocumentElement().normalize();

		//System.out.println("Root element :" + doc.getDocumentElement().getNodeName());

		NodeList nList = doc.getElementsByTagName("group");

		//System.out.println("----------------------------");

		for (int temp = 0; temp < nList.getLength(); temp++) {

			Node nNode = nList.item(temp);

			//System.out.println("\nCurrent Element :" + nNode.getNodeName());

			if (nNode.getNodeType() == Node.ELEMENT_NODE) {

				Element eElement = (Element) nNode;

				String groupIP = eElement.getAttribute("ip");
				//System.out.println(groupIP + " " + group);
				if (groupIP.equals(group)) {

					macProvider = eElement.getElementsByTagName("mackProvider").item(0).getTextContent();
					cipherProvider = eElement.getElementsByTagName("cipherProvider").item(0).getTextContent();
					cipherSuite = eElement.getElementsByTagName("cipherConfig").item(0).getTextContent();
					macCipher = eElement.getElementsByTagName("mackCipher").item(0).getTextContent();
					cipherKeySize = eElement.getElementsByTagName("keySize").item(0).getTextContent(); 
					MACKeySize = eElement.getElementsByTagName("mackKeySize").item(0).getTextContent();
				
				}

			}
		}
		
		//System.out.println(macCipher + cipherProvider + group + "............." + cipherSuite);
		return new String[] {cipherSuite, macCipher, cipherProvider, macProvider, cipherKeySize, MACKeySize};
	}


	public static String[] getPBEconfig() {

		String cipherSuitePBE = null;
		String macAlgorithmPBE = null;
		String cipherProviderPBE = null;
		String macProviderPBE = null;
		String macKHashAlgorithm = null;
		String pwdHashAlgorithm = null;
		try {
			File fXmlFile = new File("stgcsap-auth.xml");
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);

			doc.getDocumentElement().normalize();

			Element e = (Element) doc.getElementsByTagName("config").item(0);

			cipherSuitePBE = e.getElementsByTagName("cipherSuite").item(0).getTextContent();
			macAlgorithmPBE = e.getElementsByTagName("macAlgorithm").item(0).getTextContent();
			macProviderPBE = e.getElementsByTagName("macProvider").item(0).getTextContent();
			cipherProviderPBE = e.getElementsByTagName("cipherProvider").item(0).getTextContent();
			macKHashAlgorithm = e.getElementsByTagName("macKHashAlgorithm").item(0).getTextContent();
			pwdHashAlgorithm = e.getElementsByTagName("pwdHashAlgorithm").item(0).getTextContent();
			
		} catch (Exception e) {
			e.printStackTrace();

		}

		return new String[] {cipherSuitePBE, macAlgorithmPBE, cipherProviderPBE, macProviderPBE, macKHashAlgorithm, pwdHashAlgorithm};
	}


	public static boolean checkIfUserHasPerm(String UserName, String ip) {

		try {

			File fXmlFile = new File("dacl.xml");
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);

			doc.getDocumentElement().normalize();

			NodeList nList = doc.getElementsByTagName("group");
			NodeList userList = null;
			
						
			for (int temp = 0; temp < nList.getLength(); temp++) {

				Node nNode = nList.item(temp);


				if (nNode.getNodeType() == Node.ELEMENT_NODE) {

					Element eElement = (Element) nNode;

					String ipList = eElement.getAttribute("ip");

					if (ip.equals(ipList)) {

						userList = eElement.getElementsByTagName("user");
						for (int tempII = 0; tempII < userList.getLength(); tempII++) {

							Node user = userList.item(tempII);


							if (user.getNodeType() == Node.ELEMENT_NODE) {

								Element Element = (Element) user;


								String name = Element.getAttribute("id");

								if (UserName.equals(name)) {
									return true;
								}
							}
						}
						return false;
					}

				}
			}
		} catch (Exception e) {
			e.printStackTrace();

		}
		return false;
	}

	public static String getUserHpwd(String UserName) {

		String password = null;

		try {

			File fXmlFile = new File("users.xml");
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);

			doc.getDocumentElement().normalize();

			NodeList nList = doc.getElementsByTagName("user");

			for (int temp = 0; temp < nList.getLength(); temp++) {

				Node nNode = nList.item(temp);


				if (nNode.getNodeType() == Node.ELEMENT_NODE) {

					Element eElement = (Element) nNode;

					String name = eElement.getAttribute("id");

					if (UserName.equals(name)) {

						password = eElement.getElementsByTagName("password").item(0).getTextContent();

					}

				}
			}
		} catch (Exception e) {
			e.printStackTrace();

		}

		//System.out.println();
		return password;
	}


}
