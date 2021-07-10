package src.addharConnectionTest;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.Writer;
import java.net.URL;
import java.net.UnknownHostException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import sun.net.www.protocol.http.HttpURLConnection;


/**
 * @author Mk
 * @year 2016
 * 
 * */
public class NsdlClientAPI {
	
	
	public static void main(String args[]) throws Exception
	{
		String uRL="http://10.44.73.46:8090/WebServiceProject/services/PANDetailsHttpSoapEndpoint?wsdl"; //------------------> Change 1
		String soapAction = "http://www.example.org/NPVNSDL/PANDetails";
		String bankCode="0";
		String channelId="7079";
		String tellerNumber="4225767";
		String txnNumber="002000";
		String pan="AAAAA1111A"; //------------------------------------------------------------------------------------------> Change 2
		NsdlClientAPI nsdlClientAPI = new NsdlClientAPI();
		
		nsdlClientAPI.nsdlServiceCall(uRL,bankCode, channelId,tellerNumber, txnNumber,pan,soapAction);
	}

	
	public String nsdlServiceCall(String uRL,String bankCode, String channelId,String tellerNumber, String txnNumber,String pan, String soapAction) throws Exception {
		char separator='^';
		String nsdlRequestData=bankCode+separator+channelId+separator+tellerNumber+separator+txnNumber+separator+pan;
		String nsdlResponseXML = "";
		InputStream in;
		try {
			URL url = new URL(uRL);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			connection.setDoOutput(true);
			connection.setDoInput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-type","text/xml; charset=utf-8");
			connection.setRequestProperty("SOAPAction",soapAction);
			OutputStream out = connection.getOutputStream();
			Writer wout = new OutputStreamWriter(out);
			
			System.out.println("NSDL Request Data ::: " + nsdlRequestData);
			String requestMsg = getNSDLRequestMessage(nsdlRequestData);
			wout.write(requestMsg);
			wout.flush();
			wout.close();
			System.out.println("Response Code ::: "+connection.getResponseCode());
			if (connection.getResponseCode() == 200) {
				in = connection.getInputStream();
				int inVal = in.available();
				if (inVal != 0) {
					nsdlResponseXML = readResponseMessage(in);
				} else {
					nsdlResponseXML = readResponseMessage(in);
				}
			} else {
				in = connection.getErrorStream();
			}
			System.out.println("Input stream available bytes length :::::::::::::: "+ in.available());
		} catch (UnknownHostException e) {
			nsdlResponseXML = "500";
			e.printStackTrace();
		} catch (Exception e) {
			nsdlResponseXML = "500";
			e.printStackTrace();
		}
		return nsdlResponseXML;
	}

	
	
	public String getNSDLRequestMessage(String nsdlRequestData) 
	{
		String requestMessage = "";
		StringBuffer requestMsg = new StringBuffer();
		requestMsg.append("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:npv=\"http://www.example.org/NPVNSDL\">");
		requestMsg.append("<soapenv:Header/>");
		requestMsg.append("<soapenv:Body>");
		requestMsg.append("<npv:BancsLinktoSIRequest>");
		requestMsg.append("<Request>" + nsdlRequestData + "</Request>");
		requestMsg.append("</npv:BancsLinktoSIRequest>");
		requestMsg.append("</soapenv:Body>");
		requestMsg.append("</soapenv:Envelope>");
		requestMessage = requestMsg.toString();
		System.out.println("Request Data ::: "+requestMessage);
		return requestMessage;
	}
	
	
	public String readResponseMessage(InputStream inputStream) {
		String parsedResponseMsg = "";
		try {
			InputStreamReader is = new InputStreamReader(inputStream);
			StringBuilder sb = new StringBuilder();
			BufferedReader br = new BufferedReader(is);
			String read = br.readLine();
			while (read != null) {
				sb.append(read);
				read = br.readLine();
			}
			
			System.out.println("Response Data ::: "+sb.toString());
			
			DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource isNew = new InputSource();
			isNew.setCharacterStream(new StringReader(sb.toString()));
			Document doc = db.parse(isNew);
			NodeList nodes = doc.getElementsByTagName("Response");
			
			Element element = (Element) nodes.item(0);
			parsedResponseMsg=element.getFirstChild().getTextContent();
			
			System.out.println("Parsed Response ::: "+parsedResponseMsg);
		} catch (Exception exception) {
			exception.printStackTrace();
		}
		return parsedResponseMsg;
	}
}
