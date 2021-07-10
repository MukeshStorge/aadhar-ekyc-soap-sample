package src.addharConnectionTest;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.web.client.RestTemplate;
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
public class AadharVaultClientFinal {

	public static final String POST = "POST";
	static HttpHeaders httpHeader = new HttpHeaders();
	static String resMessage = null;
	private static int changeOver = 100;
	private static int max = 100000000;
	private static int base = max/changeOver;
	private static long lastTime = 0;
	private static int count = 0;
	private static SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
	private static SimpleDateFormat dateTimesdf = new SimpleDateFormat("MMddHHmmss");
	private static SimpleDateFormat pidTsFormat = new SimpleDateFormat("YYYY-MM-dd\'T\'hh:mm:ss");
	
	
	public static void main(String args[]) 
	{
		try {
		
		//Aadhaar Vault 3 API Test Block	
//			{
//			String aadharNo="584589045995"; //Input Change - 1
//			String refnumber="056335";//Input Change - 2
//			
//			String reqDateTime = null;
//			Calendar c1 = Calendar.getInstance();
//			reqDateTime = df.format(c1.getTime());
//			String referenceNumber = null;
//			String rrn = genRRN();
//			referenceNumber = "AV" + dateTimesdf.format(new Date()) + rrn;
//			AadharVaultClientFinal aadharVaultClient = new AadharVaultClientFinal();
//			String uRL="https://uatiib.co.in/vault/v1/testQryDataReq"; // Based 
//			String securityKey="fc28a3e0-c653-4101-b00f-02d240af6fc9";
//			
////			String buildedReq = aadharVaultClient
////					.getRefKeyPassAadharRequest("QryRefKey",        //Input Change - 2
////							reqDateTime, referenceNumber, aadharNo,securityKey);
//			
////			String buildedReq = aadharVaultClient
////					.getAadharPassRefKeyRequest("QryDataReq",        //Input Change - 2
////							reqDateTime, referenceNumber, refnumber,securityKey);
//			
//			String buildedReq = aadharVaultClient
//					.getMaskedAadharPassRefKeyRequest("QryMaskedDataReq",      //Input Change - 3    
//			reqDateTime, referenceNumber, refnumber,securityKey);
//					
//			String buildedResponse = serviceCall(buildedReq,uRL);
//			
//			
//			JSONObject buildedJsonResponse = aadharVaultClient.getJSONResponse(buildedResponse);
//			
//			
//			System.out.println("Final Request :::: "+buildedReq);
//			System.out.println("Final Response :::: "+buildedResponse);
//			
//			}
			
		//	Generate OTP Test Block Call
//		//--------------------------------------------------------------------------------------------------------------------------------------------------------		
//			{
//				
//				String targetURL="https://uatiib.co.in/vault/v1/testQryRefKey";
//				String uidInputData="584589045995"; //Input Change - 2 // Aadhaar Number/ VID/ UID Token/REFERENCE KEY 
//				String uidType="0"; //Input Change - 3  // 0-Aadhaar Number 2-Virtual ID(VID) 3-UID Token 9-REFERENCE KEY 
//				String tellerId="1234567" ; //Input Change - 4
//				String branchCode = "55555";//Input Change - 5
//				String channel="IN"; //Input Change - 6
//				String deviceNumber= "5555512"; //branchCode + userId 
//				
//				
//				String referenceNumber = null;
//				String rrn = genRRN();
//				referenceNumber = ""+channel  + rrn;
//				AadharVaultClientFinal aadharVaultClient = new AadharVaultClientFinal();
//				
//				String buildedReq = aadharVaultClient
//						.generateOtpBuildRequest(referenceNumber, uidInputData,uidType,tellerId,branchCode,channel,deviceNumber);
//				
//				String buildedResponse = serviceCall(buildedReq,targetURL);
//				
//				DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
//				InputSource isNew = new InputSource();
//				isNew.setCharacterStream(new StringReader(buildedResponse));
//				Document doc = db.parse(isNew);
//
//		        XPathFactory xpf = XPathFactory.newInstance();
//		        XPath xpath = xpf.newXPath();
//		        Element userElement = (Element) xpath.evaluate("OtpResponse", doc, XPathConstants.NODE);
//		        
//		        System.out.println(userElement.getAttribute("status"));
//		        System.out.println(userElement.getAttribute("err"));
//		        System.out.println(userElement.getAttribute("uref"));
//		        System.out.println(userElement.getAttribute("TxnNo"));
//				
//				System.out.println("Final Request :::: "+buildedReq);
//				System.out.println("Final Response :::: "+buildedResponse);
//			}
//			
//	//--------------------------------------------------------------------------------------------------------------------------------------------------------			
//			//	OTP Get Details Call
//			
//			{
//				String targetURL="https://siapp1uat.co.in/ekycrdv25/api/GetDetails"; 
//				String myOTP = "146323";  // --------------------------------------------------> Change 1  --->>> OTP
//				/**
//				 *  Aadhaar/ Number/ VID/ UID/ Token/ REFERENCE KEY
//				 *  
//				 * */
//				
//				String uidInputData = "584589045995"; 
//														
//				/**
//				 *  0-Aadhaar Number 2-Virtual ID(VID) 3-UID Token 
//				 *  9-REFERENCE KEYO
//				 * */										
//				String uidType = "0";  // 0-Aadhaar Number 2-Virtual ID(VID) 3-UID Token 9-REFERENCE KEY 
//				String channel = "IN"; // Aadhaar Number/ VID/ UID Token/REFERENCE KEY 
//				String deviceNumber = "55555"+"12"; // branchCode + userId
//				char residentAuthenticationType = 'O';//(F-Finger Print ,O- OTP, D-DemoAuth, I- Iris)
//				char residentConsent = 'N';
//				String referenceNumber = "" + channel + genRRN();
//				AadharVaultClientFinal aadharGetDetails = new AadharVaultClientFinal();
//				String ts = pidTsFormat.format(new Date());
//				String txnNo="IN"+"";   // --------------------------------------------------> Change 2  --->>> OTP REQ TXN NUMBER
//				
//				String filePath="D:/Document Of Observation/Recon/Documentation/"
//						+ "Fwd__DRAFT_requirement_for_revamping_of_PCMS_issuance_page/"
//						+ "uidai_auth_encrypt_preprod.cer";
//				
//				EncrypterAadhaar.getPublicKeyAndExpDate(filePath);// --------------------------------------------------> Change 3  --->>> Certificate File Path 
//				
//				String buildedReq = aadharGetDetails.buildGetOtpDetailsRequest(
//						referenceNumber, uidInputData, uidType, channel, deviceNumber, myOTP, ts,
//						txnNo,residentAuthenticationType,residentConsent,EncrypterAadhaar.certExpiryDate);
//				
//				String buildedRes = serviceCall(buildedReq,targetURL);
//				
//				System.out.println("Final Request :::: " + buildedReq);
//				System.out.println("Final Response :::: " + buildedRes);
//				
//			}
//			
//	//--------------------------------------------------------------------------------------------------------------------------------------------------------		
//			//NSDL API
//			{
//				String uRL="http://10.44.73.46:8090/WebServiceProject/services/PANDetailsHttpSoapEndpoint?wsdl"; //------------------> Change 1
//				String soapAction = "http://www.example.org/NPVNSDL/PANDetails";
//				String bankCode="0";
//				String channelId="7079";
//				String tellerNumber="4225767";
//				String txnNumber="002000";
//				String pan="AAAAA1111A"; //------------------------------------------------------------------------------------------> Change 2
//				NsdlClientAPI nsdlClientAPI = new NsdlClientAPI();
//				
//				nsdlClientAPI.nsdlServiceCall(uRL,bankCode, channelId,tellerNumber, txnNumber,pan,soapAction);
//			}
			
			
			
			{
				
				String targetURL="https://siapp1uat.co.in/ekycrdv25/api/GetDetails";   
				String myOTP = "146323";                              // --------------------------------------------------> Change 1  --->>> OTP
				String txnNo="";                                      // --------------------------------------------------> Change 2  --->>> OTP REQ TXN NUMBER
				String filePath="D:/uidai_auth_encrypt_preprod.cer";  // --------------------------------------------------> Change 3  --->>> Certificate File Path 
				String uidInputData = "584589045995"; 
				String uidType = "0";  
				String channel = "IN"; 
				String deviceNumber = "55555"+"12"; 
				char residentAuthenticationType = 'O';
				char residentConsent = 'N';
				String referenceNumber = "" + channel + genRRN();
				AadharVaultClientFinal aadharGetDetails = new AadharVaultClientFinal();
				String ts = pidTsFormat.format(new Date());
				final int connTimeout = 5000;
				final int readTimeout = 1000;
				
				
				String Content_Type = "application/json"; //------------------Target--------------------
				
				EncrypterAadhaar.getPublicKeyAndExpDate(filePath);
				
				String buildedReq = aadharGetDetails.buildGetOtpDetailsRequest(
						referenceNumber, uidInputData, uidType, channel, deviceNumber, myOTP, ts,
						txnNo,residentAuthenticationType,residentConsent,EncrypterAadhaar.certExpiryDate);
				
				String buildedRest = sendPost(targetURL, buildedReq, POST,
						Content_Type, false, connTimeout, readTimeout);
				
				System.out.println("Final Request :::: " + buildedReq);
				System.out.println("Final Response:: "+buildedRest);
				
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	private static String sendPost(String urlString, String requestMessage,
			String requestMethod, String contentType, boolean noResponse,
			int connTimeout, int readTimeout) throws Exception {
		
		URL url = new URL(urlString.trim());
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		requestMethod = requestMethod.toUpperCase();
		conn.setRequestMethod(requestMethod);
		InputStream inputStream;
		conn.setDoOutput(true);
		conn.setAllowUserInteraction(false);
		conn.setDoInput(true);
		conn.setConnectTimeout(connTimeout);
		conn.setReadTimeout(readTimeout);
		conn.setRequestProperty("Content-Type", contentType);
		
		if (requestMessage != null && requestMessage.getBytes().length > 0) {
			conn.setRequestProperty("Content-Length", String.valueOf(requestMessage.getBytes().length));
			BufferedOutputStream out = new BufferedOutputStream(conn.getOutputStream());
			out.write(requestMessage.getBytes(), 0, requestMessage.getBytes().length);
			out.flush();
			out.close();
		}
		
		if (noResponse)
			return null;
		
		int responseCode = conn.getResponseCode();
		String  responsemessage=conn.getResponseMessage();
		System.out.println("responsemessage:::: "+responsemessage);
		System.out.println("Response code ::: "+responseCode);
	

		
		if (responseCode == HttpURLConnection.HTTP_OK) {
			inputStream = conn.getInputStream();
		} else {
			inputStream = conn.getErrorStream();
		}

		BufferedReader in = new BufferedReader(
		        new InputStreamReader(conn.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();
		return response.toString();
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
			connection.setRequestMethod(POST);
			connection.setRequestProperty("Content-type","text/xml; charset=utf-8");
			connection.setRequestProperty("SOAPAction",soapAction);
			OutputStream out = connection.getOutputStream();
			Writer wout = new OutputStreamWriter(out);
			
			System.out.println("NSDL XML Request Data ::: " + nsdlRequestData);
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
	

	public static String serviceCall(String command,String uRL) {
		try {
			RestTemplate rest = initRestTemplateForByteArrayAndSelfSignedHttps();
			httpHeader.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
			httpHeader.setContentType(new MediaType("application", "json"));
			HttpEntity<String> entity = new HttpEntity<>(command, httpHeader);
			resMessage = rest.postForObject(uRL, entity,String.class); //Input Change - 3
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		return resMessage;
	}
	
	
	
	private static RestTemplate initRestTemplateForByteArrayAndSelfSignedHttps()
			throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		RestTemplate restTemplate = new RestTemplate(useApacheHttpClientWithSelfSignedSupport());
		restTemplate.getMessageConverters().add(generateByteArrayHttpMessageConverter());
		return restTemplate;
	}
	
	public String generateOtpBuildRequest(
			String requestRefNumber, String uidInputData, String uidType, String tellerId, String branchCode, String channel, String deviceNumber) throws JSONException {
		
		JSONObject request = new JSONObject();
		request.put("ReferenceNumber", requestRefNumber);
		request.put("UIDType", uidType);
		request.put("UID", uidInputData);
		request.put("Tellerid", tellerId);
		request.put("BranchCode", branchCode);
		request.put("Channel", channel);
		request.put("DeviceInfo", deviceNumber);
		System.out.println("Request Data::: " + request.toString());
		return request.toString();
	}
	
	
	public String getRefKeyPassAadharRequest(String code, String reqDateTime,
			String requestRefNumber, String aadharNo,String securityKey) throws JSONException {
		String reqMess = null;
		String txnSecKey = null;
		txnSecKey = getTxnSecKey(
				securityKey, code,
				reqDateTime, requestRefNumber, aadharNo);
		System.out.println("Encoded TxnSec Key ::: " + txnSecKey);
		reqMess = buildRequestGetReferenceNo(reqMess, aadharNo, reqDateTime,
				txnSecKey, requestRefNumber);
		System.out.println("Request Data::: " + reqMess);
		return reqMess;
	}

	public String getAadharPassRefKeyRequest(String code, String reqDateTime,
			String requestRefNumber, String referenceKey,String securityKey) throws JSONException {
		String reqMess = null;
		String txnSecKey = null;
		txnSecKey = getTxnSecKey(securityKey, code,	reqDateTime, requestRefNumber, referenceKey);
		System.out.println("Encoded TxnSec Key ::: " + txnSecKey);
		reqMess = buildRequestGetAadharNo(reqMess, referenceKey, reqDateTime, txnSecKey, requestRefNumber);
		System.out.println("Request Data::: " + reqMess);
		return reqMess;
	}
	
	public String getMaskedAadharPassRefKeyRequest(String code, String reqDateTime,
			String requestRefNumber, String referenceKey,String securityKey) throws JSONException {
		String reqMess = null;
		String txnSecKey = null;
		txnSecKey = getTxnSecKey(securityKey, code,	reqDateTime, requestRefNumber, referenceKey);
		System.out.println("Encoded TxnSec Key ::: " + txnSecKey);
		reqMess = buildRequestMaskedPan(reqMess, referenceKey, reqDateTime,	txnSecKey, requestRefNumber);
		System.out.println("Request Data::: " + reqMess);
		return reqMess;
	}
	
	public JSONObject getJSONResponse(String buildedResponse) {

		try {
			if (resMessage != null) {
				System.out.println("Reference Key response ::: " + resMessage);
				JSONObject jsonObj = new JSONObject(buildedResponse);
				return jsonObj;
			} else {
				System.out.println("No response from EIS connect~~~~~~~~~~");
				System.out.println("Reference Key response ::: " + resMessage);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		}

		return null;
	}

	public static String getTxnSecKey(String secretKey, String code,
			String reqDateTime , String requestRefNumber, String inputData) {
		String plainKey = secretKey + "~" + code + "~" + requestRefNumber + "~"
				+ reqDateTime + "~" +inputData;
		System.out.println("----"+plainKey);
		MessageDigest digest;
		String encodedKey = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hashedKey = digest.digest(plainKey
					.getBytes(StandardCharsets.UTF_8));
			encodedKey = new String(Base64.encodeBase64(hashedKey));

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return encodedKey;
	}

	public String buildRequestGetReferenceNo(String reqMes,
			String aadharNumber, String requestDate, String txnSecKey,
			String requestRefNumber) throws JSONException {

		JSONObject request = new JSONObject();
		request.put("SOURCE_ID", "PREP");
		request.put("REQUEST_REF_NO", requestRefNumber);
		request.put("REQUEST_CODE", "AV02");
		request.put("REQUEST_DATE_TIME", requestDate);
		request.put("DATA_TYPE", "UID");
		request.put("DATA", aadharNumber);
		request.put("TXNSEC_KEY", txnSecKey);
		reqMes = request.toString();
		return reqMes;
	}

	public String buildRequestGetAadharNo(String reqMes,
			String referrenceKey, String requestDate, String txnSecKey,
			String requestRefNumber) throws JSONException {

		JSONObject request = new JSONObject();
		request.put("SOURCE_ID", "PREP");
		request.put("REQUEST_REF_NO", requestRefNumber);
		request.put("REQUEST_CODE", "AV01");
		request.put("REQUEST_DATE_TIME", requestDate);
		request.put("DATA_TYPE", "UID");
		request.put("REFERENCE_KEY", referrenceKey);
		request.put("TXNSEC_KEY", txnSecKey);
		reqMes = request.toString();
		return reqMes;
	}

	public String buildRequestMaskedPan(String reqMes,
			String referrenceKey, String requestDate, String txnSecKey,
			String requestRefNumber) throws JSONException {

		JSONObject request = new JSONObject();
		request.put("SOURCE_ID", "PREP");
		request.put("REQUEST_REF_NO", requestRefNumber);
		request.put("REQUEST_CODE", "AV05");
		request.put("REQUEST_DATE_TIME", requestDate);
		request.put("DATA_TYPE", "UID");
		request.put("REFERENCE_KEY", referrenceKey);
		request.put("TXNSEC_KEY", txnSecKey);
		reqMes = request.toString();
		return reqMes;
	}
	
	private static HttpComponentsClientHttpRequestFactory useApacheHttpClientWithSelfSignedSupport()
			throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

		// Creation of TrustStrategy
		TrustStrategy acceptingTrustStrategy = new TrustStrategy() {

			@Override
			public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				// TODO Auto-generated method stub
				return true;
			}
		};

		// Creation of SSLContect using TrustStrategy
		SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy)
				.build();
		SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext);

		CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();

		HttpComponentsClientHttpRequestFactory useApacheHttpClient = new HttpComponentsClientHttpRequestFactory();

		useApacheHttpClient.setHttpClient(httpClient);
		useApacheHttpClient.setReadTimeout(20000);
		useApacheHttpClient.setConnectTimeout(10000);
		return useApacheHttpClient;
	}
	
	

	private static ByteArrayHttpMessageConverter generateByteArrayHttpMessageConverter() {
		ByteArrayHttpMessageConverter byteArrayHttpMessageConverter = new ByteArrayHttpMessageConverter();
		List<MediaType> supportedApplicationTypes = new ArrayList<MediaType>();
		supportedApplicationTypes.add(new MediaType("application", "json"));
		supportedApplicationTypes.add(new MediaType("application", "txt"));
		byteArrayHttpMessageConverter.setSupportedMediaTypes(supportedApplicationTypes);
		return byteArrayHttpMessageConverter;
	}


	/**
	 * Build GET OTP request 
	 * @param txnNo 
	 * @param ts 
	 * @param myOTP 
	 * @param deviceNumber 
	 * @param channel 
	 * @param uidType 
	 * @param uidInputData 
	 * @param referenceNumber 
	 * @param requestRefNumber 
	 * @param txnNo 
	 * @param residentConsent 
	 * @param residentAuthenticationType 
	 * @param certExpiryDate 
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 *  
	 * */
	public String buildGetOtpDetailsRequest(String referenceNumber,
			String uidInputData, String uidType, String channel,
			String deviceNumber, String myOTP, String ts, String txnNo, 
			char residentAuthenticationType, char residentConsent, Date certExpiryDate)
			throws JSONException, ParseException, IllegalStateException,
			InvalidCipherTextException, IOException, GeneralSecurityException 
			{
		
			/**
			 *  PID block 
			 * 
			 * */
			
			byte[] pidXmlBytes = getPidXMLBytes(ts,myOTP); 
			System.out.println("PID block bytes ::: "+pidXmlBytes);
			
			/**
			 * Step 1 :: Generate Session Key
			 * 
			 * */
			
			byte[] sessionKey = EncrypterAadhaar.generateSessionKey();
			System.out.println("AES Session Key bytes ::: "+ sessionKey);
			
			/**
			 * Step 2 :: Generate Hmac plain bytes using pid plain bytes
			 * 
			 * */
			
			byte[] hmac = generateSha256Hash(pidXmlBytes);
			System.out.println("hmac Key SHA-256 bytes::: "+ hmac);

			/**
			 * Step 3 ::  Generate IV -  Last 12 bytes of ts (time stamp) 
			 * 
			 * */
			
			byte[] iv = EncrypterAadhaar.generateIv(ts);
			System.out.println("iv 12 bytes::: "+ iv);

			/**
			 * Step 4 ::  Generate AAD -   Last 16 bytes of the ts (time stamp) 
			 * 
			 * */
			
			byte[] aad = EncrypterAadhaar.generateAad(ts); 
			System.out.println("aad 16 bytes::: "+ aad);
			
			
			JSONObject request = new JSONObject();
			request.put("ReferenceNumber", referenceNumber); 		   							 // OK
			request.put("UID", uidInputData);                 		  							 // OK
			request.put("UIDType", uidType);                 		   							 // OK
			request.put("Channel", channel);                  		   							 // OK
			request.put("ResidentAuthenticationType",residentAuthenticationType);   		     // OK
			request.put("ResidentConsent", residentConsent);           							 // OK
			request.put("DeviceInformation", deviceNumber);   		   							 // OK
			request.put("TxnNo",txnNo ); 					              						 // OK
			
			
			/**
			 * PID Format(X-XML, P- Protobuf binary format)
			 * 
			 * */
			
			request.put("PIDFormat", "X");		   							 // OK
			
			
			/**
			 * AES/GCM Encryption of  PID block using Secret key 
			 * 
			 * */
			request.put("EncryptedData", getPIDEncryptedData(myOTP,ts,pidXmlBytes,sessionKey,iv,aad).toString());  // OK
			
			
			/**
			 * Terminal Device ID(Alpha Numeric)  
			 * 
			 * */
			request.put("Hmac",  getHmacEncriptedData(ts,sessionKey,iv,aad,hmac).toString());                      // OK
			
			
		
			/**
			 * UIDAI Public key certificate expiration date in the format “YYYYMMDD”. 
			 * 
			 * */
			request.put("Skey_Ci", EncrypterAadhaar.getCertificateIdentifier());                                			   // OK
			
			
			/**
			 * RSA Encryption of  Secret key using UIDAI public key 
			 * 
			 * */
			
			
			byte[]  encryptedSessionKey = EncrypterAadhaar.encryptUsingPublicKey(sessionKey);
			
			request.put("Skey", encryptedSessionKey);                                   								// NA
		
	
			// Get “ki” value (seed key) using new session key
//			SynchronizedKey synchronizedKey = new SynchronizedKey(EncrypterAadhaar.generateSessionKey(), UUID.randomUUID().toString(), new Date());
//			String keyIdentifier = synchronizedKey.getKeyIdentifier(); 

			// request.put("DpId", "");
			// request.put("RdsId", "");
			// request.put("RdsVer", "");
			// request.put("Dc", "");
			// request.put("Mi", "");
			// request.put("Mc", "");
			
			
			System.out.println("AES Session Key Bytes::: "+ sessionKey.toString());
			System.out.println("Request Data::: " + request.toString());
			return request.toString();
	}
	
	
	/**
	 * Generate the Hmac Encrypted data
	 * @param ts 
	 * @param sessionKey 
	 * @param aad 
	 * @param iv 
	 * @param hmac
	 * @throws UnsupportedEncodingException 
	 * 
	 * */
	
	public byte[] getHmacEncriptedData(String ts, byte[] sessionKey, byte[] iv, byte[] aad, byte[] hmac) throws IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException
	{
		/**
		 * packedEncXMLPIDData is encrypted pid data can be used to send to uidai
		 * Encrypt Hmac plain bytes using generated plain session key
		 * */
		byte[]  encryptedHmacBytes = EncrypterAadhaar.encryptUsingSessionKey(true, sessionKey, iv, aad, hmac);
		
		byte[] tsInBytes = ts.getBytes("UTF-8");
		byte[] packedEncryptedHmacBytes = new byte[encryptedHmacBytes.length + tsInBytes.length];
		
		System.out.println("encryptedHmacBytes bytes ::: "+ encryptedHmacBytes);
		System.out.println("packedEncryptedHmacBytes bytes ::: "+ packedEncryptedHmacBytes.toString());
		
		return encryptedHmacBytes;
	}

	/**
	 * Generate the Encrypted data
	 * @param pidXmlBytes 
	 * @param sessionKey 
	 * @param aad 
	 * @param iv 
	 * 
	 * */
	private byte[] getPIDEncryptedData(String myOTP, String ts, byte[] pidXmlBytes, byte[] sessionKey, byte[] iv, byte[] aad)
			throws ParseException, IllegalStateException,
			InvalidCipherTextException, IOException, GeneralSecurityException {
		
	
	/**
	 * Encrypt pid plain bytes using generated
	 * plain session key and pack it
	 * */
		byte[] encXMLPIDData = EncrypterAadhaar.encryptUsingSessionKey(true, sessionKey, iv, aad, pidXmlBytes);
	
		
		byte[] tsInBytes = ts.getBytes("UTF-8");
		byte[] packedEncXMLPIDData = new byte[encXMLPIDData.length + tsInBytes.length];
		
		System.arraycopy(tsInBytes, 0, packedEncXMLPIDData, 0, tsInBytes.length);
		System.arraycopy(encXMLPIDData, 0, packedEncXMLPIDData, tsInBytes.length, encXMLPIDData.length);
		
		
		System.out.println("encXMLPIDData bytes ::: "+ encXMLPIDData);
		System.out.println("packedEncXMLPIDData bytes ::: "+ packedEncXMLPIDData.toString());
		return encXMLPIDData;
		
	}
	
	
	
	
	/**
	 * Generate Bytes of XML PID Block
	 * @param ts 
	 * @param myOTP 
	 * 
	 * */
	
	private byte[] getPidXMLBytes(String ts, String myOTP) {
		System.out.println("PID Block String ::: "+"<Pid ts= " + ts + " ver=" + "\"2.0\">"+ "<PV otp=" + myOTP + "/></Pid>");
		return ("<Pid ts= " + ts + "ver=" + "\"2.0\">"+ "<PV otp=" + myOTP + "/></Pid>").getBytes();
	}

// <Pid ts="" ver="2.0"> <PV otp=”OTP Value” /> </Pid> 
// <Pid ts= 2018-06-17T05:36:17 ver="2.0"> <PV otp=146323/> </Pid>	

	
	/**
	 * Generate Sha256Hash
	 * @param message
	 * 
	 * */
	
	
	public byte[] generateSha256Hash(byte[] message) {
		String algorithm = "SHA-256";
		String SECURITY_PROVIDER = "BC";
		byte[] hash = null;
		MessageDigest digest;
		try {
		digest = MessageDigest.getInstance(algorithm, SECURITY_PROVIDER);
		digest.reset();
		hash = digest.digest(message);
		} catch (Exception e) {
		e.printStackTrace();
		}
		return hash;
		} 
	

	public static String genRRN(){
		StringBuffer buffer = new StringBuffer();
		synchronized (AadharVaultClient.class) {
			GregorianCalendar currentGC = new GregorianCalendar();
			long currentTimeInMS = currentGC.getTimeInMillis();
			int day = currentGC.get(GregorianCalendar.DAY_OF_YEAR);
			
			buffer.append(String.valueOf(currentGC.get(GregorianCalendar.YEAR))
					.substring(3));
			String dayStr = String.valueOf(day); 				
			while(dayStr.length() < 3){
				dayStr = "0" + dayStr;
			}

			buffer.append(dayStr);
			String first = "";			
			if(currentTimeInMS != lastTime){
				if((lastTime + count) >= currentTimeInMS){
					try {
						long tmp = (lastTime + count + 1) - currentTimeInMS;
						Thread.sleep(tmp);
						currentTimeInMS += tmp;
					} catch (InterruptedException e) {
					}
				}
				lastTime = currentTimeInMS;
				count = 1;
				first = String.valueOf(currentTimeInMS + count).substring(String.valueOf(currentTimeInMS + count).length() - 8);				
			}else{
				count ++;
				first = String.valueOf(currentTimeInMS + count).substring(String.valueOf(currentTimeInMS + count).length() - 8);
			}			
			Integer rrnL = Integer.valueOf(first);				
			int current = rrnL/changeOver;
			int mod = rrnL%changeOver;
			int next = 0;			
			if(current % 2 == 0){
				next = base - (current/2 + 1);
			}else{
				next = current/2;
			}		
			int rrnInt = (next  * changeOver)  + mod; 
			String rrnStr = String.valueOf(rrnInt);
			if(rrnStr.length() < 8){
				while(rrnStr.length() < 8){
					rrnStr = "0" + rrnStr;
				}
			}
			buffer.append(rrnStr);
			try {
				Thread.sleep(2L);
			} catch (InterruptedException e) {				
			}
		}
		if(buffer.length() != 12){
			return genRRN();
		}else{
			return buffer.toString();
		}
	}	
}





/**
 * Generate SynchronizedKey
 * 
 * */
class SynchronizedKey {
	byte[] seedSkey;
	String keyIdentifier;
	Date seedCreationDate;

	public SynchronizedKey(byte[] seedSkey, String keyIdentifier,
			Date seedCreationDate) {
		super();
		this.seedSkey = seedSkey;
		this.keyIdentifier = keyIdentifier;
		this.seedCreationDate = seedCreationDate;
	}

	public String getKeyIdentifier() {
		return keyIdentifier;
	}

	public Date getSeedCreationDate() {
		return seedCreationDate;
	}

	public byte[] getSeedSkey() {
		return seedSkey;
	}
}



final class SessionKeyDetails {
	/**
	 * Flag indicating whether synchronized key being used.
	 */
	boolean isSynchronizedKeySchemeUsed;
	/**
	 * Flag indicating whether this session key represents initialize of
	 * synchronized key, in which case a seed key will be used along with key
	 * identifier.
	 */
	boolean isSynchronizedKeyBeingInitialized;
	/**
	 * Seed skey for synchronized key scheme. It is a RSA2048 encrypted AES key,
	 * that is encrypted using UIDAI public key.
	 */
	byte[] seedSkeyForSynchronizedKey;
	/**
	 * Random number for synchronized key scheme
	 */
	byte[] randomNumberForSynchornizedKey;
	/**
	 * Key identifier for synchronized key scheme
	 */
	String keyIdentifier;
	/**
	 * Skey value when not using synchronized key. It is a RSA2048 encrypted AES
	 * key, that is encrypted using UIDAI public key.
	 */
	byte[] normalSkey;

	private SessionKeyDetails() {
	}

	public static SessionKeyDetails createSkeyToInitializeSynchronizedKey(
			String ki, byte[] encyprtedSeedKey) {
		SessionKeyDetails d = new SessionKeyDetails();
		d.setSynchronizedKeySchemeUsed(true);
		d.setKeyIdentifier(ki);

		d.setSynchornizedKeyBeingInitialized(true);
		d.setSeedSkeyForSynchronizedKey(encyprtedSeedKey);
		return d;
	}

	public static SessionKeyDetails createSkeyToUsePreviouslyGeneratedSynchronizedKey(
			String ki, byte[] synchronizedKeyRandom) {
		SessionKeyDetails d = new SessionKeyDetails();
		d.setSynchronizedKeySchemeUsed(true);
		d.setKeyIdentifier(ki);
		d.setSynchornizedKeyBeingInitialized(false);
		d.setRandomNumberForSynchornizedKey(synchronizedKeyRandom);
		return d;
	}

	public static SessionKeyDetails createNormalSkey(byte[] encyprtedSeedKey) {
		SessionKeyDetails d = new SessionKeyDetails();
		d.setSynchronizedKeySchemeUsed(false);
		d.setNormalSkey(encyprtedSeedKey);
		return d;
	}

	public String getKeyIdentifier() {
		if (isSynchronizedKeySchemeUsed) {
			return this.keyIdentifier;
		} else {
			return null;
		}
	}

	public byte[] getSkeyValue() {
		if (isSynchronizedKeySchemeUsed) {
			if (isSynchronizedKeyBeingInitialized) {
				return this.seedSkeyForSynchronizedKey;
			} else {
				return this.randomNumberForSynchornizedKey;
			}
		} else {
			return this.normalSkey;
		}
	}

	public void setKeyIdentifier(String ki) {
		this.keyIdentifier = ki;
	}

	public void setSeedSkeyForSynchronizedKey(byte[] seedSkey) {
		this.seedSkeyForSynchronizedKey = seedSkey;
	}

	public void setSynchronizedKeySchemeUsed(boolean isSSK) {
		this.isSynchronizedKeySchemeUsed = isSSK;
	}

	public void setSynchornizedKeyBeingInitialized(boolean sskInit) {
		this.isSynchronizedKeyBeingInitialized = sskInit;
	}

	public void setRandomNumberForSynchornizedKey(byte[] sskRandom) {
		this.randomNumberForSynchornizedKey = sskRandom;
	}

	public void setNormalSkey(byte[] normalSkey) {
		this.normalSkey = normalSkey;
	}
}



final class EncrypterAadhaar {
	private static final String JCE_PROVIDER = "BC";
	private static final String ASYMMETRIC_ALGO = "RSA/ECB/PKCS1Padding";
	// AES-GCM parameters
	// AES Key size - in bits
	public static final int AES_KEY_SIZE_BITS = 256;
	// IV length - last 96 bits of ISO format timestamp
	public static final int IV_SIZE_BITS = 96;
	// Additional authentication data - last 128 bits of ISO format timestamp
	public static final int AAD_SIZE_BITS = 128;
	// Authentication tag length - in bits
	public static final int AUTH_TAG_SIZE_BITS = 128;
	private static final String CERTIFICATE_TYPE = "X.509";
	private static PublicKey publicKey;
	public static Date certExpiryDate;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * @param publicKeyFileName
	 * Location of UIDAI public key file (.cer file)
	 * @return 
	 */
	public static void getPublicKeyAndExpDate(String publicKeyFileName) {
		FileInputStream fileInputStream = null;
		try {
			
			File fileName=new File(publicKeyFileName);
			
			if(fileName.exists())
			{
				System.out.println("File Name ::: "+fileName);
				fileInputStream = new FileInputStream(fileName);
			}
			
			CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE, JCE_PROVIDER);
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fileInputStream);
			publicKey = cert.getPublicKey();
			certExpiryDate = cert.getNotAfter();
			
			System.out.println("publicKey ::: "+ publicKey);
			System.out.println("certExpiryDate ::: "+ certExpiryDate);
			
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Could not intialize encryption module",
					e);
		} finally {
			if (fileInputStream != null) {
				try {
					fileInputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	
	/**
	 * Creates a AES key that can be used as session key (skey)
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static byte[] generateSessionKey() throws NoSuchAlgorithmException,
			NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES", "BC");
		kgen.init(AES_KEY_SIZE_BITS);
		SecretKey key = kgen.generateKey();
		System.out.println("AES Session Key String ::: "+ key.toString());
		byte[] symmKey = key.getEncoded();
		return symmKey;
	}

	
	/**
	 * Encrypts given data using UIDAI public key
	 * @param data Data to encrypt
	 * @return Encrypted data
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static byte[] encryptUsingPublicKey(byte[] data) throws IOException,
			GeneralSecurityException {
		Cipher pkCipher = Cipher.getInstance(ASYMMETRIC_ALGO, "BC");
		pkCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encSessionKey = pkCipher.doFinal(data);
		return encSessionKey;
	}

	/**
	 * Encrypts given data using session key, iv, aad
	 * 
	 * @param cipherOperation
	 *            - true for encrypt, false otherwise
	 * @param skey
	 *            - Session key
	 * @param iv
	 *            - initialization vector or nonce
	 * @param aad
	 *            - additional authenticated data
	 * @param data
	 *            - data to encrypt
	 * @return encrypted data
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 */
	public static byte[] encryptUsingSessionKey(boolean cipherOperation,
			byte[] skey, byte[] iv, byte[] aad,

			byte[] data) throws IllegalStateException,
			InvalidCipherTextException {
		AEADParameters aeadParam = new AEADParameters(new KeyParameter(skey),
				AUTH_TAG_SIZE_BITS, iv, aad);
		GCMBlockCipher gcmb = new GCMBlockCipher(new AESEngine());
		gcmb.init(cipherOperation, aeadParam);
		int outputSize = gcmb.getOutputSize(data.length);
		byte[] result = new byte[outputSize];
		int processLen = gcmb.processBytes(data, 0, data.length, result, 0);
		gcmb.doFinal(result, processLen);
		return result;
	}

	/**
	 * Generate IV using timestamp
	 * 
	 * @param ts
	 *            - timestamp string
	 * @return 12 bytes array
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] generateIv(String ts)
			throws UnsupportedEncodingException {
		return getLastBits(ts, IV_SIZE_BITS / 8);
	}

	/**
	 * Generate AAD using timestamp
	 * 
	 * @param ts
	 *            - timestamp string
	 * @return 16 bytes array
	 * @throws UnsupportedEncodingException
	 */
	public static byte[] generateAad(String ts)
			throws UnsupportedEncodingException {
		return getLastBits(ts, AAD_SIZE_BITS / 8);
	}

	/**
	 * Fetch specified last bits from String
	 * 
	 * @param ts
	 *            - timestamp string
	 * @param bits
	 *            - no of bits to fetch
	 * @return byte array of specified length
	 * @throws UnsupportedEncodingException
	 */
	private static byte[] getLastBits(String ts, int bits)
			throws UnsupportedEncodingException {
		byte[] tsInBytes = ts.getBytes("UTF-8");
		return Arrays.copyOfRange(tsInBytes, tsInBytes.length - bits,
				tsInBytes.length);
	}


	/**
	 * Returns UIDAI certificate's expiry date in YYYYMMDD format using GMT time
	 * zone. It can be used as certificate identifier
	 *
	 * @return Certificate identifier for UIDAI public certificate
	 */
	public static String getCertificateIdentifier() {
		SimpleDateFormat ciDateFormat = new SimpleDateFormat("yyyyMMdd");
		ciDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		String certificateIdentifier = ciDateFormat.format(certExpiryDate);
		return certificateIdentifier;
	}
}