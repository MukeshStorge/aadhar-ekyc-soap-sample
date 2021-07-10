package src.addharConnectionTest;

import java.io.StringReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
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
import org.xml.sax.InputSource;


/**
 * @author Mk
 * @year 2016
 * 
 * */
public class AadharOtpAPI {

	public static final String POST = "POST";
	static BasicHeader jsonHeader = new BasicHeader("Content-Type",	"application/json");
	static HttpHeaders httpHeader = new HttpHeaders();
	static String resMessage = null;
	private static int changeOver = 100;
	private static int max = 100000000;
	private static int base = max/changeOver;
	private static long lastTime = 0;
	private static int count = 0;
	private static String targetURL="https://uatiib.co.in/vault/v1/testQryRefKey"; //Change 1
	
	
	public static void main(String args[]) {
		try {
			
			String uidInputData="584589045995"; //Input Change - 2 // Aadhaar Number/ VID/ UID Token/REFERENCE KEY 
			String uidType="0"; //Input Change - 3  // 0-Aadhaar Number 2-Virtual ID(VID) 3-UID Token 9-REFERENCE KEY 
			String tellerId="1234567" ; //Input Change - 4
			String branchCode = "55555";//Input Change - 5
			String channel="IN"; //Input Change - 6
			String deviceNumber= "5555512"; //branchCode + userId 
			
			SimpleDateFormat dateTimesdf = new SimpleDateFormat("MMddHHmmss");
			String referenceNumber = null;
			String rrn = genRRN();
			referenceNumber = "AV" + dateTimesdf.format(new Date()) + rrn;
			
			AadharOtpAPI aadharVaultClient = new AadharOtpAPI();
			
			String buildedReq = aadharVaultClient
					.generateOtpBuildRequest(referenceNumber, uidInputData,uidType,tellerId,branchCode,channel,deviceNumber);
			
			String buildedResponse = serviceCallForAadhaar(buildedReq);
			
			DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource isNew = new InputSource();
			isNew.setCharacterStream(new StringReader(buildedResponse));
			Document doc = db.parse(isNew);

	        XPathFactory xpf = XPathFactory.newInstance();
	        XPath xpath = xpf.newXPath();
	        Element userElement = (Element) xpath.evaluate("OtpResponse", doc, XPathConstants.NODE);
	        
	        System.out.println(userElement.getAttribute("status"));
	        System.out.println(userElement.getAttribute("err"));
	        System.out.println(userElement.getAttribute("uref"));
	        System.out.println(userElement.getAttribute("TxnNo"));
			System.out.println("Final Request :::: "+buildedReq);
			System.out.println("Final Response :::: "+buildedResponse);
			
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	

	public static String serviceCallForAadhaar(String command) {
		try {
			RestTemplate rest = initRestTemplateForByteArrayAndSelfSignedHttps();
			HttpEntity<String> entity = new HttpEntity<>(command, httpHeader);
			resMessage = rest.postForObject(targetURL, entity,String.class); //Input Change - 3
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		return resMessage;
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

	
	
	private static RestTemplate initRestTemplateForByteArrayAndSelfSignedHttps()
			throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
		RestTemplate restTemplate = new RestTemplate(useApacheHttpClientWithSelfSignedSupport());
		restTemplate.getMessageConverters().add(generateByteArrayHttpMessageConverter());
		return restTemplate;
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