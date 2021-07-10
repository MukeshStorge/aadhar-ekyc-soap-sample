package src.addharConnectionTest;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.web.client.RestTemplate;


/**
 * @author Mk
 * @year 2016
 * 
 * */
public class AadharVaultClient {

	public static final String POST = "POST";
	static HttpHeaders httpHeader = new HttpHeaders();
	static String resMessage = null;
	private static int changeOver = 100;
	private static int max = 100000000;
	private static int base = max/changeOver;
	private static long lastTime = 0;
	private static int count = 0;
	
	
	
	public static void main(String args[]) {
		try {
			
			String aadharNo="584589045995"; //Input Change - 1
			String refKey="";//Input Change - 2
			
			
			String reqDateTime = null;
			SimpleDateFormat df = new SimpleDateFormat("yyyyMMddHHmmss");
			SimpleDateFormat dateTimesdf = new SimpleDateFormat("MMddHHmmss");
			Calendar c1 = Calendar.getInstance();
			reqDateTime = df.format(c1.getTime());
			String referenceNumber = null;
			String rrn = genRRN();
			referenceNumber = "AV" + dateTimesdf.format(new Date()) + rrn;
			AadharVaultClient aadharVaultClient = new AadharVaultClient();
			String securityKey="c0eed2cc-2f7a-462d-8627-ee5e72f9a267";
			String uRL="https://uatiib.co.in/vault/v1/testQryDataReq";
			
//			String buildedReq = aadharVaultClient
//					.getRefKeyPassAadharRequest("QryRefKey",        //Input Change - 1
//							reqDateTime, referenceNumber, aadharNo,securityKey);
			
//			String buildedReq = aadharVaultClient
//					.getAadharPassRefKeyRequest("QryDataReq",        //Input Change - 2
//							reqDateTime, referenceNumber, refKey,securityKey);
			
			String buildedReq = aadharVaultClient.getMaskedAadharPassRefKeyRequest("QryMaskedDataReq",      //Input Change - 3    
					reqDateTime, referenceNumber, refKey,securityKey);
					
			String buildedResponse = serviceCallForAadhaar(buildedReq,uRL);
			
			
			JSONObject buildedJsonReq = aadharVaultClient
					.getRefKeyPassAadharResponse(buildedResponse);
			
			JSONObject buildedJsonResponse = aadharVaultClient
					.getRefKeyPassAadharResponse(buildedResponse);
			
			System.out.println("Final Request :::: "+buildedJsonReq.toString());
			System.out.println("Final Response :::: "+buildedJsonResponse.toString());
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	
	

	public static String serviceCallForAadhaar(String command,String uRL) {
		try {
			RestTemplate rest = initRestTemplateForByteArrayAndSelfSignedHttps();
			httpHeader.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
			httpHeader.setContentType(MediaType.ALL);
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

	public JSONObject getRefKeyPassAadharResponse(String buildedResponse) {

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

	public JSONObject getAadharPassRefKeyResponse(String buildedResponse) {

		try {
			if (resMessage != null) {
				System.out.println("Aadhar Number response ::: " + resMessage);
				JSONObject jsonObj = new JSONObject(buildedResponse);
				return jsonObj;
			} else {
				System.out.println("No response from EIS connect~~~~~~~~~~");
				System.out.println("Aadhar Number response ::: " + resMessage);
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
		request.put("SOURCE_ID", "INB");
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
		request.put("SOURCE_ID", "INB");
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
		request.put("SOURCE_ID", "INB");
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