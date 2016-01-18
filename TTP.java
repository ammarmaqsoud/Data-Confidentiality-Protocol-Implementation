import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Random;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Base64;

public class TTP {
	
	static String MeanA, MeanB, Eoutput;
	String A1,B1,input,MeanA1,MeanB1,hash, hashMean;
	static final int bit_length = 64, Time_Limit = 2000, RSA_bit_length =512;
	static Double denomenator, Addition, Mean;
	static BigInteger p,q,K,g,y;
	static BigInteger x = new BigInteger("152543");
	static BigInteger e_ttp,N_ttp, d_ttp;
	
	static BigInteger e_cloud,N_cloud;
	static Timestamp ts,ts_mul, ts_add, ts_mean, ts_variance;
	BufferedReader in;
	PrintWriter out;
	
	Random r_ran = new SecureRandom();
	BigInteger r = new BigInteger(bit_length,r_ran);
	
 
	
	
	
	JFrame frame = new JFrame("Third party  Program");
	JTextArea messageArea = new JTextArea(50, 60);
	private static final String UNICODE_FORMAT = "UTF8";
	public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";
	private KeySpec ks;
 
	private SecretKeyFactory skf;
	private static Cipher cipher;
	byte[] arrayBytes;
	private String myEncryptionKey;
	private String myEncryptionScheme;
	static SecretKey key;
	
	public TTP() {
		messageArea.setEditable(false);
		frame.getContentPane().add(new JScrollPane(messageArea), "Center");
		frame.pack();
		}
	
	private String getServerAddress() {
	return JOptionPane.showInputDialog(
	frame,
	"Enter IP Address of the Server:",
	"Cloud Server Address",
	JOptionPane.QUESTION_MESSAGE);
	}
	
	private void run() throws IOException, InvalidKeyException,
	NoSuchAlgorithmException, NoSuchPaddingException,
	InvalidKeySpecException {
	int sessionNum = 0;
	messageArea.append("\n\n\t******************" 	+"******************************************\n" + 	"\t===========================================\n" +	"\t********** A N A L Y Z E R ***** P R O G R A M	***********\n" +
	"\t===========================================" +
	"\n\t************************"
	+"************************************\n\n\n");
	RSA();
	ElGamalParameter(bit_length);
	String serverAddress = getServerAddress();
	Socket socket = new Socket(serverAddress, 9002);
	in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	out = new PrintWriter(socket.getOutputStream(), true);
	out.println("ttp_AUTH_REQ"+" "+e_ttp+" "+N_ttp);
	messageArea.append("@@ Authentication Request Sent at 	"+getCurrentTimestamp()+"\n\n");
	while (true) {
	String line = in.readLine();
	if (line.startsWith("Cloud_Encrypt")) {
	String P[] = line.split(" ");
	e_cloud = new BigInteger(P[1]);
	N_cloud = new BigInteger(P[2]);
	}
	else if(line.startsWith("Hadoop_AUTH_RES")){
		messageArea.append("Authentication Initiated\n\n");
		ts = getCurrentTimestamp();
		String D[] = line.split(" ");
		
		messageArea.append(line);
		
		BigInteger DD = DoubleDecrypt(new BigInteger(D[1]));
	//	messageArea.append("\n");
	//	messageArea.append("                                    " +" "+DD.toString());
		
		String DDStr = new String(DD.toByteArray());
		String des[] = DDStr.split(" ");
	//	messageArea.append("\n");
	//	messageArea.append("                                    " +" "+des.toString());
		
		//Extracting the Triple DES key phrase from the received message
		myEncryptionKey = des[0];
		//Generating Triple DES symmetric key from key phrase
		myEncryptionScheme = DESEDE_ENCRYPTION_SCHEME;
		
		arrayBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
		ks = new DESedeKeySpec(arrayBytes);
		skf = SecretKeyFactory.getInstance(myEncryptionScheme);
		cipher = Cipher.getInstance(myEncryptionScheme);
		key = skf.generateSecret(ks);//generateSecret(ks,"AES");
		//for	(int i=0;i<des.length;i++)
	 //	messageArea.append(des[i]);
		String Ts1 = des[1] +" "+des[2];
		//Checking the time stamps
		if((checkTimestamp(Ts1, ts, messageArea)).intValue() <Time_Limit){
		Timestamp DesTs = setTimestamp(Ts1);
		Long tsDes = DesTs.getTime();
		tsDes++;
		Timestamp TSres = new Timestamp(tsDes);
		String AuthRes = TSres.toString()+" "+p+" "+q+" "+K+" "+g+" "+y;
		BigInteger res = DoubleEncrypt(new BigInteger(AuthRes.getBytes()));
		
		out.println("ttp_AUTH_RES"+" "+res.toString());
		messageArea.append("@@ Authenticaition response sent at "+getCurrentTimestamp()+"\n\n");
		}else {
		messageArea.append("Timestamp exceeds the time 	limit");
		}
		}
	
		else if(line.startsWith("Summation")){
		sessionNum++;
		messageArea.append("Session "+sessionNum+" Answers\n\n");
		ts = getCurrentTimestamp();
		messageArea.append("@@ Summation received at : "+ts+"\n");
		 
		String M[] = line.split(" ");
		String Answers1 = TripleDESdecrypt(M[1]);
		//messageArea.append("@@ Ammar   Answers1: "+Answers1+"\n");
		String Ans1[] = Answers1.split(" ");
		try {
			
			hash = Hash(Ans1[0]+" "+Ans1[1]+" "+Ans1[2]);
		} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
		}
		if ((hash.compareTo(Ans1[3])) == 0){
		messageArea.append("Answer Hash is correct\n\n");
		out.println("CORRECT_HASH");
		if((checkTimestamp(Ans1[4]+" "+Ans1[5], ts,messageArea)).intValue() < Time_Limit)
		{
		messageArea.append("Timestamp is within the time limit\n\n");
		denomenator = new Double(Ans1[0]);
		BigInteger AdditionA = new BigInteger(Ans1[1]);
		BigInteger AdditionB = new BigInteger(Ans1[2]);
		Addition =Decryption(AdditionA,AdditionB,p,x).doubleValue();
				messageArea.append("** Addition = "+(Addition/100)+"\n\n");
				messageArea.append("@@ Addition time : " +getCurrentTimestamp()+"\n\n");
				Mean = (Addition/denomenator);
				Long LongMean = Mean.longValue();
				String StrMean = LongMean.toString();
				messageArea.append("** Mean = "+(Mean/100)+"\n\n");
				messageArea.append("@@ Mean time : " +getCurrentTimestamp()+"\n\n");
				Encryption(StrMean,messageArea);
				String EMean = MeanA+" "+MeanB;
				try {hash = Hash(EMean);
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
					}
					messageArea.append("Hash : "+hash+"\n");
					String output = EMean+" "+hash+" "+getCurrentTimestamp().toString();
					messageArea.append("Unencrypted message : "+output+"\n");
					Eoutput = TripleDESencrypt(output,cipher);
					messageArea.append("Encrypted message : "+Eoutput+"\n\n");
					out.println("MEAN"+" "+Eoutput);
					messageArea.append("@@ Computed MEAN sent at "+getCurrentTimestamp()+"\n\n");
					}else{
						
						messageArea.append("Timestamp exceeds the time limit");
								}
								}else{
								messageArea.append("Hash is incorrect\nWaiting for Resending....");
								out.println("INCORRECT_HASH_MEAN");
								}
								}
	
		
		
		else if(line.startsWith("STAT_Para")){
								messageArea.append("@@ Answers received at "+getCurrentTimestamp()+"\n\n");
								ts = getCurrentTimestamp();
								String EAns[] = line.split(" ");
								String Ans = TripleDESdecrypt(EAns[1]);
								String Ans1[] = Ans.split(" ");
								try {
									hash = Hash(Ans1[0]+" "+Ans1[1]+" "+Ans1[2]+" "+Ans1[3]+" "+Ans1[4]+" "+Ans1[5]);
											} catch (NoSuchAlgorithmException e) {
											e.printStackTrace();
											}
											if ((hash.compareTo(Ans1[6])) == 0){
											messageArea.append("STAT Para Hash is correct\n\n");
											out.println("CORRECT_HASH");
											if((checkTimestamp(Ans1[7]+" "+Ans1[8], ts,messageArea)).intValue() < Time_Limit){
											messageArea.append("Timestamp is within the time limit\n\n");
											BigInteger VarianceA = new
											BigInteger(Ans1[0]);
											BigInteger VarianceB = new BigInteger(Ans1[1]);									
											Double Variance =Decryption(VarianceA,VarianceB,p,x).doubleValue()/10000;
											Variance = (Variance / denomenator);
											messageArea.append("**********************************A N S W E R S	**********************************\n\n");
											messageArea.append("** Addition = "+(Addition/100)+"\n");
											messageArea.append("** Mean ="+(Mean/100)+"\n");
											System.out.println("Variance Answer = "+Variance);
											messageArea.append("** Variance = "+Variance+"\n");
											Timestamp ts_var = getCurrentTimestamp();
											Double StandardDeviation =Math.sqrt(Variance.doubleValue());
											messageArea.append("** Standard Deviation = "+StandardDeviation+"\n");
											messageArea.append("@@ Session "+sessionNum+"Concluding time : "+getCurrentTimestamp()+"\n\n\n\n");
											out.println("FINISH");
}else{
messageArea.append("Timestamp exceeds the time limit");
}
} else {
messageArea.append("Hash is incorrect");
out.println("INCORRECT_HASH_VARIENCE");
}
}
else{
System.out.println(input);
}
}
	}
	//--------------------------------------------------------------
	public static Timestamp getCurrentTimestamp(){
		return new Timestamp(System.currentTimeMillis());
		}
	//--------------------------------------------------------------
	public static Timestamp setTimestamp(String ts){
	return Timestamp.valueOf(ts);
	}
//	--------------------------------------------------------------
	public static Long checkTimestamp(String ts0, Timestamp ts2,JTextArea messageArea){
	Timestamp ts1 = setTimestamp(ts0);
	Long difference = ts2.getTime()-ts1.getTime();
	return difference;
	}
	
	//--------------------------------------------------------------
	public static String Hash (String message) throws NoSuchAlgorithmException{
	MessageDigest mDigest = MessageDigest.getInstance("SHA1");
	byte[] result = mDigest.digest(message.getBytes());
	StringBuffer stringbuffer = new StringBuffer();
	for (int i = 0; i < result.length; i++) {
	stringbuffer.append(Integer.toString((result[i] & 0xff) + 0x100,
	16).substring(1));
	}
	return stringbuffer.toString();
	}
	//--------------------------------------------------------------
	public void Encryption(String SalesValue, JTextArea messageArea){
		
		BigInteger N;
		messageArea.append("p = "+p+"\n");
		messageArea.append("q = "+q+"\n");
		// N = p * q
		N = p.multiply(q);
		messageArea.append("N = "+N+"\n");
		messageArea.append("y = "+y+"\n");
		messageArea.append("r = "+r+"\n");
		//Encryption Step
		String m = SalesValue;
		BigInteger M = new BigInteger(m);
		 
		//EI(M) = (M + r * p) mod N
		BigInteger bx = M.add(r.multiply(p)).mod(N);
		 
		BigInteger b = bx.multiply(y.modPow(K, p)).mod(p);
		//  g^k mod p
		BigInteger a = g.modPow(K, p);
		
		/* */
		// 
		MeanA=a.toString();
		MeanB=b.toString();
		/* */
		
		messageArea.append("Encrypted part A = "+a+"\n");
		messageArea.append("Encrypted part B = "+b+"\n\n\n");
	 
		}
	//--------------------------------------------------------------
	
	public static String TripleDESdecrypt(String encryptedString) {
	String decryptedText=null;

	
	try {
		
	cipher.init(Cipher.DECRYPT_MODE, key);
	byte[] encryptedText = Base64.decodeBase64(encryptedString);
	
	
	byte[] plainText = cipher.doFinal(encryptedText);
	decryptedText= new String(plainText);
	} catch (Exception e) {
	e.printStackTrace();
	}
	return decryptedText;	 
							}
	
	//--------------------------------------------------------------
	public static void RSA(){
	SecureRandom r = new SecureRandom();
	BigInteger p = new BigInteger(RSA_bit_length,100,r);
	BigInteger q = new BigInteger(RSA_bit_length,100,r);
	N_ttp = p.multiply(q);
	BigInteger n =(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
	e_ttp = new BigInteger("3");
	while(n.gcd(e_ttp).intValue()>1){
	e_ttp = e_ttp.add(new BigInteger("2"));
	}
	d_ttp = e_ttp.modInverse(n);
	}
	//--------------------------------------------------------------
	public static BigInteger RSAencrypt (BigInteger message,BigInteger ex,BigInteger Nx){
	return message.modPow(ex, Nx);
	}
	public static BigInteger RSAdecrypt (BigInteger message){
	return message.modPow(d_ttp, N_ttp);
	}
	public static BigInteger RSAsign (BigInteger message){
	return message.modPow(d_ttp, N_ttp);
	}
	public static BigInteger RSAunsign (BigInteger message){
//	return message.modPow(e_TTP, N_TTP);
		return message.modPow(e_cloud, N_cloud);
		
	}
	public static BigInteger DoubleEncrypt (BigInteger message){
	return RSAencrypt((RSAsign(message)),e_cloud,N_cloud);
	}
	public static BigInteger DoubleDecrypt (BigInteger message){
	return RSAunsign(RSAdecrypt(message));
	}
	
	//--------------------------------------------------------------
	public static String TripleDESencrypt(String unencryptedString, Cipher  cipher) {
	String encryptedString = null;
	try {
	cipher.init(Cipher.ENCRYPT_MODE, key);
	byte[] plainText = unencryptedString.getBytes("UTF8");
	byte[] encryptedText = cipher.doFinal(plainText);
	encryptedString = new String(Base64.encodeBase64(encryptedText));
	} catch (Exception e) {
	e.printStackTrace();
	}
	return encryptedString;
	}
	
	//--------------------------------------------------------------
	 
	public void	ElGamalParameter(int bit_length){
		
		//  BigInteger p,q,K,g,y;
		  p = new BigInteger("152549");
		  messageArea.append("p = " +p +"\n\n");
		  
		  q = new BigInteger("152547");
		  messageArea.append("q = " +q +"\n\n");
		  
		  K= new BigInteger("507222528100198841");
		  messageArea.append("K = " +K +"\n\n");
		  
		  
		  g = new BigInteger("152541");
		  messageArea.append("g = " +g +"\n\n");
		  
			//ElGamal private parameter x
		  x = new BigInteger("152543");	
		  
	      y = g.modPow(x,p);
	      messageArea.append("y = " +y +"\n\n");

	
 		
 	}
  
 
	//--------------------------------------------------------------
		
 
	public BigInteger Decryption(BigInteger A, BigInteger B,BigInteger p,BigInteger x){
			 B = B.mod(p);
			 BigInteger ZX = A.modPow(x,p); // ZX = A ^ x mod p
			 BigInteger Z = B.multiply(ZX.modInverse(p)).mod(p);
			 return Z;
			 }
	public static void main(String[] args) throws Exception {
	TTP ttp = new TTP();
	ttp.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	ttp.frame.setVisible(true);
	ttp.run();
	}
	
												
											
							 
					 
		} 