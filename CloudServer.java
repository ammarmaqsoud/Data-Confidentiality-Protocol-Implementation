import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.HashSet;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;


import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.util.ToolRunner;
 


	
	

public class CloudServer {
	private static HashSet<PrintWriter> writers = new HashSet<PrintWriter>();
	public static String ElgammalParameters, Eoutput;
	static String StrA[],StrB[];
	static String hash;
	private static final int PORT = 9002;
	static final int Time_Limit = 2000, RSA_bit_length = 512;
	static int check = 0, max_values = 50000;
	static Integer i = 0;
	static BigInteger A[], B[],p;
	static BigInteger e_cloud,N_cloud,d_cloud;
	static BigInteger e_TTP,N_TTP;
	static BigInteger e_proxy,N_proxy;
	static BigInteger SDA[],SDB[];
	static BigInteger MeanA,MeanB,VarianceA,VarianceB;
	static Timestamp ts, DesTs;
	static SecretKey key_TTP, key_Proxy;
	public static final String UNICODE_FORMAT = "UTF8";
	public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";
	public static KeySpec ks;
	public static SecretKeyFactory skf;
	public static Cipher cipher;
	static byte[] arrayBytes;
	public static String myEncryptionKey_Proxy, myEncryptionKey_TTP;
	public static String myEncryptionScheme;
	static JFrame frame = new JFrame("C L O U D S E R V E R Program");
	static JTextArea messageArea = new JTextArea(50, 60);
	

		
	public static void main(String[] args) throws Exception {
	messageArea.setEditable(false);
	frame.getContentPane().add(new JScrollPane(messageArea), "Center");
	frame.pack();
	frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	frame.setVisible(true);	
	ServerSocket listener = new ServerSocket(PORT);	
	StrA = new String[max_values];
	StrB = new String[max_values];
	A = new BigInteger[max_values];
	B = new BigInteger[max_values];
	SDA = new BigInteger[max_values];
	SDB = new BigInteger[max_values];
	RSA();
	messageArea.append("@@@@@@@@@@@@@@@ The Cloud server is running @@@@@@@@@@@@@@@@@\n\n\n");
	try {
	while (true) {
	new Handler(listener.accept()).start();
	}
	} finally {
	listener.close();
	}
	}
	private static class Handler extends Thread {
	private Socket socket;
	private BufferedReader in;
	private PrintWriter out;
	public Handler(Socket socket) {
	this.socket = socket;
	}
	public void run() {
		try {
			in = new BufferedReader(new
			InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream(), true);
			myEncryptionKey_TTP = "ThisIsSpartaThisIsSparta";
			myEncryptionScheme = DESEDE_ENCRYPTION_SCHEME;
			arrayBytes =myEncryptionKey_TTP.getBytes(UNICODE_FORMAT);
			ks = new DESedeKeySpec(arrayBytes);
			skf = SecretKeyFactory.getInstance(myEncryptionScheme);
			cipher = Cipher.getInstance(myEncryptionScheme);
			key_TTP = skf.generateSecret(ks);
			writers.add(out);
			String Add = null;
			while (true) {
			String input = in.readLine();
			if (input == null) {
			return;
			}
			else if(input.startsWith("Proxy_AUTH_REQ")){
			messageArea.append("Proxy Server is authenticating.....\n\n"); 
			
			String I[] = input.split(" ");
			e_proxy = new BigInteger(I[1]);
			N_proxy = new BigInteger(I[2]);
			check++;
			out.println("CONNECT"+" "+e_cloud+" "+N_cloud);
			messageArea.append("Authenticating response sent.....\n\n");
			}
			else if(input.startsWith("Proxy_AUTH_RES")){
			messageArea.append("Authenticating response received.....\n\n");
			ts = getCurrentTimestamp();
			String D[] = input.split(" ");
			BigInteger DD = DoubleDecrypt(new BigInteger(D[1]),e_proxy,N_proxy);
			String DDStr = new String(DD.toByteArray());
			String des[] = DDStr.split(" ");
			String myEncryptionKey_Proxy = des[0];
			myEncryptionScheme = DESEDE_ENCRYPTION_SCHEME;
			arrayBytes =myEncryptionKey_Proxy.getBytes(UNICODE_FORMAT);
			ks = new DESedeKeySpec(arrayBytes);
			skf =SecretKeyFactory.getInstance(myEncryptionScheme);
			cipher = Cipher.getInstance(myEncryptionScheme);
			key_Proxy = skf.generateSecret(ks);
			String Ts2 = des[1]+" "+des[2];
			if((checkTimestamp(Ts2, ts).intValue()) < Time_Limit){
				messageArea.append("Timestamp is within the time limits\n\n");
						Timestamp DesTs = setTimestamp(Ts2);
						Long tsDes = DesTs.getTime();
						tsDes++;
						Timestamp TSres = new Timestamp(tsDes);
						messageArea.append("TSres :"+TSres.toString()+"\n");
						messageArea.append(ElgammalParameters);
						String authRes = TSres.toString()+" "+ElgammalParameters;
						messageArea.append(authRes);
						BigInteger res = DoubleEncrypt(new BigInteger(authRes.getBytes()),e_proxy,N_proxy);
						out.println("Hadoop_AUTH_RES"+" "+res.toString());
					 
						messageArea.append("@@@@@@ DES parameters sent and Proxy authentication is verified at "+getCurrentTimestamp()+"\n\n");
								}else{
								messageArea.append("Timestamp exceeds the time limit");
								}
			}
			else if(input.startsWith("ttp_AUTH_REQ")){
			messageArea.append("TTP is authenticating....\n\n");
			messageArea.append(input+"\n\n");
			String E[] = input.split(" ");
			e_TTP = new BigInteger(E[1]);
			N_TTP = new BigInteger(E[2]);
			out.println("Cloud_Encrypt"+" "+e_cloud+" "+N_cloud);
			
			DesTs = getCurrentTimestamp();
			messageArea.append("DesTs : "+DesTs+"\n\n");
		 	String auth = myEncryptionKey_TTP+" "+DesTs.toString();
	 
					BigInteger Eauth = DoubleEncrypt(new
					BigInteger(auth.getBytes()),e_TTP,N_TTP);
					out.println("Hadoop_AUTH_RES"+" "+Eauth.toString());
					}
			
			else if(input.startsWith("ttp_AUTH_RES")){
			messageArea.append("TTP authentication response received\n\n");
			String D[] = input.split(" ");
			BigInteger DD = DoubleDecrypt(new
			BigInteger(D[1]),e_TTP,N_TTP);
			String StrDESts = new String(DD.toByteArray());
			messageArea.append("StrDESts : "+StrDESts+"\n");
			String D1[] = StrDESts.split(" ");
			String Ts = D1[0]+" "+D1[1];
			Timestamp DESts = Timestamp.valueOf(Ts);
			
			messageArea.append("DESts :"+DESts.toString()+"\n"+"DesTs : "+DesTs.toString()+"\n\n");
					if (DESts.getTime() == (DesTs.getTime() + 1)){
					messageArea.append("@@@@@@ TTP authentication completed at "+getCurrentTimestamp()+"\n\n");
					p =new BigInteger(D1[2]);
					ElgammalParameters = D1[2]+" "+D1[3]+" "+D1[4]+" "+D1[5]+" "+D1[6];
					}
					}
            else if(input.startsWith("COMPUTE")){
			 messageArea.append("\n\n@@@@@@ Encrypted values received from proxy server at "+getCurrentTimestamp()+"\n\n");
			 String in0[] = input.split(" ");
			String Dinput = TripleDESdecrypt(in0[1]);
			String in1[] = Dinput.split(" ");
			i = new Integer(in1[0]);
			String in2 = null;
			for(int j = 1 ; j < ((2*i)+1) ; j++ ){
			if(j == 1){
			in2 = in1[j];
			}else {
			in2 = in2 +" "+in1[j];
			}
			}
			try {
			hash = Hash(in1[0]+" "+in2);
			} catch
			(NoSuchAlgorithmException e)
			{
			e.printStackTrace();
			}
			if ((hash.compareTo(in1[((2*i)+1)])) == 0){
			messageArea.append("Hash is correct\n");
			for(int j = 1, l = 0 ; j < 2*i ; j = j+2 ,l++){
			StrA[l] = in1[j];
			StrB[l] = in1[j+1];
			messageArea.append("StrA"+l+" :	"+StrA[l]+"\n"+"StrB"+l+" :	"+StrB[l]+"\n");
			}
			out.println("CORRECT_HASH");
			ts = getCurrentTimestamp();
			messageArea.append("Input received time : "+ts+"\n");
			messageArea.append("Timestamp decrypted :"+in1[((2*i)+2)]+" "+in1[((2*i)+3)]+"\n\n");
			if ((checkTimestamp(in1[((2*i)+2)]+" "+in1[((2*i)+3)],ts)).intValue() < Time_Limit){
			messageArea.append("Timestamp is within the time limits\n\n");
			for(int j = 0; j < i ; j++){
			A[j] = new BigInteger(StrA[j]);
			B[j] = new BigInteger(StrB[j]);
			}
			
			
			//new part	 
			 
			try {	
				FileWriter writer = new FileWriter("/home/ammar/Desktop/PHIData/Encrypt_in/Encrypted_Ages.txt",false);
				for(int j = 0; j < i ; j++){
			    	writer.write(StrB[j]);
		            writer.write("\r\n");   // write new line		            
			    }
			    writer.close();            
		 
		        } catch (IOException e) {
		            e.printStackTrace();
		        }
			
			
			Process p00 =Runtime.getRuntime().exec(" /usr/local/hadoop-2.6.0/bin/hdfs dfs -mkdir /PHIData");
			try {
				p00.waitFor();
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
			
			Process p01 =Runtime.getRuntime().exec(" /usr/local/hadoop-2.6.0/bin/hdfs dfs -mkdir /PHIData/Encrypt_in");
			try {
				p01.waitFor();
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
			
			
			Process p02 =	Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hdfs dfs -put  /home/ammar/Desktop/PHIData/Encrypt_in/Encrypted_Ages.txt /PHIData/Encrypt_in");
			try {
				p02.waitFor();
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
			
			
			
			//String[] args={"/tmp/wordcount/Encrypt_in/ammar.txt","/tmp/wordcount/out"};
			//try {
			//	WordCount.sum_type=0;//determine in and out files paths for summation
			//	int res = ToolRunner.run(new Configuration(), new WordCount(), args);
		 	//} catch (Exception e1) {
		 	//e1.printStackTrace();
			 //}
			
			 Process p1 = 	Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hadoop jar /home/ammar/Desktop/Summation.jar grep /PHIData/Encrypt_in/Encrypted_Ages.txt output112 'dfs[a-z.]+'");	
			try {
				p1.waitFor();
			} catch (InterruptedException e1) {
				e1.printStackTrace();
			}
		 		
			 Process p2 = 	Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hdfs dfs -get /PHIData/Encrypt_out /home/ammar/Desktop/PHIData/Encrypt_out");
				try {
					p2.waitFor();
				} catch (InterruptedException e1) {
					e1.printStackTrace();
				} 
				
			   String line0,lastline="";
    		try {
	            FileReader reader = new FileReader("/home/ammar/Desktop/PHIData/Encrypt_out/part-r-00000");
	            BufferedReader bufferedReader = new BufferedReader(reader);	            
	            
	              line0="";lastline="";
	            
	            while ((line0 = bufferedReader.readLine()) != null) {
	            	lastline =	line0 ;
	            }
	            
            reader.close();  
            
			 Process p_DEl = 	Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hadoop fs -rm -r -f /PHIData/Encrypt_out");
				try {
					p_DEl.waitFor();
				} catch (InterruptedException e1) {
					e1.printStackTrace();
				} 
				File dir =new File ("/home/ammar/Desktop/PHIData/Encrypt_out");
				deleteDirectory(dir);
	 
	        } catch (IOException e) {
	            e.printStackTrace();
	        }
    		
			//String LAST_Li[] = lastline.split("\t");
			String sumB =lastline;// new String(LAST_Li[1]);
			
			Add=StrA[0].toString()+" "+sumB;		
			
			
			//Computing Addition
			//Add = Addition(A,B,i);
			
			messageArea.append("@@ Addition Calculated at "+getCurrentTimestamp()+"\n\n");
			String answer1 = i.toString()+" "+Add;
			try {
			hash = Hash(answer1.trim());
			} catch
			(NoSuchAlgorithmException e)
			{
			e.printStackTrace();
			}
 
 
			
			String output1 = answer1 +" "+hash+" "+getCurrentTimestamp().toString();
			messageArea.append("Unencrypted message : "+output1+"\n");
			Eoutput =TripleDESencrypt(output1,cipher);
			messageArea.append("Encrypted message :	"+Eoutput+"\n\n\n");
			for(PrintWriter writer : writers){
			writer.println("Summation"+" "+Eoutput);
			}
			messageArea.append("@@@@@@ Summation sent at "+getCurrentTimestamp()+"\n\n");
			}else {
			messageArea.append("Timestamp exceeds the time limit");
			}
			} else {
			messageArea.append("Hash is" + "incorrect\nWaiting for correct message....");
			out.println("INCORRECT_HASH");
			}
            }
			else if(input.startsWith("MEAN")){
			messageArea.append("\n\n@@@@ Encryped Mean received from TTP at "+getCurrentTimestamp()+"\n\n");
			String in0[] = input.split(" ");
			String Dinput = TripleDESdecrypt(in0[1]);
			String in1[] = Dinput.split(" ");
			try {
			hash = Hash(in1[0]+" "+in1[1]);		

			} catch
			(NoSuchAlgorithmException e)
			{
			e.printStackTrace();
			}
			if ((hash.compareTo(in1[2])) == 0){
			messageArea.append("Hash is correct\n");
			ts = getCurrentTimestamp();
			messageArea.append("Mean received time : "+ts+"\n");
			messageArea.append("Timestamp decrypted : "+in1[3]+" "+in1[4]+"\n\n");
			if ((checkTimestamp(in1[3]+" "+in1[4],ts)).intValue() < Time_Limit){
			messageArea.append("Timestamp is within the time limits\n\n");
			MeanA = new BigInteger(in1[0]);
			MeanB = new BigInteger(in1[1]);
			for(int j = 0 ; j < i ; j++)			
										{
				
			String Deviation =Subtraction(A[j],B[j],MeanA,MeanB);
			String Z[] = Deviation.split(" ");
					BigInteger DA = new	BigInteger(Z[1]);
					BigInteger DB = new	BigInteger(Z[2]);
					String SquareDeviation =Square(DA,DB);
					String O[] =SquareDeviation.split(" ");
		
					SDA[j] = new BigInteger(O[1]);
					SDB[j] = new BigInteger(O[2]);	
									
										}//forrrrrrrr
		
						
							//new part		 
							 
							try {	
								FileWriter writer = new FileWriter("/home/ammar/Desktop/PHIData/Encrypt_in_Variance/Encrypted_Derivation.txt",false);
								for(int j = 0; j < i ; j++){
							    	writer.write(SDB[j].toString());
						            writer.write("\r\n");   // write new line		            
							    }
							    writer.close();            
						 
						        } catch (IOException e) {
						            e.printStackTrace();
						        }
						
			/*				Process p30 = Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hdfs dfs -mkdir /PHIData");
							try {
								p30.waitFor();
							} catch (InterruptedException e1) {
								e1.printStackTrace();
							}*/
							
							
							Process p31 = 	Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hdfs dfs -mkdir /PHIData/Encrypt_in_Variance");
							try {
								p31.waitFor();
							} catch (InterruptedException e1) {
								e1.printStackTrace();
							}
							
							
							Process p3 = Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hdfs dfs -put  /home/ammar/Desktop/PHIData/Encrypt_in_Variance/Encrypted_Derivation.txt /PHIData/Encrypt_in_Variance");
							try {
								p3.waitFor();
							} catch (InterruptedException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
							
						//	String[] args={"/tmp/wordcount/Encrypt_in_Variance/ammar.txt","/tmp/wordcount/out_Variance"};
							//try {
							 
			//					int res = ToolRunner.run(new Configuration(), new WordCount_Variance(), args );
		 			//		} catch (Exception e1) {
								// TODO Auto-generated catch block
	 				//		e1.printStackTrace();
 					//		}
							
							 Process p4 = Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hadoop jar /home/ammar/Desktop/Summation_Derivation.jar grep /PHIData/Encrypt_in_Variance/Encrypted_Derivation.txt output113 'dfs[a-z.]+'");
							try {
								p4.waitFor();
							} catch (InterruptedException e1) {
								e1.printStackTrace();
							}
							
							 Process p5 = 	Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hdfs dfs -get /PHIData/Encrypt_out_Variance /home/ammar/Desktop/PHIData/out_Variance");
								try {
									p5.waitFor();
								} catch (InterruptedException e1) {
									e1.printStackTrace();
								}
								
								
								
							   String line2,lastline2="";
				    		try {
					            FileReader reader = new FileReader("/home/ammar/Desktop/PHIData/out_Variance/part-r-00000");
					            BufferedReader bufferedReader = new BufferedReader(reader);	            
					            
					              line2="";lastline2="";
					            
					            while ((line2 = bufferedReader.readLine()) != null) {
					            	lastline2 =	line2 ;
					            }
					            
				            reader.close();            
					            
							 Process p_DEl2 = 	Runtime.getRuntime().exec("/usr/local/hadoop-2.6.0/bin/hadoop fs -rm -r -f /PHIData/Encrypt_out_Variance");
								try {
									p_DEl2.waitFor();
								} catch (InterruptedException e1) {
									e1.printStackTrace();
								} 
					 
					        } catch (IOException e) {
					            e.printStackTrace();
					        }
				    		
							File dir =new File ("/home/ammar/Desktop/PHIData/out_Variance");
							deleteDirectory(dir);
							
							
						//	String LAST_Li[] = lastline2.split("\t");
							String sumSDB = lastline2;//new String(LAST_Li[1]);
							
							String Variance=SDA[0].toString()+" "+sumSDB;
							
							
							
							
						//	String Var = Addition(SDA,SDB,i);
							//String V[] = Var.split(" ");
							//VarianceA = new BigInteger(V[0]);
							//VarianceB = new BigInteger(V[1]);
							//String Variance = VarianceA+" "+VarianceB;
							messageArea.append("@@ Variance Calculated at "+getCurrentTimestamp()+"\n");
							
							
							
							
							
							
			 
							String answer2 = Variance.trim();
							try {
							hash = Hash(answer2.trim());
							} catch
							(NoSuchAlgorithmException e)
							{
							e.printStackTrace();
							}
				 
							String output = answer2.trim()+" "+hash.trim()+" "+getCurrentTimestamp().toString();
							messageArea.append("Unencrypted message :"+output+"\n");
							Eoutput = TripleDESencrypt(output,cipher);
							messageArea.append("Encrypted message : "+Eoutput+"\n\n\n\n");
									for(PrintWriter writer : writers){
										writer.println("STAT_Para"+" "+Eoutput);
										messageArea.append("@@@@@@@@ Answers sent at "+getCurrentTimestamp()+"\n\n\n");
										}
										}else {
										messageArea.append("Timestamp exceeds the time limit");
										}
										}else {
										messageArea.append("Hash is incorrect\nWaiting for correct message....");
										}
										}else if(input.startsWith("CORRECT_HASH")){
										messageArea.append("Hash response is correct \n\n");
										}else if(input.startsWith("INCORRECT_HASH")){
											messageArea.append("Hash Incorrect\nResending Message...\n\n");
												if(input.contains("MEAN")){
												out.println("Summation"+" "+Eoutput);
												}else {
												out.println("STAT_Para"+" "+Eoutput);
												}
												messageArea.append("@@ Sent time to TTP : "+getCurrentTimestamp()+"\n\n");
												}
												else if(input.startsWith("FINISH")){
												messageArea.append("Session terminated\n\n");
												for(PrintWriter writer: writers){
												writer.println("Cloud_FINISH");
												}
												}
										System.out.println("end\n"+input);
	}
	} catch (IOException e) {
	System.out.println(e);
	} catch (InvalidKeyException e) {
	e.printStackTrace();
	} catch (NoSuchAlgorithmException e) {
	e.printStackTrace();
	} catch (NoSuchPaddingException e) {
	e.printStackTrace();
	} catch (InvalidKeySpecException e) {
	e.printStackTrace();
	} finally {
	if (out != null) {
	writers.remove(out);
	}
	try {
	socket.close();
	} catch (IOException e) {
	}
	}
	}
	}
 
public static void RSA(){
SecureRandom r = new SecureRandom();
BigInteger p = new BigInteger(RSA_bit_length,100,r);
BigInteger q = new BigInteger(RSA_bit_length,100,r);
N_cloud = p.multiply(q);
BigInteger n =
(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
e_cloud = new BigInteger("3");
while(n.gcd(e_cloud).intValue()>1){
e_cloud = e_cloud.add(new BigInteger("2"));
}
d_cloud = e_cloud.modInverse(n);
}

public static BigInteger RSAdecrypt (BigInteger message){
return message.modPow(d_cloud, N_cloud);
}
public static BigInteger RSAsign (BigInteger message){
return message.modPow(d_cloud, N_cloud);
}
public static BigInteger RSAunsign (BigInteger message, BigInteger ex,
BigInteger Nx){
return message.modPow(ex, Nx);
}

//------------------------------------------------------------------

public static BigInteger RSAencrypt (BigInteger message,BigInteger ex,
BigInteger Nx){
return message.modPow(ex, Nx);
}

//------------------------------------------------------------------

public static BigInteger DoubleEncrypt (BigInteger message,BigInteger ex,
		BigInteger Nx){
	return RSAencrypt((RSAsign(message)),ex,Nx);
	}

//------------------------------------------------------------------
	public static BigInteger DoubleDecrypt (BigInteger message,BigInteger ex,
	BigInteger Nx){
	return RSAunsign((RSAdecrypt(message)),ex,Nx);
	}
	
	//------------------------------------------------------------------
	
	public static String Addition(BigInteger AA[], BigInteger AB[], Integer i){
	
	BigInteger BI1 = AA[0];
	BigInteger BI2 = new BigInteger("0");
	for(int j = 0 ; j < i ; j++){
	BI2 = BI2.add(AB[j]);
	}
	return (BI1.toString()+" "+BI2.toString());
	}
	
	//------------------------------------------------------------------
	
	public static String Subtraction(BigInteger DA1, BigInteger DB1,BigInteger
			DA2, BigInteger DB2){
			BigInteger BI1 = DA1;
			BigInteger BI2 = DB1.subtract(DB2);
			return "Subtraction"+" "+BI1.toString()+" "+BI2.toString();
	}
	public static String Square(BigInteger SA, BigInteger SB){
			BigInteger BI1 = SA.pow(2);
			BigInteger BI2 = SB.pow(2);
			return "Square"+" "+BI1.toString()+" "+BI2.toString();
	}
	public static String Cube(BigInteger CA, BigInteger CB){
			BigInteger BI1 = CA.modPow(new BigInteger("3"), p);
			BigInteger BI2 = CB.modPow(new BigInteger("3"), p);
			return "Cube"+" "+BI1.toString()+" "+BI2.toString();
	}
	public static String Biquadrate(BigInteger BQA, BigInteger BQB){
			BigInteger BI1 = BQA.modPow(new BigInteger("4"), p);
			BigInteger BI2 = BQB.modPow(new BigInteger("4"), p);
			return "Biquadrate"+" "+BI1.toString()+" "+BI2.toString();
	}
			
			//------------------------------------------------------------------
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
			
			//------------------------------------------------------------------
			public static Timestamp getCurrentTimestamp(){
				return new Timestamp(System.currentTimeMillis());
				}
			
			//------------------------------------------------------------------
			
			public static Timestamp setTimestamp(String ts){
			return Timestamp.valueOf(ts);
			}
			public static Long checkTimestamp(String ts0, Timestamp ts2){
			Timestamp ts1 = setTimestamp(ts0);
			Long difference = ts2.getTime()-ts1.getTime();
			messageArea.append("Timestamp Difference : "+difference+"\n\n");
			return difference;
			}
			
			//------------------------------------------------------------------
			public static String TripleDESencrypt(String unencryptedString, Cipher
			cipher) {
			String encryptedString = null;
			try {
			cipher.init(Cipher.ENCRYPT_MODE, key_TTP);
			byte[] plainText = unencryptedString.getBytes("UTF8");
			byte[] encryptedText = cipher.doFinal(plainText);
			encryptedString = new String(Base64.encodeBase64(encryptedText));
			} catch (Exception e) {
			e.printStackTrace();
			}
			return encryptedString;
			}
			
			//------------------------------------------------------------------
			public static String TripleDESdecrypt(String encryptedString) {
			String decryptedText=null;
			try {
			cipher.init(Cipher.DECRYPT_MODE, key_Proxy);
			byte[] encryptedText = Base64.decodeBase64(encryptedString);
			
			
			byte[] plainText = cipher.doFinal(encryptedText);
			decryptedText= new String(plainText);
			} catch (Exception e) {
			e.printStackTrace();
			}
			return decryptedText;
			}
			
			//------------------------------------------------------------------
			public static boolean deleteDirectory(File dir)
			{
			if (dir.isDirectory()){
			File[] child =dir.listFiles();
			for (int i=0 ; i< child.length; i++){
				boolean success = deleteDirectory(child[i]);
				if (!success){
					return false;
				}
			}
			}
			return dir.delete();
			}	
							}