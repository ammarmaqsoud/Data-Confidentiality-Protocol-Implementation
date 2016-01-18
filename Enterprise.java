import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.HashSet;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import ProxyServer.Handler1;

import java.sql.Timestamp;



public class Enterprise {
static final int bit_length = 64;
String A,B,input;
BigInteger p,q,K,y,g;
Random r_ran = new SecureRandom();
BigInteger r = new BigInteger(bit_length,r_ran);
BufferedReader in;
PrintWriter out;
JFrame frame = new JFrame(" Enterprise Program");
JTextArea messageArea = new JTextArea(50, 60);
public Enterprise () {
messageArea.setEditable(false);
frame.getContentPane().add(new JScrollPane(messageArea), "Center");
frame.pack();
}
 
private String getServerAddress() {
return JOptionPane.showInputDialog(frame,"Enter IP Address of the  Server :"," ",
JOptionPane.QUESTION_MESSAGE);
}
private String getName() {
return JOptionPane.showInputDialog(frame,"Enter the username :"," ",
JOptionPane.PLAIN_MESSAGE);
}
private String getInput() {
return JOptionPane.showInputDialog(frame,"Enter the number to be calculated : "," ",
JOptionPane.PLAIN_MESSAGE);
}
private String getPassword(){
int checkPwd = 0;
JPasswordField pwd = new JPasswordField(10);
int action = JOptionPane.showConfirmDialog(frame, pwd,"Enter the Password : ",JOptionPane.OK_CANCEL_OPTION);

do {
if((action < 0) || (pwd.getPassword().length == 0)){
JOptionPane.showMessageDialog(null,"You must enter a password to proceed");
}else {
		
	checkPwd++;
	break;
	}
	}while(checkPwd == 0);
	return new String(pwd.getPassword());
	}




private void run() throws IOException {
messageArea.append("\n\n\t**********************************"
+"******************\n" +
"\t=====================================\n" +"\t********** Enterprise ***** P R O G R A M ***********\n" +
"\t=====================================" +"\n\t***************************************"+"*************\n\n\n");
String serverAddress = getServerAddress();
Socket socket = new Socket(serverAddress, 9001);

in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
out = new PrintWriter(socket.getOutputStream(), true);

while (true) {
	String line = in.readLine();
	if (line.startsWith("USERNAME")) {
	out.println(getName());
	} else if(line.startsWith("PASSWORD")){
	out.println(getPassword());
	
	} else if (line.startsWith("NAMEACCEPTED")) {
		String P[] = line.split(" ");
	 	p = new BigInteger(P[1]);
	 	messageArea.append("p = " +p +"\n\n");
		q = new BigInteger(P[2]);
		messageArea.append("q = " +q +"\n\n");
		K = new BigInteger(P[3]);
		messageArea.append("K = " +K +"\n\n");
		g = new BigInteger(P[4]);
		messageArea.append("g = " +g +"\n\n");
		y = new BigInteger(P[5]);
		messageArea.append("y = " +y +"\n\n");

		 
		 try {
	            FileReader reader = new FileReader("/home/ammar/Desktop/PHIData/in/Clear_Ages.txt");
	            BufferedReader bufferedReader = new BufferedReader(reader);
	 
	            
	            
	            int numberOfLines = 3;
	            String[ ] textData = new String[numberOfLines];
	            
	            
	            
	            int i;

	            for (i=0; i < numberOfLines; i++) {
	            textData[ i ] = bufferedReader.readLine();

	             
	            
	            

	    		Double Doubleinput = new Double(textData[ i ]);
	    		Doubleinput = Doubleinput * 100;
	    		Long Longinput = Doubleinput.longValue();
	    		
	    		String inputHundred = Longinput.toString();
	    		messageArea.append("@@ Encryption initiating at " +getCurrentTimestamp()+"\n\n");
	    		Encryption(inputHundred, messageArea);
	    		messageArea.append("@@ Value encrypted at "+getCurrentTimestamp()+"\n\n");
	    		
	    		String output = A+" "+B;
	    		out.println("Value"+" "+output);
	    		messageArea.append("Sent message : "+"Value"+" "+output+"\n\n");
	    		messageArea.append("@@ Sent time :"+getCurrentTimestamp()+"\n\n\n\n");
	    		
	    		
	    		
	            reader.close();
	            }
	 
	        } catch (IOException e) {
	            e.printStackTrace();
	        }
		 
		 
		
		}
	
	else if(line.startsWith("_FINISH")){
			
			messageArea.append("\t@@@@@@@@@@@@@@@@@@@@@  New Session @@@@@@@@@@@@@@@@@@@@\n\n\n");
					input = getInput();
					messageArea.append("\nValue Input : "+input+"\n\n\n");
					Double Doubleinput = new Double(input);
					Doubleinput = Doubleinput * 100;
					Long Longinput = Doubleinput.longValue();
					String inputHundred = Longinput.toString();
					Encryption(inputHundred, messageArea);
					String output = A+" "+B;
					out.println("Value"+" "+output);
					
					messageArea.append("Sent message : "+"Value"+" "+output+"\n");
					messageArea.append("@@ Sent time :"+getCurrentTimestamp()+"\n\n\n\n");
					}
					}
					}


public static void main(String[] args) throws Exception {
	Enterprice Enterp = new Enterprice();
	Enterp.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	Enterp.frame.setVisible(true);
	Enterp.run();
	}


public void Encryption(String SalesValue, JTextArea messageArea){
BigInteger N;
messageArea.append("p = "+p+"\n");
messageArea.append("q = "+q+"\n");
// N = p * q
N = p.multiply(q);
messageArea.append("N = "+N+"\n");
messageArea.append("y = "+y+"\n");
messageArea.append("r = "+r+"\n");
String m = SalesValue;
BigInteger M = new BigInteger(m);
 
BigInteger bx = M.add(r.multiply(p)).mod(N);
 
BigInteger b = bx.multiply(y.modPow(K, p)).mod(p);
//  
BigInteger a = g.modPow(K, p);

messageArea.append("Encrypted part A = "+a+"\n");
messageArea.append("Encrypted part B = "+b+"\n\n\n");
A = a.toString();
B = b.toString();
}
public Timestamp getCurrentTimestamp(){
return new Timestamp(System.currentTimeMillis());
}
}

