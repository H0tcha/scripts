// Simplelocker antidote, written by Simon Bell, SecureHoney.net
 
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Collection;
 
public class SimplelockerAntidote {
 
    private final Cipher cipher;
    private final SecretKeySpec key;
    private AlgorithmParameterSpec spec;
 
    public SimplelockerAntidote(String password) throws Exception {
 
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(password.getBytes("UTF-8"));
        byte[] keyBytes = new byte[32];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
 
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        key = new SecretKeySpec(keyBytes, "AES");
        spec = getIV();
    }
 
    public AlgorithmParameterSpec getIV() {
        return new IvParameterSpec(new byte[16]);
    }
 
    public void encrypt(String paramString1, String paramString2) throws Exception {
        FileInputStream localFileInputStream = new FileInputStream(paramString1);
        FileOutputStream localFileOutputStream = new FileOutputStream(paramString2);
        this.cipher.init(1, this.key, this.spec);
        CipherOutputStream localCipherOutputStream = new CipherOutputStream(localFileOutputStream, this.cipher);
        byte[] arrayOfByte = new byte[8];
        while (true) {
            int i = localFileInputStream.read(arrayOfByte);
            if (i == -1) {
                localCipherOutputStream.flush();
                localCipherOutputStream.close();
                localFileInputStream.close();
                return;
            }
            localCipherOutputStream.write(arrayOfByte, 0, i);
        }
    }
 
    public void decrypt(String paramString1, String paramString2) throws Exception {
        FileInputStream localFileInputStream = new FileInputStream(paramString1);
        FileOutputStream localFileOutputStream = new FileOutputStream(paramString2);
        this.cipher.init(2, this.key, this.spec);
        CipherInputStream localCipherInputStream = new CipherInputStream(localFileInputStream, this.cipher);
        byte[] arrayOfByte = new byte[8];
        while (true) {
            int i = localCipherInputStream.read(arrayOfByte);
            if (i == -1) {
                localFileOutputStream.flush();
                localFileOutputStream.close();
                localCipherInputStream.close();
                return;
            }
            localFileOutputStream.write(arrayOfByte, 0, i);
        }
    } 
 
    public static String[] getEncryptedFiles() {
 
        File dir = new File(System.getProperty("user.dir"));
 
        Collection<String> files  =new ArrayList<String>();
 
        if(dir.isDirectory()){
            File[] listFiles = dir.listFiles();
 
            for(File file : listFiles){
                String filename = file.getName();
                if(
                    file.isFile() 
                    && (filename.lastIndexOf(".") >= 0)
                    && (filename.substring(filename.lastIndexOf(".")).toLowerCase().equals(".enc"))
                ) {
                    files.add(file.getName());
                }
            }
        }
         
        return files.toArray(new String[]{});
    }
 
    public static void main(String[] args) throws Exception{
 
        // set default cipher password
        String cipher_password = "jndlasf074hr";
 
        // overwrite cipher password if set by first argument
        if(args.length == 1)
        {
            cipher_password = args[0];
        }
 
        // create new SimplelockerAntidote object
        SimplelockerAntidote sa = new SimplelockerAntidote(cipher_password);
 
        // get array of filenames to decrypt from current directory
        String[] files = sa.getEncryptedFiles();
 
        // iterate through files in the array
        for (int i = 0; i < files.length; i++) {
 
            // set input and output filenames
            // and remove the .enc file extension
            String inputFilename = files[i];            
            String outputFilename = inputFilename.substring(0,inputFilename.length()-4);
 
            System.out.println("Decrypting "+outputFilename);
 
            // call decrypt on the current file
            sa.decrypt(inputFilename,outputFilename);
        }
 
        System.out.println("Decryption complete.");
 
    }
}
