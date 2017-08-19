import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;


public class FileDecrypter {

    //Method for selecting files.
    public static File getSelectedFile()
    {
        File file = null;
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int selection = fileChooser.showOpenDialog(null);
        if (selection == JFileChooser.APPROVE_OPTION) {
            file = fileChooser.getSelectedFile();
        }
        else if(selection == JFileChooser.CANCEL_OPTION)
        {
            System.out.println("Exiting.");
            System.exit(1);
        }

        return file;

    }

    public void start() {
        try{

            System.out.println("Select File: ");
            File file = getSelectedFile();
            System.out.println("Select private key: ");
            File pvKeyFile = getSelectedFile();

            PrivateKey pvKey = null;
            try {
                byte[] keyBytes = Files.readAllBytes(pvKeyFile.toPath());
                ByteArrayInputStream bin = new ByteArrayInputStream(keyBytes);
                KeyFactory kf =  KeyFactory.getInstance("RSA");
                pvKey =kf.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            }catch(ClassCastException ccx){System.out.println("\nInvalid private key! Aborting!");System.exit(2);/*In case an invalid file is selected.*/}

            HashMap<Integer, SealedObject> sealedStuff = null;

            try {
                FileInputStream fileReader = new FileInputStream(file);
                ObjectInputStream headerReader = new ObjectInputStream(fileReader);
                sealedStuff = (HashMap<Integer, SealedObject>) headerReader.readObject();
                long content_start = fileReader.getChannel().position();



                //Initialise decryption cipher with private key.
            Cipher deCipher = Cipher.getInstance("RSA");
            deCipher.init(Cipher.DECRYPT_MODE,pvKey);

                //Get AES key bytes.
            SealedObject sealedKey = sealedStuff.get(0);
            byte[] keyBytes = (byte[])sealedKey.getObject(deCipher);
                //Get AES IV bytes.
            SealedObject sealedIV = sealedStuff.get(1);
            byte[] IVBytes = (byte[])sealedIV.getObject(deCipher);

                //Generate key and AES decryption cipher.
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes,"AES");


            Cipher contentCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            contentCipher.init(Cipher.DECRYPT_MODE,keySpec,new IvParameterSpec(IVBytes));

                //Get decrypted name and content.
            SealedObject sealedName = sealedStuff.get(2);
            String fileName = (String)sealedName.getObject(contentCipher);

                CipherInputStream contentReader = new CipherInputStream(fileReader,contentCipher);
                OutputStream fileOut = new FileOutputStream(fileName);
                int read;
                byte[] buffer = new byte[1024];
                while((read = contentReader.read(buffer)) !=-1)
                {
                    fileOut.write(buffer,0,read);
                }
                contentReader.close();
                headerReader.close();

                fileOut.close();

            }catch(ClassCastException ccx){System.out.println("Invalid sealed file! Aborting!");System.exit(3);/*In case an invalid sealed file is selected.*/}

        }catch(IOException iox){System.out.println("IO Error! Exiting!"); iox.printStackTrace();System.exit(4);/*General IO errors.*/}
        catch(GeneralSecurityException gsx){System.out.println("Decryption Error! Aborting!"); System.exit(5);/*In case of wrong key.*/}
        catch(Exception x){System.out.println("Error! Exiting!"); x.printStackTrace();System.exit(6);/*Other errors.*/}
    }
}
