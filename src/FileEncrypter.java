import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.HashMap;
import java.util.Scanner;

/**
 * Created by udbhav on 29/11/16.
 */
public class FileEncrypter {

    // Function for file selection
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
            System.exit(4);
        }

        return file;

    }



    public static void main(String[] args) {
        try {

            Scanner scanner = new Scanner(System.in);
            System.out.println("Select file: ");


            File file = getSelectedFile();
            //byte[] fileData = Files.readAllBytes(file.toPath());
            String fileName = file.getName();
            String path = file.getParent();


            System.out.println("Generate key pair?(y/n) ");
            char ans = scanner.next().toLowerCase().charAt(0);

            PrivateKey pvKey = null;
            PublicKey pbKey = null;
            if(ans == 'y')
            {
                //Generate new key pair.
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(1024);
                KeyPair keyPair = generator.generateKeyPair();
                pvKey = keyPair.getPrivate();
                pbKey = keyPair.getPublic();



                ObjectOutputStream pbOut = new ObjectOutputStream(new FileOutputStream(path+ "/" + "PUBLIC.key"));

                pbOut.writeObject(pbKey);
                pbOut.close();



                ObjectOutputStream pvOut = new ObjectOutputStream(new FileOutputStream(path+ "/" + "PRIVATE.key"));
                pvOut.writeObject(pvKey);
                pvOut.close();

                System.out.println("Keys generated!\nDo not share your private key with anyone!");

            }
            else
            {
                try {
                    //Read public key.
                    System.out.println("Select public key: ");
                    File keyFile = getSelectedFile();

                    ObjectInputStream oin = new ObjectInputStream(new FileInputStream(keyFile));


                    pbKey = (PublicKey) oin.readObject();
                    oin.close();
                } catch(ClassCastException ccx)
                {
                    //In case an invalid public key is selected.
                    System.out.println("Invalid public key! Aborting!");
                    System.exit(1);
                }
            }



            SecureRandom random = new SecureRandom();

            byte[] keyb = new byte[16];
            byte[] ivb = new byte[16];

            random.nextBytes(keyb);
            random.nextBytes(ivb);


            //Creating new AES key.
            SecretKeySpec keySpec = new SecretKeySpec(keyb,"AES");


            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,keySpec,new IvParameterSpec(ivb));

            Cipher keyCipher = Cipher.getInstance("RSA");
            keyCipher.init(Cipher.ENCRYPT_MODE,pbKey);



            //The file name and content are encrypted with the new AES cipher.
            SealedObject sealedName = new SealedObject(fileName,cipher);
            //SealedObject sealedContent = new SealedObject(fileData,cipher);




            //The key and IV are encrypted with the public key.
            SealedObject sealedKey = new SealedObject(keyb,keyCipher);
            SealedObject sealedIV = new SealedObject(ivb,keyCipher);


            //The encrypted data is stored in a hashmap with specific key bindings.
            HashMap<Integer, SealedObject> dataStore = new HashMap<Integer, SealedObject>();
            dataStore.put(0,sealedKey);
            dataStore.put(1,sealedIV);
            dataStore.put(2,sealedName);

            //The encrypted structure is saved.
            ObjectOutputStream enWriter = new ObjectOutputStream(new FileOutputStream(path + "/" + fileName + ".sealed"));
            enWriter.writeObject(dataStore);
            enWriter.close();

            CipherOutputStream contentWriter = new CipherOutputStream(new FileOutputStream(path+ "/" + fileName + ".sealed",true),cipher);
            byte[] buffer = new byte[1024];
            int read;
            InputStream fileReader = new FileInputStream(file);
            while((read = fileReader.read(buffer))!=-1) {

                contentWriter.write(buffer,0,read);
            }
            fileReader.close();
            contentWriter.close();


            System.out.println("Encryption successful!\nExiting.");
            System.exit(0);


        }

        catch(IOException iox){System.out.println("IO Error! Exiting!");System.exit(2); /*General IO errors.*/}
        catch(Exception x){System.out.println("Error! Exiting!"); x.printStackTrace();System.exit(3);/*Other errors*/  }
    }
}
