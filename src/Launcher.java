
public class Launcher {

    public static void main(String[] args) {

        if(args.length < 1)
        {
            System.out.println("Usage: java -jar FileEncrypter.jar encrypt/decrypt");
        }
        else
        {
            if(args[0].equals("encrypt"))
            {
                new FileEncrypter().start();
            }
            else if(args[0].equals("decrypt"))
            {
                new FileDecrypter().start();
            }
            else
            {
                System.out.println("Invalid operation.");
            }
        }
    }
}
