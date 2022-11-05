//Katelyn Bowers
//Software Security - Project 2
package SoftwareSecurity;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Project2 {
    static Scanner scannerObj = new Scanner(System.in);

    private static Map<String, UserInfo> userDatabase = new HashMap<String,UserInfo>();


    //Creating a cipher
    static Cipher cipher;
    {
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }


    //Creating a key
    static KeyGenerator keyGenerator;
    {
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }



    public static void main(String[] args) throws Exception {
        int choice = actionQuestion();

        if(choice == 1)
        {
            newAccountQuestions();
        }
        if(choice == 2)
        {
            authenticate();
        }
    }



    //Asking user what they want to do
    public static int actionQuestion(){
        boolean validInput = false;
        int choice = 0;

        do{
            System.out.println("Would you like to 1. create a new account or 2. authenticate?");
            System.out.println("Enter 1 or 2: ");

            choice = scannerObj.nextInt();
            scannerObj.nextLine();
            if(choice == 1 || choice == 2)
                validInput = true;
            else
            {
                validInput = false;
                System.out.println("Invalid input, please enter 1 or 2");
            }
        }while(!validInput);

        return choice;
    }





    //Getting desired username and password from user and checking for validity
    public static void newAccountQuestions() throws Exception {
        boolean happy = false;
        String username, password = null, happyReply;

        System.out.println("Your username must be 10 alphabetic characters or less");
        System.out.println("Your password must only contain numbers (0-9)");

        //Getting and checking username
        username = getUsername();

        //Getting and checking password
        password = getPassword();

        //Sending username and password to file generator method
        newAccountCreation(username, password);

    }




    //Save new account information to files
    public static void newAccountCreation(String username, String password) throws Exception {

        //Saving account info to the first file type
        byte[] passwordPlain = password.getBytes();
        saveInformation("plaintext", username, passwordPlain, null);


        //Commented out for testing  -  file2

//        SecureRandom secureRandom = new SecureRandom();
//        int keyBitSize = 256;
//        keyGenerator.init(keyBitSize, secureRandom);

//        //Generating the password key for the second file type
//        SecretKey hashedKey = keyGenerator.generateKey();
//        try {
//            cipher.init(Cipher.ENCRYPT_MODE, hashedKey);
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        }




        //Way of doing file3 before quickprogrammingtips.com
//        //Generating the password key for the third file type
//        SecretKey saltKey = keyGenerator.generateKey();
//        try {
//            cipher.init(Cipher.ENCRYPT_MODE, saltKey);
//        } catch (InvalidKeyException e) {
//            e.printStackTrace();
//        }


//        //Saving the information to the hashed password file
//        byte[] passwordByte = new byte[0];
//        try {
//            passwordByte = password.getBytes("UTF-8");
//        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
//        }
//        byte[] hashedPassword = new byte[0];
//        try {
//            hashedPassword = cipher.doFinal(passwordByte);
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        }
//
//        saveInformation("hashed", username, hashedPassword, null);



//        //Saving the information to the salt file
//
//        //Getting a salt value of one byte
//        byte[] byteSalt = null;
//        try {
//            byteSalt = getSalt();
//        } catch (NoSuchAlgorithmException ex) {
//            System.out.println("Exception thrown while trying to create salt in newAccountCreation");
//        }
//
//        //Hashing the salt/password mix
//        byte[] saltedPassword = getSaltedPassword(password, byteSalt);
//        byte[] hashedSaltedPassword = new byte[0];
//        try {
//            hashedSaltedPassword = cipher.doFinal(saltedPassword);
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        }
//
//        saveInformation("salt", username, hashedSaltedPassword, byteSalt);



        //New way
        String saltFileInfo = newSaltUser(username, password);
        saveInformation("salt", saltFileInfo);

    }





    //Authenticating username and password of user
    public static void authenticate() throws Exception {
        String username, password;

        username = getUsername();

        password = getPassword();

        byte[] passwordByte = password.getBytes();

        //NEED TO HASH THE SECOND AND THIRD BEFORE CHECKING

        boolean firstFile = checkInformation("plaintext", username, passwordByte);
        boolean secondFile = checkInformation("hashed", username, passwordByte);
        boolean thirdFile = checkInformation("salt", username, passwordByte);

        if(firstFile == true)
        {
            System.out.println("Successfully logged into file 1");
        }
        else
        {
            System.out.println("Logging into file 1 failed");
        }


        if(secondFile == true)
        {
            System.out.println("Successfully logged into file 2");
        }
        else
        {
            System.out.println("Logging into file 2 failed");
        }


        if(thirdFile == true)
        {
            System.out.println("Successfully logged into file 3");
        }
        else
        {
            System.out.println("Logging into file 3 failed");
        }




    }



    public static String getUsername(){
        String username;
        boolean goodUsername = false;
        do{
            System.out.println("Please enter your desired username: ");
            username = scannerObj.nextLine().trim();

            if(username.length() > 10 || username.isBlank())         //Testing username length
            {
                System.out.println(username);
                System.out.println("Invalid username: Username must be 10 characters or less and cannot be blank");
                goodUsername = false;
                continue;
            }
            else if(!username.matches("[a-zA-Z]+"))           //Testing username for alphabetic characters only
            {
                System.out.println("Invalid username: Username can only contain alphabetic characters");
                goodUsername = false;
                continue;
            }
            else
                goodUsername = true;
        }while(!goodUsername);

        return username;
    }



    public static String getPassword(){
        String password;
        boolean goodPassword = false;
        do{
            System.out.println("Please enter your desired password: ");
            password = scannerObj.nextLine().trim();
            if(!password.matches("\\d+"))
            {
                System.out.println("Invalid password: Password must be an integer, only containing numbers (0-9)");
                goodPassword = false;
                continue;
            }
            else if(password.isBlank())
            {
                System.out.println("Invalid password: Password cannot be left blank");
                goodPassword = false;
                continue;
            }
            else
                goodPassword = true;
        }while(!goodPassword);

        return password;
    }




    //Creating salt value
    public static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[1];
        secureRandom.nextBytes(salt);
        return salt;
    }



    //New user from quickprogrammingtips.com
    private void newUser(String userName, String password) throws Exception {
        String salt = getSalt2();
        String encryptedPassword = getEncryptedPassword(password, salt);
        UserInfo user = new UserInfo();
    }

    //Modified newUser
    private static String newSaltUser(String userName, String password) throws Exception {
        String newUserString;

        String salt = getSalt2();
        String encryptedPassword = getEncryptedPassword(password, salt);

        newUserString = String.join(" : ", userName, salt, encryptedPassword);

        return newUserString;
    }


    //Second type of getSalt from quickprogrammingtips.com
    public static String getSalt2() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[1];
        secureRandom.nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }

    //Taken from quickprogrammingtips.com
    //Gets the password/salt mix
    public static String getEncryptedPassword(String password, String salt) throws Exception{
        String algorithm = "PBKDF2WithHmacSHA1";
        int derivedKeyLength = 160;
        int iterations = 10000;

        byte[] saltBytes = Base64.getDecoder().decode(salt);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, iterations, derivedKeyLength);
        SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);

        byte[] encBytes = f.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(encBytes);
    }


    //Salting the password
    public static byte[] getSaltedPassword(String password, byte[] salt) {
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte byteData[] = md.digest(password.getBytes());
            md.reset();
            return byteData;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger("SHA-512").log(Level.SEVERE, "SHA-512 is not a valid algorithm name", ex);
            return null;
        }
    }


    //Saving information to correct file
    public static void saveInformation(String fileName, String username, byte[] password, byte[] salt){
        FileWriter fw = null;
        BufferedWriter bw = null;
        PrintWriter pw = null;

        if(fileName == "plaintext")        //for file 1
        {
            try {
                fw = new FileWriter(fileName, true);
                bw = new BufferedWriter(fw);
                pw = new PrintWriter(bw);

                pw.println(username + " : " + password);

                System.out.println("Account successfully created and saved to file1!");
                pw.flush();

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    pw.close();
                    bw.close();
                    fw.close();
                } catch (IOException io) {}
            }
        }
        else if(fileName == "hashed")     //For file 2
        {
            try {
                fw = new FileWriter(fileName, true);
                bw = new BufferedWriter(fw);
                pw = new PrintWriter(bw);

                HashMap<String, byte[]> passwords = new HashMap<String, byte[]>();
                passwords.put(username, password);

                //pw.println(username + " : " + password);
                pw.println(Arrays.toString(passwords.put(username, password)));    //Saving it as a hashmap entry

                System.out.println("Account successfully created and saved to file2!");
                pw.flush();

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    pw.close();
                    bw.close();
                    fw.close();
                } catch (IOException io) {}
            }
        }
        else         //For file 3
        {
            try {
                fw = new FileWriter(fileName, true);
                bw = new BufferedWriter(fw);
                pw = new PrintWriter(bw);

                HashMap<String, byte[]> passwords = new HashMap<String, byte[]>();
                passwords.put(username, password);

                //pw.println(username + " : " + password);
                pw.println(Arrays.toString(passwords.put(username, password)) + " : " + salt);    //Saving it as a hashmap entry

                System.out.println("Account successfully created and saved to file3!");
                pw.flush();

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    pw.close();
                    bw.close();
                    fw.close();
                } catch (IOException io) {}
            }
        }
    }

    //New saveInformation Method
    public static void saveInformation(String fileName, String userInfoString){
        FileWriter fw = null;
        BufferedWriter bw = null;
        PrintWriter pw = null;


        try {
            fw = new FileWriter(fileName, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);

            pw.println(userInfoString);

            System.out.println("Account successfully created and saved to file!");
            pw.flush();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                pw.close();
                bw.close();
                fw.close();
            } catch (IOException io) {}
        }

    }





    public static boolean checkInformation(String fileName, String username, byte[] password) throws Exception {
//        try {
            Scanner scanner = new Scanner(fileName);

            boolean exists = false;
            int lineNum = 0;
            while(scanner.hasNextLine()) {
                String line = scanner.nextLine();
                lineNum++;
                if(line == username + " : " + password)
                {
                    exists = true;
                }
            }

        //IN THE MIDDLE OF CHANGING TO authenticateUser FROM WEBSITE
        if(fileName == "salt")
        {
            UserInfo user = userDatabase.get(username);
            if(user == null)
                return false;
            else
            {
                String salt = user.userSalt;
                String calculatedHash = getEncryptedPassword(String.valueOf(password), salt);
                while(scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    lineNum++;
                    if(line.contains(username))
                    {

                    }
                }
            }
        }

            if(exists == false)
            {
                return true;
            }
            else
                return false;

//        } catch(FileNotFoundException e) {
//            System.out.println("File not found");
//        }
    }



}



class UserInfo {
    String userEncryptedPassword;
    String userSalt;
    String userName;
}
