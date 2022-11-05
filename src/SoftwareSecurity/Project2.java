//Katelyn Bowers
//Software Security - Project 2
package SoftwareSecurity;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;


public class Project2 {
    Scanner scannerObj = new Scanner(System.in);

    //Creating a cipher
//    Cipher cipher;
//    {
//        try {
//            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//        }
//    }
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");


//    //Creating a key
//    KeyGenerator keyGenerator;
//    {
//        try {
//            keyGenerator = KeyGenerator.getInstance("AES");
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//    }

    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

    public Project2() throws NoSuchAlgorithmException, NoSuchPaddingException {
    }


    public static void main(String[] args) throws Exception {
        Project2 projectObject = new Project2();
        int choice = projectObject.actionQuestion();

        if(choice == 1)
        {
            projectObject.newAccountQuestions();
        }
        if(choice == 2)
        {
            projectObject.authenticate();
        }
    }



    //Asking user what they want to do
    public int actionQuestion() throws NumberFormatException {
        boolean validInput;
        String choiceInput;
        int choiceTest = 0;
        int choiceReal = 0;


        do{
            System.out.println("Would you like to 1. create a new account or 2. authenticate?");
            System.out.println("Please enter 1 or 2: ");

            choiceInput = scannerObj.nextLine();
            try{
                choiceTest = Integer.parseInt(choiceInput.trim());
                break;
            }catch (NumberFormatException ex){
                System.out.println("Invalid input, " + choiceInput + " is not a valid number");
            }

            if(choiceInput.equals("1") || choiceInput.equals("2"))
                validInput = true;
            else
            {
                validInput = false;
                System.out.println("Invalid input, please enter 1 or 2");
            }
        }while(!validInput);

        if(choiceInput.equals("1"))
            choiceReal = 1;
        else
            choiceReal = 2;

        return choiceReal;
    }



    //Getting desired username and password from user and checking for validity
    public void newAccountQuestions() throws Exception {
        String username, password = null;

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
    public void newAccountCreation(String username, String password) throws Exception {

        //File type 1
        String plaintextFileInfo = String.join(" : ", username, password);
        saveInformation("plaintext", plaintextFileInfo);


        //File type 2
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 256;
        keyGenerator.init(keyBitSize, secureRandom);

        SecretKey hashedKey = keyGenerator.generateKey();
        cipher.init(Cipher.ENCRYPT_MODE, hashedKey);

        //Changing password into byte array and encrypting it
        byte[] passwordBytes = password.getBytes("UTF-8");
        byte[] hashedPassword = cipher.doFinal(passwordBytes);

        //Changing encrypted byte array password into string
        String hashedPasswordString = new String(hashedPassword, StandardCharsets.ISO_8859_1);

        //Combining the username and password into one string and sending it to file
        String hashedFileInfo = String.join(" : ", username, hashedPasswordString);
        saveInformation("hashed", hashedFileInfo);



        //File type 3
        String saltFileInfo = newSaltUser(username, password);
        saveInformation("salt", saltFileInfo);

    }





    //Authenticating username and password of user
    public void authenticate() throws Exception {
        String username, password;

        username = getUsername();
        password = getPassword();

        //byte[] passwordByte = password.getBytes();

        //NEED TO HASH THE SECOND AND THIRD BEFORE CHECKING

        boolean firstFile = checkInformation("plaintext", username, password);
        boolean secondFile = checkInformation("hashed", username, password);           //All WERE passwordByte getting passed
        boolean thirdFile = checkInformation("salt", username, password);

        if(firstFile)
        {
            System.out.println("Successfully logged into file 1");
        } else
        {
            System.out.println("Logging into file 1 failed");
        }


        if(secondFile)
        {
            System.out.println("Successfully logged into file 2");
        } else
        {
            System.out.println("Logging into file 2 failed");
        }


        if(thirdFile)
        {
            System.out.println("Successfully logged into file 3");
        } else
        {
            System.out.println("Logging into file 3 failed");
        }

    }



    public String getUsername(){
        String username;
        boolean goodUsername;
        do{
            System.out.println("Please enter your username: ");
            username = scannerObj.nextLine().trim();

            if(username.length() > 10 || username.isBlank())         //Testing username length
            {
                System.out.println(username);
                System.out.println("Invalid username: Username must be 10 characters or less and cannot be blank");
                goodUsername = false;
            }
            else if(!username.matches("[a-zA-Z]+"))           //Testing username for alphabetic characters only
            {
                System.out.println("Invalid username: Username can only contain alphabetic characters");
                goodUsername = false;
            }
            else
                goodUsername = true;
        }while(!goodUsername);

        return username;
    }



    public String getPassword(){
        String password;
        boolean goodPassword;
        do{
            System.out.println("Please enter your password: ");
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



    //Modified newUser
    private String newSaltUser(String userName, String password) throws Exception {
        String newUserString;

        String salt = getSalt2();
        String encryptedPassword = getEncryptedPassword(password, salt);

        newUserString = String.join(" : ", userName, salt, encryptedPassword);

        return newUserString;
    }


    //Second type of getSalt from quickprogrammingtips.com
    public String getSalt2() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[1];
        secureRandom.nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }

    //Taken from quickprogrammingtips.com
    //Gets the password/salt mix
    public String getEncryptedPassword(String password, String salt) throws Exception{
        String algorithm = "PBKDF2WithHmacSHA1";
        int derivedKeyLength = 160;
        int iterations = 10000;

        byte[] saltBytes = Base64.getDecoder().decode(salt);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, iterations, derivedKeyLength);
        SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);

        byte[] encBytes = f.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(encBytes);
    }


    //New saveInformation Method
    public void saveInformation(String fileName, String userInfoString){
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





    public boolean checkInformation(String fileName, String usernameInput, String passwordInput) throws Exception {
        Scanner scanner = new Scanner(fileName);

        boolean exists = false;
        int lineNum = 0;
        while(scanner.hasNextLine()) {
            String line = scanner.nextLine();
            lineNum++;
            if(line.equalsIgnoreCase(String.join(" : ", usernameInput, passwordInput)))
            {
                exists = true;
            }
            else
                exists = false;
        }


        //Authenticating for salt file
        if(fileName.equals("salt"))
        {
            while(scanner.hasNextLine()) {

                String line = scanner.nextLine();
                lineNum++;
                if(line.contains(usernameInput))
                {
                    //Splits the line into the username, salt, and hashed, salted password
                    String[] userInfo = Pattern.compile(" : ").split(line, 3);
                    //Takes the salt
                    String salt = userInfo[2];
                    //Calculating the given password with the salt from the file
                    String calculatedHash = getEncryptedPassword(passwordInput, salt);
                    if(Objects.equals(salt, calculatedHash))
                    {

                    }
                }
            }
        }

        if(exists)
            return true;
        else
            return false;
    }


}

