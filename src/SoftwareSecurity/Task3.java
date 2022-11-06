package SoftwareSecurity;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.regex.Pattern;

public class Task3 {
    static Scanner scannerObj = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
        Project2 project2 = new Project2();
        Task3 task3 = new Task3();

        int selection;
        boolean good;


        int maxPasswordLength;
        do {
            System.out.println("What is the max size you would to use for password searching (max password length is 9 digits)");
            maxPasswordLength = scannerObj.nextInt();

            if (maxPasswordLength > 9) {
                System.out.println("Max password length must be 9 or less, please select a new number");
                good = false;
            } else if (maxPasswordLength <= 0) {
                System.out.println("Password max must be at least 1");
                good = false;
            } else
                good = true;

        } while (!good);


        StringBuilder passwordSizeString = new StringBuilder("9");
        passwordSizeString.append("9".repeat(maxPasswordLength - 1));

        int maxPasswordSize = Integer.parseInt(String.valueOf(passwordSizeString));

        System.out.println("Would you like to try and crack 1. the hashed file or 2. the salt file? (1/2)");
        selection = scannerObj.nextInt();
        scannerObj.nextLine();

        if (selection == 1) {
            int passwordsCrackedFile2 = task3.hackingFile2(maxPasswordSize);
            System.out.println("A total of " + passwordsCrackedFile2 + " passwords were cracked from file2");
        } else if (selection == 2) {
            int passwordsCrackedFile2 = task3.hackingFile3(maxPasswordSize);
            System.out.println("A total of " + passwordsCrackedFile2 + " passwords were cracked from file2");
        }

        System.out.println("Hacking complete!");

    }



    public int hackingFile2(int maxPasswordSize) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {
        Project2 project2 = new Project2();
        
        System.out.println("Hashed password file cracking started...");
        long startTime = System.nanoTime();
        long endTime;

        int passwordsCracked = 0;


        for(int i = 0; i <= maxPasswordSize; i++)
        {
            BufferedReader reader;
            reader = new BufferedReader(new FileReader("hashed"));
            String line = reader.readLine();
            //Converting current password attempt int to string
            String passwordInput = project2.getHashedPassword(Integer.toString(i));        //Something wrong here

            while(line != null)
            {
                String[] userInfo = Pattern.compile(" : ").split(line, 2);
                if(userInfo[1].equalsIgnoreCase(passwordInput)) {
                    passwordsCracked++;
                    if(passwordsCracked == 1)
                    {
                        endTime = System.nanoTime();
                        long duration = (endTime - startTime);
                        System.out.println("The first password was cracked after " + (duration / 1000000) + " milliseconds");
                    }
                    line = reader.readLine();
                }else
                {
                    line = reader.readLine();
                }
            }
            reader.close();
        }

        endTime = System.nanoTime();
        long totalDuration = endTime - startTime;

        System.out.println("Hash password file cracking ended.");
        System.out.println("Total time for file 2: " + totalDuration);

        return passwordsCracked;
    }





    public int hackingFile3(int maxPasswordSize) throws Exception {
        Project2 project2 = new Project2();

        System.out.println("Salt password file cracking started...");
        long startTime = System.nanoTime();
        long endTime;

        int passwordsCracked = 0;

        for(int i = 0; i <= maxPasswordSize; i++)
        {
            System.out.println("I: " + i);
            BufferedReader reader;
            reader = new BufferedReader(new FileReader("salt"));
            String line = reader.readLine();
            while (line != null) {
                String[] userInfo = Pattern.compile(" : ").split(line, 3);
                //Takes the salt
                String salt = userInfo[1];
                //Takes the hashed, salted password
                String filePassword = userInfo[2];
                //Calculating the given password with the salt from the file
                String calculatedHash = project2.getEncryptedPassword(Integer.toString(i), salt);

                if (filePassword.equals(calculatedHash)) {
                    passwordsCracked++;
                    if(passwordsCracked == 1)
                    {
                        endTime = System.nanoTime();
                        long duration = (endTime - startTime);
                        System.out.println("The first password was cracked after " + (duration / 1000000) + " milliseconds");
                    }
                    System.out.println("Number of passwords hacked: " + passwordsCracked);
                    line = reader.readLine();
                }else {
                    line = reader.readLine();
                }
            }
            reader.close();
        }

        endTime = System.nanoTime();
        long totalDuration = endTime - startTime;

        System.out.println("Salt password file cracking ended.");
        System.out.println("Total time for file 3: " + totalDuration);

        return passwordsCracked;
    }




}
