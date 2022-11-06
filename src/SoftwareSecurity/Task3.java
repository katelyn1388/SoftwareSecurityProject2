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


        System.out.println("Would you like to try and crack 1. the hashed file or 2. the salt file? (1/2)");
        selection = scannerObj.nextInt();
        scannerObj.nextLine();


        if(selection == 1)
        {
            int passwordsCrackedFile2 = task3.hackingFile2();
            System.out.println("A total of " + passwordsCrackedFile2 + " passwords were cracked from file2");
        }
        else if(selection == 2)
        {
            int passwordsCrackedFile2 = task3.hackingFile3();
            System.out.println("A total of " + passwordsCrackedFile2 + " passwords were cracked from file2");
        }






    }



    public int hackingFile2() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {
        Project2 project2 = new Project2();
        BufferedReader reader;
        reader = new BufferedReader(new FileReader("hashed"));
        String line = reader.readLine();
        
        System.out.println("Hashed password file cracking started...");
        long startTime = System.nanoTime();
        long endTime;

        int passwordsCracked = 0;


        for(int i = 0; i <= 999999999; i++)
        {
            System.out.println(i);
            //Converting current password attempt int to string
            String passwordInput = project2.getHashedPassword(Integer.toString(i));

            while(line != null)
            {
                String[] userInfo = Pattern.compile(" : ").split(line, 2);

                if(userInfo[1].equalsIgnoreCase(passwordInput)) {
                    passwordsCracked++;
                    if(passwordsCracked == 1)
                    {
                        endTime = System.nanoTime();
                        long duration = (endTime - startTime);
                        System.out.println("The first password was cracked after " + (duration / 1000000000) + " seconds");
                    }
                }else
                {
                    line = reader.readLine();
                }
            }
        }
        reader.close();

        System.out.println("Hashed password file cracking ended.");

        return passwordsCracked;
    }





    public int hackingFile3() throws Exception {
        Project2 project2 = new Project2();
        BufferedReader reader;
        reader = new BufferedReader(new FileReader("salt"));
        String line = reader.readLine();

        System.out.println("Salt password file cracking started...");
        long startTime = System.nanoTime();
        long endTime;

        int passwordsCracked = 0;

        for(int i = 0; i <= 999999999; i++)
        {
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
                        System.out.println("The first password was cracked after " + (duration / 1000000000) + " seconds");
                    }
                }else {
                    line = reader.readLine();
                }
            }
        }
        reader.close();

        System.out.println("Salt password file cracking ended.");

        return passwordsCracked;
    }




}
