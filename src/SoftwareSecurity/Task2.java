package SoftwareSecurity;

import java.util.Random;
import java.util.Scanner;

public class Task2 {
    static Scanner scannerObj = new Scanner(System.in);

    public static void main(String[] args) throws Exception {
        Project2 project2 = new Project2();

        int leftLimit = 97, rightLimit = 122, leftIntLimit = 48, rightIntLimit = 57, userNameMax = 10, userNameMin = 3;
        boolean good = false;
        Random random = new Random();

        int min, max, accountsNum;

        System.out.println("What password length range would you like? First give me the minimum password length, then the maximum");
        System.out.println("Maximum cannot be bigger than 9");
        System.out.println("Minimum: ");
        min = Integer.parseInt(scannerObj.nextLine());

        do{
            System.out.println("Maximum: ");
            max = Integer.parseInt(scannerObj.nextLine());

            if(max > 9)
                System.out.println("Maximum cannot exceed 9");
            else
                good = true;
        }while(!good);


        System.out.println("Now select a number of accounts you would like to create: ");
        accountsNum = Integer.parseInt(scannerObj.nextLine());


        for(int i = 0; i < accountsNum; i++)
        {
            int userNameLength = random.nextInt(userNameMax - userNameMin + 1) + userNameMin;
            //Creating random usernames
            String userNameString = random.ints(leftLimit, rightLimit + 1)
                    .limit(userNameLength)
                    .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                    .toString();

            int passwordLength = random.nextInt(max - min + 1) + min;

            //Creating random passwords
            String passwordString = random.ints(leftIntLimit, rightIntLimit + 1)
                    .limit(passwordLength)
                    .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                    .toString();

            //Sending random username and password to task1
            project2.newAccountCreation(userNameString, passwordString);
        }

        System.out.println("Accounts created!");

    }



}
