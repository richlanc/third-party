package com.osirium.windows;

import jcifs.smb.*;
import jcifs.UniAddress;
import java.util.regex.*;
import java.io.*;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class VerifyPassword
{
    public static void main(String[] args)
    {
        try
        {
            String host = args[0].trim();
            String username = args[1].trim();
            String domain = (args.length > 2 ? args[2] : "").trim();
            String password = "";
            try
            {
                password = new Scanner(System.in).useDelimiter("\\Z").next();
            }
            catch (NoSuchElementException e)
            {
                // empty password
            }

            SmbSession.logon(
                UniAddress.getByName(host),
                new NtlmPasswordAuthentication(domain.isEmpty() ? "?" : domain, username, password)
            );

            System.exit(0);
        }
        catch (SmbAuthException e)
        {
            System.err.println(e.getMessage());
            System.exit(1);
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            System.err.println("Usage <host> <username> [domain]");
            System.exit(2);
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
            System.exit(3);
        }
    }
}
