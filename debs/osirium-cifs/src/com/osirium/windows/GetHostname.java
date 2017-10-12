package com.osirium.windows;

import java.net.UnknownHostException;
import jcifs.netbios.NbtAddress;

public class GetHostname
{
    public static void main(String[] args)
    {
        if (args.length != 1) {
            System.err.println("Usage: <host>");
            System.exit(2);
        }
        try
        {
            String host = args[0].trim();

            NbtAddress[] addresses = (NbtAddress.getAllByAddress(host));
            for (int i = 0; i < addresses.length; i++) {
                NbtAddress address = addresses[i];
                if (address.getNameType() == 0 && !address.isGroupAddress()) {
                    System.out.println(address.getHostName());
                    System.exit(0);
                }
            }
            throw new UnknownHostException("No netbios name found");
        }
        catch (UnknownHostException e)
        {
            System.err.println(e.toString());
            System.exit(1);
        }
        catch (Exception e)
        {
            System.err.println(e);
            System.exit(3);
        }
    }
}
