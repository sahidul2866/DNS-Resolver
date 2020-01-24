import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

public class DnsResolver {

    static ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    static DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
    static ByteArrayInputStream byteArrayInputStream;
    static DataInputStream dataInputStream;
    static String ROOTSERVER = "192.5.5.241";
    static String NAMESERVER;
    static String HOSTNAME;
    public static void main(String[] args) {

         if (args.length == 0) {
            System.out.println("Incorrect number of arguements");
        }

        HOSTNAME = args[0];
        NAMESERVER = HOSTNAME;

        System.out.println("QUESTION SECTION:");
        System.out.println(String.format("%30s",HOSTNAME)+ "  "+String.format("%10s",0)+"    IN  "+String.format("%10s","A"));
        System.out.println("\nANSWER SECTION:");

        getIP getIp = new getIP(dataOutputStream,dataInputStream,byteArrayInputStream,byteArrayOutputStream,NAMESERVER,HOSTNAME,ROOTSERVER);

        if( getIp.getIP(HOSTNAME).equals("TIME OUT")) System.out.println("TIME OUT");
    }


    }