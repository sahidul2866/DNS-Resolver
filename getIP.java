import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

public class getIP{
    DataOutputStream dataOutputStream;
    DataInputStream dataInputStream;
    ByteArrayInputStream byteArrayInputStream;
    ByteArrayOutputStream byteArrayOutputStream;
    String NAMESERVER;
    String HOSTNAME;
    String ROOTSERVER;

    public getIP() {
    }

    public getIP(DataOutputStream dataOutputStream, DataInputStream dataInputStream, ByteArrayInputStream byteArrayInputStream, ByteArrayOutputStream byteArrayOutputStream, String NAMESERVER, String HOSTNAME, String ROOTSERVER) {
        this.dataOutputStream = dataOutputStream;
        this.dataInputStream = dataInputStream;
        this.byteArrayInputStream = byteArrayInputStream;
        this.byteArrayOutputStream = byteArrayOutputStream;
        this.NAMESERVER = NAMESERVER;
        this.HOSTNAME = HOSTNAME;
        this.ROOTSERVER = ROOTSERVER;
    }

    String getIP(String domainName)
    {
        //split the domain name into domainNameParts[] array.
        String partOfTheDomainName[]=domainName.split("\\.");

        try{
             /// ID - An arbitrary 16 bit request identifier

            dataOutputStream.writeShort(0x1222);

            /// Query parameters
            /// flag set to 0000 to restrict of doing recursion
            dataOutputStream.writeShort(0x0000);
            /// Question count -  number of questions 1
            dataOutputStream.writeShort(0x0001);
            /// Answer count - number of answers is 0
            dataOutputStream.writeShort(0x0000);
            /// Number of authority records -
            dataOutputStream.writeShort(0x0000);
            /// Number of Additional Records
            dataOutputStream.writeShort(0x0000);

            /// Question - it has three sections . 1.QNAME 2.QTYPE 3.QCLASS

            /// Question Name - This contains the URL whose IP address we want to find . It is encoded as labels. Each label corresponds to a section of URL

            //get a byte array from domainNameParts[]
            int LENGTH = partOfTheDomainName.length;
            for(int i=0;i<LENGTH;i++)
            {
                byte b[]=partOfTheDomainName[i].getBytes();
                dataOutputStream.writeByte(b.length);
                dataOutputStream.write(b);
            }
             // The QNAME section is terminated by 00
            dataOutputStream.writeByte(0x00);

            /// QTYPE -Here we are looking up for the IP address of a hostname and for thisquestion, the  Question Type is 'A' whose value is 1
            dataOutputStream.writeShort(0x0001);

            /// OCLASS - Here we are using Interent class , IN and the value is 1
            dataOutputStream.writeShort(0x0001);


            byte DNSQUERYMESSAGE[] = byteArrayOutputStream.toByteArray();
            int MESSAGELENGTH = DNSQUERYMESSAGE.length;

            //CREATING A DATAGRAM SOCKET AND PACKET AT PORT NO 53 AND ROOT SERVER, SENDING AND SETTING THE TIME OUT
            DatagramSocket DATAGRAMSOCKET = new DatagramSocket();
            DatagramPacket DATAGRAMPACKET = new DatagramPacket(DNSQUERYMESSAGE,MESSAGELENGTH, InetAddress.getByName(ROOTSERVER),53);
            DATAGRAMSOCKET.send(DATAGRAMPACKET);
            DATAGRAMSOCKET.setSoTimeout(3000);

            byte RESPONSEBYTEARRAY[] = new byte[1024];
            //RECEIVING THE PACKETS OF THE DATAGRAM
            try {
                DatagramPacket receivedPacked = new DatagramPacket(RESPONSEBYTEARRAY, RESPONSEBYTEARRAY.length);
                DATAGRAMSOCKET.receive(receivedPacked);
            }
            catch (SocketTimeoutException e){
                return "TIME OUT";
            }

            byteArrayInputStream = new ByteArrayInputStream(RESPONSEBYTEARRAY);
            dataInputStream = new DataInputStream(byteArrayInputStream);

            dataInputStream.readShort();    //Transaction ID
            dataInputStream.readShort();    //Flags
            dataInputStream.readShort();    //Questions
            short resRRs = dataInputStream.readShort();    //answer RRs
            short authRRs = dataInputStream.readShort();    //Authority RRs
            short additionalRRs = dataInputStream.readShort();    //Additional RRs
            String queriedDomain = ResolveName(RESPONSEBYTEARRAY);
            dataInputStream.readShort();    //Query Type
            dataInputStream.readShort();    //Class : IN


            //loop through all answer RRs
            for(int i=1;i<=resRRs;i++)
            {
                String TYPE="", IP="", NAME = ResolveName(RESPONSEBYTEARRAY);

                int checkingType = dataInputStream.readShort();
                int timeToLive = dataInputStream.readInt();
                TYPE=getType(checkingType);
                dataInputStream.readShort();    //Class :IN
                dataInputStream.readShort();    //Data length

                if(TYPE.equals("A"))
                {
                    int a=dataInputStream.readByte(), b=dataInputStream.readByte(), c=dataInputStream.readByte(), d=dataInputStream.readByte();
                    a= a & 0x000000ff;
                    b= b & 0x000000ff;
                    c= c & 0x000000ff;
                    d= d & 0x000000ff;

                    IP = String.format("%d.%d.%d.%d",a,b,c,d); //ip address

                    if(NAME.equals(HOSTNAME))
                        responseMessageOutput(HOSTNAME,timeToLive,TYPE,IP); //if ip address belongs to hostName , then it will be printed
                }
                else if(TYPE.equals("AAAA"))
                {
                    int a=dataInputStream.readShort(), b=dataInputStream.readShort(), c=dataInputStream.readShort(), d=dataInputStream.readShort(), e=dataInputStream.readShort(), f=dataInputStream.readShort(), g=dataInputStream.readShort(), h=dataInputStream.readShort();

                    String ipv6Address=String.format("%x:%x:%x:%x:%x:%x:%x:%x",a,b,c,d,e,f,g,h);
                    if(NAME.equals(HOSTNAME))
                    {
                        responseMessageOutput(HOSTNAME,timeToLive,TYPE,ipv6Address);
                    }
                }
                else if(TYPE.equals("CNAME"))
                {
                    String cname=ResolveName(RESPONSEBYTEARRAY);
                    responseMessageOutput(HOSTNAME,timeToLive,TYPE,cname);
                    if(NAME.equals(HOSTNAME))
                    {
                        HOSTNAME=cname;
                        return getIP(HOSTNAME);    //CNAME will be printed
                    }
                }
                else if(TYPE.equals("SOA"))
                {
                    System.out.println("        "+domainName+"  :  Does Not Exist");    //SOA means the domain name dose not exist.
                    return "Does Not Exist";
                }
                if(i==resRRs)
                {
                    return IP;
                }

            }

            //loop through all authority RRs
            for(int i=0;i<authRRs;i++)
            {
                String type="";
                String name = ResolveName(RESPONSEBYTEARRAY);

                int t = dataInputStream.readShort();
                type=getType(t);
                dataInputStream.readShort();    //Class : IN
                dataInputStream.readInt();      //Time to live :
                dataInputStream.readShort();    //Data length :

                if(type.equals("CNAME"))
                {
                    String cname=ResolveName(RESPONSEBYTEARRAY);
                    return getIP(cname);
                }
                else if(type.equals("NS"))
                {
                    String str =ResolveName(RESPONSEBYTEARRAY);
                    NAMESERVER=str;
                    if(additionalRRs==0)
                    {
                        String nameServerIp=getIP(NAMESERVER);
                        ROOTSERVER = nameServerIp;
                        String ip= getIP(domainName);
                        if(!(ip.equals("time out")))
                        {
                            return ip;
                        }
                    }
                }
                else if(type.equals("SOA"))
                {
                    System.out.println("        "+domainName+"  :  Does Not Exist");
                    return "Does Not Exist";
                }
            }

            //loop through all additional RRs
            for(int i=0;i<additionalRRs;i++)
            {
                String type="";
                String name = ResolveName(RESPONSEBYTEARRAY);  //Name :

                int t = dataInputStream.readShort();
                type=getType(t);
                dataInputStream.readShort();    //Class : IN
                dataInputStream.readInt();      //Time to live :
                dataInputStream.readShort();    //Data length :

                if(type.equals("A"))
                {
                    int a=dataInputStream.readByte(), b=dataInputStream.readByte(), c=dataInputStream.readByte(), d=dataInputStream.readByte();
                    a= a & 0x000000ff;
                    b= b & 0x000000ff;
                    c= c & 0x000000ff;
                    d= d & 0x000000ff;

                    String outputIPAddress = String.format("%d.%d.%d.%d",a,b,c,d);
                    if(name.equals(domainName))
                        return outputIPAddress;
                    ROOTSERVER = outputIPAddress;
                    String ip = getIP(domainName);
                    if(!(ip.equals("time out")))
                        return ip;

                }
                else if(type.equals("AAAA"))
                {
                    int a=dataInputStream.readShort(), b=dataInputStream.readShort(), c=dataInputStream.readShort(), d=dataInputStream.readShort(), e=dataInputStream.readShort(), f=dataInputStream.readShort(), g=dataInputStream.readShort(), h=dataInputStream.readShort();
                    String ipv6Address=String.format("%x:%x:%x:%x:%x:%x:%x:%x",a,b,c,d,e,f,g,h);
                }

            }
        }
        catch (Exception e)
        {
            System.out.println("THERE IS AN ERROR ");
            e.printStackTrace();
        }
        return getIP(NAMESERVER);
    }

    //this printing part is collected
    static  void responseMessageOutput(String domainName, int timeToLive, String type,String address)
    {
        System.out.println(String.format("%30s",domainName)+ "  "+String.format("%10s",timeToLive)+"    IN  "+String.format("%10s",type)+"    "+address);
    }

    String ResolveName(byte response[])throws Exception
    {
        byte DomainNameByteArray[] = new byte[1024];
        int i=0;
        while (true)
        {
            byte k=dataInputStream.readByte();
            if(k==0)
            {
                break;
            }
            if(String.format("%x",k).equals("c0"))
            {
                int  index = dataInputStream.readByte();
                index= index & 0x000000ff;
                int j=response[index];
                index++;
                while (j>0)
                {
                    if(i>0)
                    {
                        DomainNameByteArray[i]='.';
                        i++;
                    }

                    for(int l=0;l<j;l++)
                    {
                        DomainNameByteArray[i]=response[index];
                        i++;
                        index++;
                    }
                    j=response[index];
                    index++;
                }

                break;
            }
            if(i>0)
            {
                DomainNameByteArray[i]='.';
                i++;
            }

            for(int j=0;j<k;j++)
            {
                byte b=dataInputStream.readByte();
                DomainNameByteArray[i]=b;
                i++;
            }

        }
        String DomainName = new String(DomainNameByteArray,0,i);
        return DomainName;
    }

    static String getType(int i)
    {
        switch (i){
            case 1: return "A";
            case 2: return "NS";
            case 5: return "CNAME";
            case 28: return "AAAA";
            case 6: return "SOA";
        }
        return "Unknown";
    }


}
