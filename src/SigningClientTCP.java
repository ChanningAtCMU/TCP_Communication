/**
 * Author: Changzhou Zheng (changzhz)
 * Date: Oct. 6th, 2022
 * 95702-A Distributed Systems for Information Systems Management
 *
 * This Java file is simulating a TCP client who sends
 * user input order number to a TCP server for processing
 * "add", "subtract", or "get" with encryption method RSA.
 */

import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

//Reference: https://github.com/CMU-Heinz-95702/Project-2-Client-Server
public class SigningClientTCP {

    public static void main(String args[]) {
        System.out.println("The client is running.");

        //Run the defined method and catch exceptions
        try {
            SigningClientTCP.deliver();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //m is going to store user orders
    private static String m, id;

    private static BigInteger e, n, d;

    /**
     * This method keeps tack of user inputs and
     * send the inputs to the server for further processing
     * @throws IOException
     */
    private static void deliver () throws IOException {
        //Arguments supply hostname
        Socket clientSocket = null;

        try {
            //BufferReader return the current user input after each println
            BufferedReader typed = new BufferedReader(new InputStreamReader(System.in));

            //Ask input from the user
            System.out.println("Please enter server port:");
            int serverPort = Integer.parseInt(typed.readLine());
            //Build the client socket with the user-assigned server port number
            clientSocket = new Socket("localhost", serverPort);

            //Enable the client to catch input streams
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            //Enable the client to send output streams
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));

            //Create elements of RSA
            SigningClientTCP.createRSA();

            do {
                //Ask user for options
                System.out.println("1. Add a value to your sum.\n" +
                        "2. Subtract a value from your sum.\n" +
                        "3. Get your sum.\n" +
                        "4. Exit client");
                //Retrieve the option
                m = typed.readLine();
                //Tell the server what option the user has made so that it can modify the following algorithms
                out.println(m);

                //If the user is going to change one of the values
                if(m.equals("1") | m.equals("2")){
                    String sig = "", value = "";
                    //Tell the server whether is to add or to subtract
                    if(m.equals("1")){
                        //If the order number is 1, ask a value to add
                        System.out.println("Enter value to add:");
                        value = typed.readLine();
                        sig = id+","+e+","+n+",add,"+value;
                    } else if(m.equals("2")){
                        //If the order number is 1, ask a value to subtract
                        System.out.println("Enter value to subtract:");
                        value = typed.readLine();
                        sig = id+","+e+","+n+",subtract,"+value;
                    }
                    //Create signature by combining the elements got above
                    String signature = SigningClientTCP.sign(getHash(sig));
                    out.println(signature);
                    System.out.println("client side signature: "+signature);

                    //Push out all elements to the server
                    out.println(id);
                    out.println(e);
                    out.println(n);
                    //If the order number is 1, push out "1"; push "2" if 2
                    if(m.equals("1")){
                        out.println("add");
                    } else if(m.equals("2")){
                        out.println("subtract");
                    }
                    out.println(value);
                    out.flush();

                    //Get input stream from the server --> the changed value
                    String data = in.readLine(); // read a line of data from the stream
                    System.out.println("The returned result: " + data + "\n");
                }
                //Else if the user only want to peek the value
                else if (m.equals("3")) {
                    String sig = id+","+e+","+n+",get";
                    String signature = SigningClientTCP.sign(getHash(sig));

                    //Push out all elements to the server
                    out.println(signature);
                    out.println(id);
                    out.println(e);
                    out.println(n);
                    out.println("get");
                    out.flush();

                    //Get input stream from the server --> the value
                    String data = in.readLine(); // read a line of data from the stream
                    System.out.println("The returned result: " + data + "\n");
                } else {
                    //If the user choose 4, then quit the client
                    out.println("4");
                    out.flush();
                    System.out.println("Client side quitting. The remote variable server is still running.");
                    break;
                }
            } while (m != null); //Keep iterating if there is another order input

            //Catch all exceptions
        }catch (SocketException e) {System.out.println("Socket: " + e.getMessage());
        }catch (IOException e){System.out.println("IO: " + e.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        } finally {if(clientSocket != null) clientSocket.close();}
    }

    /**
     * This method creates necessary elements for RSA verification
     * @throws NoSuchAlgorithmException
     */
    //Reference: https://github.com/CMU-Heinz-95702/Project-2-Client-Server
    private static void createRSA() throws NoSuchAlgorithmException {
        Random rnd = new Random();

        // Step 1: Generate two large random primes.
        // We use 400 bits here, but best practice for security is 2048 bits.
        // Change 400 to 2048, recompile, and run the program again, and you will
        // notice it takes much longer to do the math with that many bits.
        BigInteger p = new BigInteger(400, 100, rnd);
        BigInteger q = new BigInteger(400, 100, rnd);

        // Step 2: Compute n by the equation n = p * q.
        n = p.multiply(q);

        // Step 3: Compute phi(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Step 4: Select a small odd integer e that is relatively prime to phi(n).
        // By convention the prime 65537 is used as the public exponent.
        e = new BigInteger("65537");

        // Step 5: Compute d as the multiplicative inverse of e modulo phi(n).
        d = e.modInverse(phi);

        System.out.println("Public key = (e-->" + e +" and n-->" + n+")");  //(e,n) is the RSA public key
        System.out.println("Private key = (d-->" + d +" and n-->" + n+")");  //(d,n) is the RSA private key

        //Generate the public key
        String pubKey = e.toString().concat(n.toString());

        //Using SHA-256 pattern
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        //Get the last 20 bytes from the information as the User ID
        md.update(pubKey.getBytes());
        byte[] bigDigest = md.digest();
        //Get the total length of the message
        int bdLen = bigDigest.length;
        //Create a byte array to store the 20 bytes of ID
        byte[] idArr = new byte[20];
        for (int i = 0; i < 20; i++){
            idArr[i] = bigDigest[bdLen-21+i];
        }
        BigInteger hashedID = new BigInteger(idArr);
        //Parse BigInteger ID to String type
        id = hashedID.toString();
    }

    /**
     * This method signs output messages and returns the signature as a String
     * @param message
     * @return
     * @throws Exception
     */
    private static String sign(String message) throws Exception {
        // From the digest, create a BigInteger
        BigInteger m = new BigInteger(message);

        // encrypt the digest with the private key
        BigInteger c = m.modPow(d, n);

        // return this as a big integer string
        return c.toString();
    }

    /**
     * This method gets input variables hashed and returns the hash as String
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static String getHash(String str) throws NoSuchAlgorithmException {
        MessageDigest md;
        //Digest input by SHA-256 pattern
        md = MessageDigest.getInstance("SHA-256");
        md.update(str.getBytes());
        byte[] db = md.digest();

        ////Prevent the message initiating with any negative value
        byte[] rDB = new byte[db.length + 1];
        rDB[0] = 0;
        for(int i = 1; i<db.length + 1; i++){
            rDB[i] = db[i-1];
        }

        //Convert rDB to a BigInteger and then a String
        return new BigInteger(rDB).toString();
    }
}
