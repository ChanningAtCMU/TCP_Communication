/**
 * Author: Changzhou Zheng (changzhz)
 * Date: Oct. 6th, 2022
 * 95702-A Distributed Systems for Information Systems Management
 *
 *  This Java file is simulating a TCP server who receives
 *  user input order number from a TCP client and
 *  add, subtract, or get the result for each ID
 *  with encryption method RSA to verify the client's identification.
 */

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.TreeMap;

//Reference: https://github.com/CMU-Heinz-95702/Project-2-Client-Server
public class VerifyingServerTCP {

    public static void main(String args[]) {
        //Tell that the server starts running
        System.out.println("Server started\n");

        //Run the defined method
        VerifyingServerTCP.process();
    }

    private static TreeMap<String, Integer> dict = new TreeMap<>();
    private static int val;
    private static String result, data = null, id, signature, operand, value;
    private static Boolean verID, verSig;
    private static BigInteger e, n;

    /**
     * This method handles all the input methods and verifies
     * the user's signature and ID
     * by calling verifySig and verifyID methods.
     */
    private static void process(){
        Socket clientSocket = null;
        try {
            int serverPort = 7777; // the server port we are using

            // Create a new server socket
            ServerSocket listenSocket = new ServerSocket(serverPort);

            /*
             * Forever,
             *   read a line from the socket
             *   print it to the console
             *   echo it (i.e. write it) back to the client
             */
            while (true) {
                /*
                 * Block waiting for a new connection request from a client.
                 * When the request is received, "accept" it, and the rest
                 * the tcp protocol handshake will then take place, making
                 * the socket ready for reading and writing.
                 */
                clientSocket = listenSocket.accept();
                // If we get here, then we are now connected to a client.

                // Set up "in" to read from the client socket
                Scanner inPort;
                inPort = new Scanner(clientSocket.getInputStream());

                // Set up "out" to write to the client socket
                PrintWriter outPort;
                outPort = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));

                /*
                 * The following loop constantly receives messages sending from the client
                 */
                while(true){
                    //If there is a next user input
                    if(inPort.hasNext()){
                        //Read the next message from the client
                        data = inPort.nextLine();

                        //If the order is 1
                        if(data.equals("1")){
                            //Catch all variables from the client
                            signature = inPort.nextLine();
                            id = inPort.nextLine();
                            e = new BigInteger(inPort.nextLine());
                            n = new BigInteger(inPort.nextLine());
                            operand = inPort.nextLine();
                            value = inPort.nextLine();

                            //Print the public key and verify the results
                            System.out.println("Public key = (e-->" + e +" and n-->" + n+")");
                            String message = id+","+e+","+n+","+operand+","+value;
                            VerifyingServerTCP.verifySig(message,signature);
                            VerifyingServerTCP.verifyID();

                            //If both signature and ID are verified, start calculation
                            if(verSig && verID){
                                System.out.println("Verification Approved");
                                //Print the adding value and the ID
                                System.out.println("Adding: "+ value);
                                System.out.println("To ID: "+ id);

                                //Find the pre-calculation value. Return 0 if not found
                                int curVal = dict.getOrDefault(id, 0);
                                //Get the result from TreeMap and add to the input
                                curVal += Integer.parseInt(value);
                                dict.put(id, curVal);
                                //Put the result back to the map
                                result = String.valueOf(dict.get(id));
                                System.out.println("The returned result: "+ result + "\n");

                                //Send the result to the client
                                outPort.println(result);
                                outPort.flush();
                            }else{
                                System.out.println("Verification Fail");;
                            }
                        }
                        //Else if the order is 2
                        else if(data.equals("2")){
                            //Catch all variables from the client
                            signature = inPort.nextLine();
                            id = inPort.nextLine();
                            e = new BigInteger(inPort.nextLine());
                            n = new BigInteger(inPort.nextLine());
                            operand = inPort.nextLine();
                            value = inPort.nextLine();

                            //Print the public key and verify the results
                            System.out.println("Public key = (e-->" + e +" and n-->" + n+")");
                            String message = id+","+e+","+n+","+operand+","+value;
                            VerifyingServerTCP.verifySig(message,signature);
                            VerifyingServerTCP.verifyID();
                            if(verSig && verID){
                                System.out.println("Verification Approved");
                                //Print the adding value and the ID
                                System.out.println("Subtracting: "+ value);
                                System.out.println("To ID: "+ id);

                                //Find the pre-calculation value. Return 0 if not found
                                int curVal = dict.getOrDefault(id, 0);
                                //Get the result from TreeMap and add to the input
                                curVal -= Integer.parseInt(value);
                                dict.put(id, curVal);
                                //Put the result back to the map
                                result = String.valueOf(dict.get(id));
                                System.out.println("The returned result: "+ result + "\n");

                                //Send the result to the client
                                outPort.println(result);
                                outPort.flush();
                            }else{
                                System.out.println("Verification Fail");;
                            }
                        }
                        //Else if the order is 3
                        else if(data.equals("3")){
                            //Catch all variables from the client
                            signature = inPort.nextLine();
                            id = inPort.nextLine();
                            e = new BigInteger(inPort.nextLine());
                            n = new BigInteger(inPort.nextLine());
                            operand = inPort.nextLine();

                            //Print the public key and verify the results
                            System.out.println("Public key = (e-->" + e +" and n-->" + n+")");
                            String message = id+","+e+","+n+","+operand;
                            VerifyingServerTCP.verifySig(message,signature);
                            VerifyingServerTCP.verifyID();

                            //If verifications are approved, get the result and return to the client
                            if(verSig && verID){
                                System.out.println("Verification Approved");
                                //Print the ID
                                System.out.println("Getting ID: "+ id);

                                //Put the result back to the map
                                result = String.valueOf(dict.getOrDefault(id, 0));
                                System.out.println("The returned result: "+ result + "\n");

                                //Send the result to the client
                                outPort.println(result);
                                outPort.flush();
                            }else{
                                System.out.println("Verification Fail");;
                            }
                        }
                    }
                    //If no next line of input could be found, means client has quit
                    else {
                        System.out.println("Client quit\n");
                        data = " ";
                        break;
                    }
                }

            }

            // Handle exceptions
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());

            // If quitting (typically by you sending quit signal) clean up sockets
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                // ignore exception on close
            }
        }
    }

    /**
     * This method verifies the user's signature
     *
     * @param messageToCheck
     * @param encryptedHashStr
     * @throws NoSuchAlgorithmException
     */
    private static void verifySig(String messageToCheck, String encryptedHashStr) throws NoSuchAlgorithmException {
        verSig = false;
        // Take the encrypted string and make it a big integer
        BigInteger encryptedHash = new BigInteger(encryptedHashStr);
        // Decrypt it
        BigInteger decryptedHash = encryptedHash.modPow(e, n);

        //Digest the message and encrypted by the SHA-256 pattern
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(messageToCheck.getBytes());
        byte[] md = messageDigest.digest();

        //Prevent the message initiating with any negative value
        byte[] msgByte = new byte[md.length + 1];
        msgByte[0] = 0;
        for (int i = 1; i < md.length + 1; i++) {
            msgByte[i] = md[i - 1];
        }
        BigInteger rMD = new BigInteger(msgByte);

        //Check if the client's signature is identical to what the server calculated
        if(rMD.equals(decryptedHash)) {
            verSig = true;
        } else {
            verSig = false;
        }
    }

    /**
     * This method verifies user's ID
     *
     * @throws NoSuchAlgorithmException
     */
    private static void verifyID() throws NoSuchAlgorithmException {
        verID = false;
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        //Digest the message and encrypted by the SHA-256 pattern
        messageDigest.update((e.toString() + n.toString()).getBytes());
        byte[] idInput = messageDigest.digest();

        //Get the last 20 bytes from the input message as ID
        byte[] idCompare = new byte[20];
        for (int i = 0; i < 20; i++) {
            idCompare[i] = idInput[idInput.length - 21 + i];
        }
        BigInteger idResult = new BigInteger(idCompare);

        //Check if the client's ID is identical to what the server calculated
        if(idResult.toString().equals(id)) {
            verID = true;
        } else {
            verID = false;
        }
    }
}