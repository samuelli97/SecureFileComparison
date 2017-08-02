/*
 * File: ServerCommunication.java
 * A class for the server to communicate to a single client using Sockets,
 * and computes encrypted dot product.
 * Part of 2017 REU in secure cloud computing at MST.
 * Written by Samuel Li
 */

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.util.regex.Pattern;

import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.DefaultListModel;



public class ServerCommunication implements Runnable {
    
    private static final int sigDigits = 4; // significant digits for conversions
    private static final int bitVectorEntries = 27; // SBIT protocol, not used
    
    private int port; // port for specific client
    private ArrayList<Dictionary> myLibrary; // contains all document dictionaries
    private DefaultListModel<String> listModel; // contains names of all collections
    private ServerSocket ss; // socket for communication
    private Socket client; // client socket
    private ObjectOutputStream outputStream; // for sending objects
    private ObjectInputStream inputStream; // for receiving objects
    private String clientChoice; // client's collection of choice
    private ArrayList<Double> products; // array of encrypted products
    
    private boolean connected; // connection status to client
    
    static {
        // include serverGMP library
        String directory = System.getProperty("user.dir");
        System.load(directory + "/serverGMP.dylib");
//        System.load("/Users/sam/NetBeansProjects/serverGMP/dist/serverGMP.dylib");
    }
    
    private native String GMPexponent(String ciphertext, int power, String nSquared);
    private native String GMPproduct(String ciphertext1, String ciphertext2, String nSquared);
    private native String SBITinitialize(String n);
    private native String[] SBITlooppartone(String T, String g, String n, String nSquared);
    private native String[] SBITloopparttwo(String T, String r, String alpha, String g, String n, String nSquared);
    
    public ServerCommunication(int port, ArrayList<Dictionary> myLibrary, 
            DefaultListModel<String> listModel) throws IOException {
        
        this.port = port;
        this.myLibrary = myLibrary;
        this.listModel = listModel; 
        
        // open server socket, connect to client socket
        this.ss = new ServerSocket(port); 
        this.client = ss.accept();

        // set up input and output streams
        this.outputStream = new ObjectOutputStream(client.getOutputStream());
        this.inputStream = new ObjectInputStream(client.getInputStream());

        this.connected = true;

        // sends collection choices to client
        this.outputStream.writeObject(this.listModel);
    }
    
    public void run() {
        
        while (this.connected) {
        
            try {
                // gets client's collection choice
                this.clientChoice = (String) inputStream.readObject();

                // determines which dictionary to send to client
                int index = this.listModel.indexOf(this.clientChoice);
                Dictionary selectedDictionary = this.myLibrary.get(index);
                ArrayList<String> myWords = selectedDictionary.getAllWords();

                // sends client unique words in selected collection
                this.outputStream.writeObject(myWords);

                // gets encrypted vector, g, n, n^2 from client
                String[] sVector = (String[])this.inputStream.readObject();
                String g = (String) this.inputStream.readObject();
                String n = (String) this.inputStream.readObject();
                String nSquared = (String) this.inputStream.readObject();
                
                // fills with encrypted dot products with each record in server
                ArrayList<String> encryptedProducts = 
                        homomorphic(sVector, selectedDictionary, nSquared);
                
                Integer numProducts = encryptedProducts.size();
                this.outputStream.writeObject(numProducts);
                
                
                // sbit protocol
                ArrayList<String[]> encryptedBitProducts = 
                        bitDecomposition(encryptedProducts, g, n, nSquared);

                // gives encrypted dot products to client
//                this.outputStream.writeObject(encryptedProducts);
                this.outputStream.writeObject(encryptedBitProducts);

            } catch (Exception e) {
                this.connected = false;

                try {
                    closeServer();

                } catch (Exception ex) {
                    Logger.getLogger(ServerCommunication.class.getName()).log(Level.SEVERE, null, ex);
                }
                return;
            }
        
        } // end while loop
    }
    
    private ArrayList<String[]> bitDecomposition(ArrayList<String> encryptedProducts, 
            String g, String n, String nSquared) throws Exception {
        
        ArrayList<String[]> decomposedProducts = new ArrayList<String[]>();
        
        // for each encrypted product...
        for (int i = 0; i < encryptedProducts.size(); i++) {
            
            String[] decomposed = new String[bitVectorEntries];
            
            String T = encryptedProducts.get(i);
            
            System.out.println("For product vector : " + i);
            // for each bit vector entry...
            for (int j = 0; j < bitVectorEntries; j++) {
                
                // calculate Y and r
                String[] YandR = SBITlooppartone(T, g, n, nSquared);
                
                // send Y to client
                this.outputStream.writeObject(YandR[0]);
                
                // receive alpha from client
                String alpha = (String) this.inputStream.readObject();
                
                // calculate E(xi), update Z, update T
                String[] EandT = SBITloopparttwo(T, YandR[1], alpha, g, n, nSquared);
                
                // store E(xi), update T
                decomposed[j] = EandT[0];
                T = EandT[1];
                
            }
            decomposedProducts.add(decomposed);
        }
        
        
        return decomposedProducts;
    }
    
    
    public ArrayList<Double> getProducts() {
        return this.products;
    }
    
    public boolean isConnected() {
        return this.connected;
    }
    
    private ArrayList<String> homomorphic(String[] sVector, Dictionary selectedDictionary,
            String nSquared) {
        
        ArrayList<String[]> intermediateProducts = new ArrayList<String[]>();
        ArrayList<String> encryptedProducts = new ArrayList<String>();
        
        // gets server vectors and normalizes them
        Vector[] serverVectors = selectedDictionary.getVectorArray();
        for (int i = 0; i < serverVectors.length; i++)
            serverVectors[i].normalize();
        
        // gets int vector
        ArrayList<int[]> convertedVectors = convert(serverVectors);
        
        // multiplicative homomorphic
        // for each server integer vector...
        for (int i = 0; i < convertedVectors.size(); i++) {
            int[] iVector = convertedVectors.get(i);
            
            String[] curProduct = new String[iVector.length];
            
            for (int j = 0; j < iVector.length; j++) {
                curProduct[j] = GMPexponent(sVector[j], iVector[j], nSquared);
                
            }
            intermediateProducts.add(curProduct);
        }
        
        
        // additive homomorphic
        
        // intermediate products has multiplicative homomorphic properties applied
        // for each server vector
        for (int i = 0; i < intermediateProducts.size(); i++) {
            
            String[] singleIntermediate = intermediateProducts.get(i);
            String cumulativeProduct = singleIntermediate[0];
            
            for (int j = 1; j < singleIntermediate.length; j++) {
                cumulativeProduct = GMPproduct(singleIntermediate[j], cumulativeProduct, nSquared);
            }
            encryptedProducts.add(cumulativeProduct); 
        }
        
        return encryptedProducts;
    }
    
    private ArrayList<int[]> convert(Vector[] serverVectors) {
        
        Conversions myConversions = new Conversions(sigDigits);
        ArrayList<int[]> convertedVectors = new ArrayList<int[]>();
        
        for (int i = 0; i < serverVectors.length; i++) {
            int[] iVector = myConversions.wholeNumberVector(serverVectors[i]);
            convertedVectors.add(iVector);
        }
        return convertedVectors;
    }
    
    public void closeServer() throws Exception{
        this.inputStream.close();
        this.outputStream.close();
        this.client.close();
        this.ss.close();
    }
}
