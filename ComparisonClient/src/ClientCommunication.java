/*
 * File: ClientCommunication.java
 * Employs Socket communication to compute document comparison scores with server.
 * Part of 2017 REU in secure cloud computing at MST.
 * Written by Samuel Li
 */


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.math.BigInteger;

import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.TermFreqVector;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.TermDocs;
import org.apache.lucene.index.TermEnum;
import org.apache.lucene.index.Term;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.io.FileReader;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;

public class ClientCommunication {
    
    private static final int positionG = 0; // position of G in pk[]
    private static final int positionN = 1; // position of N in pk[]
    private static final int positionNSQUARED = 2; // position of N^2 in pk[]
    
    private static final int sigDigits = 4; // desired significant digits, preset 
    private static final int bitVectorEntries = 27; // not employed, for SBIT
    private static final int numBits = 512; // size of private key, in bits
    
    private Conversions myConversions; // Conversions instance
    
    private String server; // name of server
    private int port; // port to connect to
    private String dataDir; // directory of client documents
    private String indexDir; // directory for Lucene indexing
    
    private Socket socket; // client socket
    private ObjectOutputStream outputStream; // to output objects
    private ObjectInputStream inputStream; // to input objects
    private DefaultListModel<String> listModel; // list of collections choices
    private ArrayList<Double> products; // computed products
    
    static {
        try {
            // connect to GMP libraries
            String directory = System.getProperty("user.dir");
            System.load(directory + "/myGMP.dylib");
//            System.load("/Users/sam/NetBeansProjects/myGMP/dist/myGMP.dylib");

        } catch (Exception ex) {
            Logger.getLogger(ClientCommunication.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    private native String[] initialize(int numBits);
    private native String encrypt(int message, String[] pk);
    private native int decrypt(String ciphertext, String[] pk);
    private native String SBITclient(String Y, String[] pk);
    
    // connects to server and receives list of colelction names
    public ClientCommunication(String server, int masterPort) throws Exception {
        
        Socket tempSocket = new Socket(server, masterPort);
        ObjectOutputStream tempOutput = new ObjectOutputStream(tempSocket.getOutputStream());
        ObjectInputStream tempInput = new ObjectInputStream(tempSocket.getInputStream());
        
        // receives actual port for comparisons
        Integer usagePort = (Integer) tempInput.readObject();
        
        // disconnects from masterPort
        tempSocket.close();
        tempOutput.close();
        tempInput.close();
        
        this.server = server;
        this.port = usagePort;
        
        // attempts to connect to server
        this.socket = new Socket(server, port);
        this.outputStream = new ObjectOutputStream(socket.getOutputStream());
        this.inputStream = new ObjectInputStream(socket.getInputStream());
        
        // receives options list from server
        this.listModel = (DefaultListModel<String>) inputStream.readObject();
        // initialize Conversions object
        myConversions = new Conversions(sigDigits);
        return;
    }
    
    // returns list display
    public DefaultListModel<String> getListModel() {
        return this.listModel;
    }
    
    // returns computed products
    public ArrayList<Double> getProducts() {
        return this.products;
    }
    
    // queries encrypted collection selection to server, creates encrypted
    // vector for query document in directory dataDir, with Lucene index in indexDir
    public void communicate(String selection, String indexDir, 
            String dataDir) throws Exception{
        
        this.indexDir = indexDir;
        this.dataDir = dataDir;
        
        // tells server which collection was selected
        this.outputStream.writeObject(selection);
        
        // receives unique words of selected collection
        ArrayList<String> uniqueWords = (ArrayList<String>) this.inputStream.readObject();
        
        // creates and normalizes vector from unique word dictionary
        Vector myVector = LuceneIndex(uniqueWords);
        myVector.normalize();
        
        // create private key
        String[] pk = initialize(numBits);
        
        // encrypts query Vector
        String[] sVector = encryptVector(myVector, pk);
        
        // sends encrypted string vector to server
        this.outputStream.writeObject(sVector);
        
        // sends g, n, n^2 to server
        this.outputStream.writeObject(pk[positionG]);
        this.outputStream.writeObject(pk[positionN]);
        this.outputStream.writeObject(pk[positionNSQUARED]);
        
        int numProducts = (Integer)this.inputStream.readObject();
        
        for (int i = 0; i < numProducts; i++) {
        
            System.out.println("Client calculates alphas for : " + i);
            for (int j = 0; j < bitVectorEntries; j++) {

                String Y = (String) this.inputStream.readObject();
                
                
                String alpha = SBITclient(Y, pk);
                
                this.outputStream.writeObject(alpha);
            }
        }
        
        ArrayList<String[]> encryptedBitProducts = (ArrayList<String[]>) this.inputStream.readObject();
        
        // receives ArrayList of encrypted dot products in String form
//        ArrayList<String> encryptedProducts = (ArrayList<String>) this.inputStream.readObject();
        
        // decrypts encrypted dot products, scales them to [0,1]
//        ArrayList<Double> decryptedProducts = new ArrayList<Double>();
//        for (int i = 0; i < encryptedProducts.size(); i++) {
//            String cipherProduct = encryptedProducts.get(i);
//            
//            int decryptedDot = decrypt(cipherProduct, pk);
//            
//            double scaledDot = myConversions.scaledDotProduct(decryptedDot);
//            decryptedProducts.add(scaledDot);
//           
//        }
//
//        this.products = decryptedProducts;
        
        this.products = bitProductConversion(encryptedBitProducts, pk);
        
        return;
    }
    
    // for SBIT protocol, not included
    private ArrayList<Double> bitProductConversion(ArrayList<String[]> encryptedBitProducts,
            String[] pk) {
        
        ArrayList<Double> decryptedProducts = new ArrayList<Double>();
        
        // for each vector of encrypted bits
        for (int i = 0; i < encryptedBitProducts.size(); i++) {
            
            String[] currentVector = encryptedBitProducts.get(i);
            long decryptedPartialProduct = 0;
            // for each entry in the vector
            System.out.println("Vector number " + i);
            for (int entry = 0; entry < currentVector.length; entry++) {
                int multiplier = decrypt(currentVector[entry], pk);
                
                System.out.print(multiplier + "    ");
                    
                
                decryptedPartialProduct += (multiplier * Math.pow(2, entry));
            }
            System.out.println();
            // scale down!!!
            double scaledProduct = this.myConversions.scaledDotProduct(decryptedPartialProduct);
            decryptedProducts.add(scaledProduct);
        }
        
        return decryptedProducts;
    }
    
    // indexes document with Lucene and the dictionary of uniqueWords
    private Vector LuceneIndex(ArrayList<String> uniqueWords) throws Exception{
        Indexer indexer = new Indexer(indexDir);
        int numIndexed;
        Vector queryVector = new Vector(uniqueWords.size());
        try {
            numIndexed = indexer.index(dataDir, new TextFilesFilter());
            IndexReader reader = indexer.getWriter().getReader();
            int numDocuments = reader.numDocs();
            
            
            // create vector;
            TermFreqVector freqVector = reader.getTermFreqVector(0, "contents");
            int[] termFreqs = freqVector.getTermFrequencies();
            int position = 0;
            int frequency = 0;
            
            for (String term : uniqueWords) {
                int index = freqVector.indexOf(term);
                if (index == -1)
                    queryVector.setValue(position, 0);
                else {
                    frequency = termFreqs[index];
                    queryVector.setValue(position, frequency);
                }
                position++;
                
            }
            reader.close();
            
        } finally {
            indexer.close();
        }
        return queryVector;
    }
        
    // encrypts each element of the vector myVector with key pk
    private String[] encryptVector(Vector myVector, String[] pk) {
        
        // gets whole number components of Vectors, according to myConversions
        int[] iVector = myConversions.wholeNumberVector(myVector);
              
        // creates encrypted vector of strings from iVector
        String[] sVector = new String[myVector.getDimension()];
        for (int i = 0; i < myVector.getDimension(); i++) {
            sVector[i] = encrypt(iVector[i], pk);
        }
        
        return sVector;
    }
    
    // closes client communication channels
    public void closeClient() throws Exception{
        inputStream.close();
        outputStream.close();
        socket.close();
    }
    
    // ensures only .txt files are accepted
    private static class TextFilesFilter implements FileFilter {
    	public boolean accept(File path) {
      	return path.getName().toLowerCase()        
             .endsWith(".txt");                  
        }
    }
}
