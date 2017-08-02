/*
 * File: MasterCommunication.java
 * Manages threads and ServerCommunication objects to handle multiple clients at once
 * with multithreading.
 * Part of 2017 REU in secure cloud computing at MST.
 * Written by Samuel Li
 */


import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import javax.swing.DefaultListModel;

public class MasterCommunication implements Runnable {

    private int basePortNumber;
    private int nextPortNumber;
    private ServerSocket masterSocket;
    private ArrayList<Dictionary> myLibrary;
    private DefaultListModel<String> listModel;
    
    private boolean available = true;

    public MasterCommunication(int base, ArrayList<Dictionary> myLibrary, DefaultListModel<String> listModel) {
        this.basePortNumber = base;
        this.nextPortNumber = this.basePortNumber + 1;
        this.myLibrary = myLibrary;
        this.listModel = listModel;
    }

    /* Initializes new ServerCommunication object for each client */
    public void run() {
        
        try {
            this.masterSocket = new ServerSocket(this.basePortNumber);

            while (this.available) {
                Socket clientSocket = masterSocket.accept();
                ObjectOutputStream outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream inputStream = new ObjectInputStream(clientSocket.getInputStream());

                outputStream.writeObject(this.nextPortNumber);

                ServerCommunication communicator = new ServerCommunication(this.nextPortNumber, myLibrary, listModel);
                new Thread(communicator).start();
                nextPortNumber += 1;
                
                clientSocket.close();
                outputStream.close();
                inputStream.close();
            }
            
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
    
    public void shutServer() {
        this.available = false; 
    }
    
}
