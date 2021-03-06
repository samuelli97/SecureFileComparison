/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author sam
 * 
 * 
 */
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.Directory;
import org.apache.lucene.util.Version;

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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.DefaultListModel;

import java.text.DecimalFormat;

import java.util.ArrayList;
import java.util.HashMap;


public class ComparisonServerUI extends javax.swing.JFrame {

    /**
     * Creates new form ComparisonServerUI
     */
    public ComparisonServerUI() {
        initComponents();
        myLibrary = new ArrayList<Dictionary>();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        indexingPanel = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        collectionPathField = new javax.swing.JTextField();
        toIndexPathField = new javax.swing.JTextField();
        IndexButton = new javax.swing.JButton();
        topClearButton = new javax.swing.JButton();
        jLabel7 = new javax.swing.JLabel();
        luceneMessageField = new javax.swing.JTextField();
        searchCollectionButton = new javax.swing.JButton();
        searchIndexButton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        collectionsList = new javax.swing.JList<>();
        removeButton = new javax.swing.JButton();
        jLabel8 = new javax.swing.JLabel();
        collectionNameTextField = new javax.swing.JTextField();
        comparisonPanel = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        portField = new javax.swing.JTextField();
        bottomClearButton = new javax.swing.JButton();
        openServerButton = new javax.swing.JButton();
        jLabel6 = new javax.swing.JLabel();
        serverMessageField = new javax.swing.JTextField();
        closeServerButton = new javax.swing.JButton();
        exitButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        indexingPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Indexing", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Lucida Grande", 1, 13))); // NOI18N
        indexingPanel.setToolTipText("");

        jLabel1.setText("Collection Directory Path");

        jLabel2.setText("Index Directory Path");

        IndexButton.setText("Index Collection");
        IndexButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                IndexButtonActionPerformed(evt);
            }
        });

        topClearButton.setText("Clear");
        topClearButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                topClearButtonActionPerformed(evt);
            }
        });

        jLabel7.setText("Lucene Message");

        luceneMessageField.setEditable(false);

        searchCollectionButton.setText("Search");
        searchCollectionButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                searchCollectionButtonActionPerformed(evt);
            }
        });

        searchIndexButton.setText("Search");
        searchIndexButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                searchIndexButtonActionPerformed(evt);
            }
        });

        collectionsList.setBorder(javax.swing.BorderFactory.createTitledBorder("Selected Collections"));
        collectionsList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jScrollPane1.setViewportView(collectionsList);

        removeButton.setText("Remove");
        removeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeButtonActionPerformed(evt);
            }
        });

        jLabel8.setText("Collection Name");

        javax.swing.GroupLayout indexingPanelLayout = new javax.swing.GroupLayout(indexingPanel);
        indexingPanel.setLayout(indexingPanelLayout);
        indexingPanelLayout.setHorizontalGroup(
            indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(indexingPanelLayout.createSequentialGroup()
                .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(indexingPanelLayout.createSequentialGroup()
                        .addGap(196, 196, 196)
                        .addComponent(topClearButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(IndexButton))
                    .addGroup(indexingPanelLayout.createSequentialGroup()
                        .addGap(2, 2, 2)
                        .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel7, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel8, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(indexingPanelLayout.createSequentialGroup()
                                .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(luceneMessageField, javax.swing.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE)
                                    .addComponent(toIndexPathField, javax.swing.GroupLayout.DEFAULT_SIZE, 381, Short.MAX_VALUE)
                                    .addComponent(collectionPathField, javax.swing.GroupLayout.DEFAULT_SIZE, 379, Short.MAX_VALUE)
                                    .addComponent(collectionNameTextField))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(searchCollectionButton)
                                    .addComponent(searchIndexButton)))
                            .addGroup(indexingPanelLayout.createSequentialGroup()
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 391, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(removeButton)))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        indexingPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {collectionPathField, luceneMessageField, toIndexPathField});

        indexingPanelLayout.setVerticalGroup(
            indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(indexingPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(collectionPathField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(searchCollectionButton))
                .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(toIndexPathField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2)
                    .addComponent(searchIndexButton))
                .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(indexingPanelLayout.createSequentialGroup()
                        .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel8)
                            .addComponent(collectionNameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(5, 5, 5)
                        .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel7)
                            .addComponent(luceneMessageField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(indexingPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(topClearButton)
                            .addComponent(IndexButton))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(removeButton))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        comparisonPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "File Comparison", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Lucida Grande", 1, 13))); // NOI18N

        jLabel4.setText("Master Port");

        portField.setText("3333");

        bottomClearButton.setText("Clear");
        bottomClearButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bottomClearButtonActionPerformed(evt);
            }
        });

        openServerButton.setText("Open Server");
        openServerButton.setToolTipText("");
        openServerButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                openServerButtonActionPerformed(evt);
            }
        });

        jLabel6.setText("Server Status");

        serverMessageField.setEditable(false);

        closeServerButton.setText("Close Server");
        closeServerButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closeServerButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout comparisonPanelLayout = new javax.swing.GroupLayout(comparisonPanel);
        comparisonPanel.setLayout(comparisonPanelLayout);
        comparisonPanelLayout.setHorizontalGroup(
            comparisonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(comparisonPanelLayout.createSequentialGroup()
                .addGap(47, 47, 47)
                .addGroup(comparisonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel4)
                    .addComponent(jLabel6))
                .addGap(23, 23, 23)
                .addGroup(comparisonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(comparisonPanelLayout.createSequentialGroup()
                        .addComponent(portField, javax.swing.GroupLayout.PREFERRED_SIZE, 78, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(bottomClearButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(openServerButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(closeServerButton))
                    .addComponent(serverMessageField, javax.swing.GroupLayout.PREFERRED_SIZE, 394, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        comparisonPanelLayout.setVerticalGroup(
            comparisonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(comparisonPanelLayout.createSequentialGroup()
                .addGap(8, 8, 8)
                .addGroup(comparisonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(portField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(bottomClearButton)
                    .addComponent(openServerButton)
                    .addComponent(closeServerButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(comparisonPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel6)
                    .addComponent(serverMessageField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(19, Short.MAX_VALUE))
        );

        exitButton.setText("Exit");
        exitButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(comparisonPanel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(582, Short.MAX_VALUE)
                .addComponent(exitButton)
                .addContainerGap())
            .addComponent(indexingPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 663, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(indexingPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(comparisonPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(exitButton)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void bottomClearButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bottomClearButtonActionPerformed
        // TODO add your handling code here:
        portField.setText("");
        
    }//GEN-LAST:event_bottomClearButtonActionPerformed

    private void exitButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exitButtonActionPerformed
        // TODO add your handling code here:
        System.exit(0);
    }//GEN-LAST:event_exitButtonActionPerformed

    
    private void openServerButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_openServerButtonActionPerformed
        // TODO add your handling code here:
        if (myLibrary == null) {
            JOptionPane.showMessageDialog(null, "Error: Index a directory first");
            return;
        }
        
        try {
            int basePortNumber = Integer.parseInt(portField.getText());
            this.masterCom = new MasterCommunication(basePortNumber, myLibrary, listModel);
            new Thread(masterCom).start();
            serverMessageField.setText("Server now available");
            
        } catch (Exception ex) {
            Logger.getLogger(ComparisonServerUI.class.getName()).log(Level.SEVERE, null, ex);
        }
    }//GEN-LAST:event_openServerButtonActionPerformed
        
    private void removeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeButtonActionPerformed
        // TODO add your handling code here:
        String selected = collectionsList.getSelectedValue();
        // remember to remove corresponding Dictionary object in ArrayList
        int index = listModel.indexOf(selected);
        this.myLibrary.remove(index);
        
        listModel.removeElement(selected);
        collectionsList.setModel(listModel);
    }//GEN-LAST:event_removeButtonActionPerformed

    private void searchIndexButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_searchIndexButtonActionPerformed
        // TODO add your handling code here:
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fileChooser.setAcceptAllFileFilterUsed(false);

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {

            File file = fileChooser.getSelectedFile();
            String dirName = file.getAbsolutePath();
            toIndexPathField.setText(dirName);
        }
    }//GEN-LAST:event_searchIndexButtonActionPerformed

    private void searchCollectionButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_searchCollectionButtonActionPerformed
        // TODO add your handling code here:
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        fileChooser.setAcceptAllFileFilterUsed(false);

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {

            File file = fileChooser.getSelectedFile();
            String dirName = file.getAbsolutePath();
            collectionPathField.setText(dirName);
        }
    }//GEN-LAST:event_searchCollectionButtonActionPerformed

    private void topClearButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_topClearButtonActionPerformed
        // TODO add your handling code here:
        collectionPathField.setText("");
        toIndexPathField.setText("");
        luceneMessageField.setText("");
        collectionNameTextField.setText("");
    }//GEN-LAST:event_topClearButtonActionPerformed

    private void IndexButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_IndexButtonActionPerformed
        // TODO add your handling code here:
        if (listModel == null) listModel = new DefaultListModel();
        
        String name = collectionNameTextField.getText();
        if (name.equals("") || listModel.contains(name)) {
            luceneMessageField.setText("Invalid collection name\n");
            return;
        }
        
        String indexDir = toIndexPathField.getText();
        String dataDir = collectionPathField.getText();
        try {
            LuceneIndex(indexDir, dataDir);
            listModel.addElement(name);
            collectionsList.setModel(listModel);
        } catch (Exception ex) {
            Logger.getLogger(ComparisonServerUI.class.getName()).log(Level.SEVERE, null, ex);
            luceneMessageField.setText("Lucene failed to index. Try again.");
        }
    }//GEN-LAST:event_IndexButtonActionPerformed
        
    private void closeServerButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_closeServerButtonActionPerformed
        // TODO add your handling code here:
        if (masterCom != null) {
            masterCom.shutServer();
            serverMessageField.setText("Server closed");
        }
    }//GEN-LAST:event_closeServerButtonActionPerformed
    
    @SuppressWarnings("deprecated")
    public void LuceneIndex(String indexDir, String dataDir) throws Exception {
        long start = System.currentTimeMillis();
        Indexer indexer = new Indexer(indexDir);
        int numIndexed;
        Dictionary allWords;
        try {
            numIndexed = indexer.index(dataDir, new TextFilesFilter());
            IndexReader reader = indexer.getWriter().getReader();
            int numDocuments = reader.numDocs();
            allWords = new Dictionary(reader, numDocuments);
            
            
            this.myLibrary.add(allWords);
            reader.close();
        } finally {
            indexer.close();
        }
        long end = System.currentTimeMillis();
        luceneMessageField.setText("Indexing and creating dictionary for " + 
                numIndexed + " files took " + (end - start) + " milliseconds");
        

    }
    
    private static class TextFilesFilter implements FileFilter {
        @Override
        public boolean accept(File path) {
            return path.getName().toLowerCase().endsWith(".txt");
        }
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ComparisonServerUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ComparisonServerUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ComparisonServerUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ComparisonServerUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new ComparisonServerUI().setVisible(true);

            }
        });
    }

    private ArrayList<Dictionary> myLibrary;
    private javax.swing.DefaultListModel<String> listModel = null;
    private MasterCommunication masterCom;
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton IndexButton;
    private javax.swing.JButton bottomClearButton;
    private javax.swing.JButton closeServerButton;
    private javax.swing.JTextField collectionNameTextField;
    private javax.swing.JTextField collectionPathField;
    private javax.swing.JList<String> collectionsList;
    private javax.swing.JPanel comparisonPanel;
    private javax.swing.JButton exitButton;
    private javax.swing.JPanel indexingPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextField luceneMessageField;
    private javax.swing.JButton openServerButton;
    private javax.swing.JTextField portField;
    private javax.swing.JButton removeButton;
    private javax.swing.JButton searchCollectionButton;
    private javax.swing.JButton searchIndexButton;
    private javax.swing.JTextField serverMessageField;
    private javax.swing.JTextField toIndexPathField;
    private javax.swing.JButton topClearButton;
    // End of variables declaration//GEN-END:variables
}
