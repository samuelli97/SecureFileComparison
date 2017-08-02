
/*
 * File: Indexer.java
 * Indexes client and server documents with Apache Lucene library.
 * Part of 2017 REU in secure cloud computing at MST.
 * Written by Samuel Li
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


@SuppressWarnings("deprecation")
public class Indexer {

  private IndexWriter writer; // IndexWriter object to assist indexing

  // returns IndexWriter instance variable
  public IndexWriter getWriter() {
    return this.writer;
  }
  
  // initilaizes IndexWriter with standard Lucene features
  public Indexer(String indexDir) throws IOException {
    Directory dir = FSDirectory.open(new File(indexDir));

    writer = new IndexWriter(dir,new StandardAnalyzer(Version.LUCENE_30),
          true, IndexWriter.MaxFieldLength.UNLIMITED);           
  }

  // closes IndexWriter instance
  public void close() throws IOException {
    writer.close();                             
  }

  // prepares indexing directory
  public int index(String dataDir, FileFilter filter)
    throws Exception {

    File[] files = new File(dataDir).listFiles();

    for (File f: files) {
      if (!f.isDirectory() &&
          !f.isHidden() &&
          f.exists() &&
          f.canRead() &&
          (filter == null || filter.accept(f))) {
        indexFile(f);
      }
    }

    return writer.numDocs();                    
  }

  // only includes .txt files
  private static class TextFilesFilter implements FileFilter {
    public boolean accept(File path) {
      return path.getName().toLowerCase()        
             .endsWith(".txt");                  
    }
  }

  // Initializes Document object
  protected Document getDocument(File f) throws Exception {
    Document doc = new Document();
    doc.add(new Field("contents", new FileReader(f), Field.TermVector.YES));      
    doc.add(new Field("filename", f.getName(),              
                Field.Store.YES, Field.Index.NOT_ANALYZED));
    doc.add(new Field("fullpath", f.getCanonicalPath(),     
                Field.Store.YES, Field.Index.NOT_ANALYZED));
    return doc;
  }

  // indexes single file
  private void indexFile(File f) throws Exception {
    System.out.println("Indexing " + f.getCanonicalPath());
    Document doc = getDocument(f);
    writer.addDocument(doc);                              
  }
}


