This application implements the secure document comparison protocol developed
at the 2017 REU program in secure cloud computing at Missouri University of
Science and Technology. It employs the Apache Lucene library, GNU GMP library,
Java Native Interface. Security is based on the Paillier cryptosystem. Our
application currently only compares .txt files.

The paper for our project is included in the repository.

USAGE:

Download the ComparisonClient and ComparisonServer folders. Run the jar files
in the respective dist folders. MAKE SURE TO ONLY RUN FROM THE DIST FOLDERS. Each
jar requires a separate .dylib file that is also in the folder.

On the server side:
Select a directory containing .txt files as the collection directory path. Select
any empty directory as the index directory path. Name the collection, the click
the "Index Collection" button. Index as many collections as you want to make
available to the client. Select a master port (default 3333), and then click
"Open Server button".

On the client side:
Select the hostname of the server. Server and client must be on the same network.
Select the same port as the server master port (this must be agreed upon in
advance). Once successfully connected by pressing the "Connect" button, select
the collection you want to query to. Select query directory
containing ONE query .txt files, and an empty directory as the index directory.
Indicate how many scores you want to see, then click "Query". The top-k
similarity scores will appear. They range from 0 (no common terms) to 1 (very similar). Query as many times as you want.

The server application is multithreaded and can handle many clients at once.

Any questions, feel free to contact: samuelli97@gmail.com
