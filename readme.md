Grade: 20/20

# Goal:
Write UDP programs allowing two parties(Alice and Bob) to establish a secure communication channel

- Alice and Bob shares a common password PW
- Alice stores H(PW)

# Compilation Info

Optional - setup program
------------------------
Purpose:
1. Hash Bob's hardcoded PW using SHA-1 hashing algorithm
2. Generate Diffie Hellman parameters
3. Save (p, g, H(PW)) to a text file under Alice's directory

How
---
1. javac setup.java
2. java setup

What will happen
----------------
- Program will generate new DH parameters again and overwrite the dhparams.txt in Alice's directory
- Note: p and g are the only values that will change. H(PW) remains the same unless PW is changed prior to the execution of the program.


Running the program
-------------------
Step 1: Open up two separate terminals

Step 2: with one of the terminals, cd into Alice

Step 3: with the other terminal, cd into Bob

Step 4: run the following command in Alice's terminal: java EchoServer
- if the program does not run, run the following command: javac EchoServer.java; followed by: java EchoServer

Step 5: run the following command in Bob's terminal: java EchoClient
- if the program does not run, run the following command: javac EchoClient.java; followed by: java EchoClient

Step 6: in Bob's terminal, password will be prompted. Please enter "CSCI368" for the password.
- if password is wrong, communication channel will be terminated on the client's side
    - Alice will timeout after 30 seconds of not receiving any response from Bob
    - to kill the process, execute "ctrl + c" command on Alice's terminal
- if password is correct, host and client will begin to establish handshake
    - if handshake is SUCCESSFUL, Alice and Bob can proceed to send message to each other
    - if handshake is UNSUCCESSFUL, the communication channel will be terminated on both sides

Step 7: the program has been set up for the client to send a message first before the host replies
- using Bob's terminal, try sending a message

Step 8: after receiving a message from Bob, Alice will then be able to send a message to Bob
- using Alice's terminal, try sending a message

Step 9: repeat Step 7 and Step 8 to continuously send messages between Alice and Bob

Step 10: to exit the program, simply enter "exit" on either Alice's or Bob's terminal